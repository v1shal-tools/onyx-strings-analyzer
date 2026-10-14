
[CmdletBinding()]
param(
    [int]$ProcessId = 0,
    [int]$MinLength = 5,
    [int]$Samples   = 2,
    [string]$KeywordFile,
    [switch]$Detail,
    [switch]$DumpStrings,
    [switch]$NoPause
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
try { chcp 65001 | Out-Null } catch { }

if (-not [Environment]::Is64BitProcess) {
    Write-Host "Run this in 64-bit PowerShell (not the x86 one)." -ForegroundColor Red
    return
}

# ---------------------------------------------------------------- native scanner
if (-not ('OnyxScan' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class OnyxHit {
    public string Keyword; public string Category; public int Severity; public long Count;
    public List<string> Samples = new List<string>();
    public HashSet<string> SampleSet = new HashSet<string>();
    public bool Ascii; public bool Wide; public ulong FirstAddr;
}

public static class OnyxScan {
    [StructLayout(LayoutKind.Sequential)]
    struct MBI { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect;
                 public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern UIntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, UIntPtr len);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr size, out UIntPtr read);

    public static volatile bool Done;
    public static long TotalBytes, DoneBytes, StringsSeen;
    public static int HitCount;
    public static string Error;

    const int CH = 16 * 1024 * 1024;
    const int MAXRUN = 2048;
    static char[] run = new char[MAXRUN];
    static int[][] go; static List<int>[] outp; static string[] kw, cat; static int[] sev, klen;
    static OnyxHit[] hitArr;
    static StreamWriter dump;
    static int minLen;

    static char Nrm(char c) {
        if (c >= 0xFF01 && c <= 0xFF5E) c = (char)(c - 0xFEE0);
        else if (c == 0x3000) c = ' ';
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        return c;
    }

    public static void Init(string[] words, string[] cats, int[] sevs) {
        kw = words; cat = cats; sev = sevs; klen = new int[words.Length];
        hitArr = new OnyxHit[words.Length]; HitCount = 0;
        List<int[]> g = new List<int[]>(); List<int> fail = new List<int>(); List<List<int>> o = new List<List<int>>();
        Func<int> newNode = delegate() {
            int[] a = new int[128]; for (int i = 0; i < 128; i++) a[i] = -1;
            g.Add(a); fail.Add(0); o.Add(null); return g.Count - 1; };
        newNode();
        for (int i = 0; i < words.Length; i++) {
            int s = 0; int l = 0;
            foreach (char c0 in words[i]) {
                char c = Nrm(c0); if (c >= 128) continue; l++;
                if (g[s][c] == -1) { int n = newNode(); g[s][c] = n; }
                s = g[s][c];
            }
            klen[i] = l;
            if (o[s] == null) o[s] = new List<int>();
            o[s].Add(i);
        }
        Queue<int> q = new Queue<int>();
        for (int c = 0; c < 128; c++) { int n = g[0][c]; if (n == -1) g[0][c] = 0; else { fail[n] = 0; q.Enqueue(n); } }
        while (q.Count > 0) {
            int r = q.Dequeue();
            for (int c = 0; c < 128; c++) {
                int n = g[r][c];
                if (n == -1) { g[r][c] = g[fail[r]][c]; }
                else {
                    fail[n] = g[fail[r]][c];
                    List<int> fo = o[fail[n]];
                    if (fo != null) { if (o[n] == null) o[n] = new List<int>(); o[n].AddRange(fo); }
                    q.Enqueue(n);
                }
            }
        }
        go = g.ToArray(); outp = o.ToArray();
    }

    public static void Start(int pid, int minLength, string dumpPath) {
        Done = false; Error = null; TotalBytes = 0; DoneBytes = 0; StringsSeen = 0; minLen = minLength;
        Thread t = new Thread(delegate() { Work(pid, dumpPath); });
        t.IsBackground = true; t.Start();
    }

    public static List<OnyxHit> GetHits() {
        List<OnyxHit> l = new List<OnyxHit>();
        foreach (OnyxHit h in hitArr) if (h != null) l.Add(h);
        return l;
    }

    static void Work(int pid, string dumpPath) {
        IntPtr h = OpenProcess(0x0410, false, pid);
        if (h == IntPtr.Zero) {
            Error = "OpenProcess failed (Win32 error " + Marshal.GetLastWin32Error() + "). Try an elevated (Administrator) terminal.";
            Done = true; return;
        }
        try {
            dump = null;
            if (!string.IsNullOrEmpty(dumpPath)) dump = new StreamWriter(dumpPath, false, new UTF8Encoding(false));
            List<ulong[]> regs = new List<ulong[]>();
            ulong addr = 0; MBI m; int sz = Marshal.SizeOf(typeof(MBI));
            while (true) {
                UIntPtr r = VirtualQueryEx(h, (IntPtr)(long)addr, out m, (UIntPtr)sz);
                if (r == UIntPtr.Zero) break;
                ulong b = (ulong)(long)m.BaseAddress, s = (ulong)(long)m.RegionSize;
                if (m.State == 0x1000 && m.Protect != 0 && (m.Protect & 0x01) == 0 && (m.Protect & 0x100) == 0) {
                    regs.Add(new ulong[] { b, s }); TotalBytes += (long)s;
                }
                ulong nx = b + s; if (nx <= addr) break; addr = nx;
                if (addr > 0x7FFFFFFFFFFFUL) break;
            }
            byte[] buf = new byte[CH];
            foreach (ulong[] rg in regs) {
                ulong off = 0;
                while (off < rg[1]) {
                    int want = (int)Math.Min((ulong)CH, rg[1] - off);
                    UIntPtr rd;
                    if (!ReadProcessMemory(h, (IntPtr)(long)(rg[0] + off), buf, (UIntPtr)want, out rd) || rd == UIntPtr.Zero) {
                        off += (ulong)want; DoneBytes += want; continue;
                    }
                    int n = (int)(ulong)rd;
                    ScanAscii(buf, n, rg[0] + off);
                    ScanWide(buf, n, rg[0] + off);
                    off += (ulong)n; DoneBytes += n;
                }
            }
        }
        catch (Exception ex) { Error = ex.Message; }
        finally {
            if (dump != null) { dump.Flush(); dump.Dispose(); dump = null; }
            CloseHandle(h); Done = true;
        }
    }

    static void ScanAscii(byte[] b, int n, ulong baseAddr) {
        int len = 0;
        for (int i = 0; i <= n; i++) {
            byte c = i < n ? b[i] : (byte)0;
            if ((c >= 0x20 && c < 0x7F) || c == 9) {
                if (len >= MAXRUN) { ProcessRun(len, baseAddr + (ulong)i, false); len = 0; }
                run[len++] = (char)c;
            } else {
                if (len >= minLen) ProcessRun(len, baseAddr + (ulong)(i - len), false);
                len = 0;
            }
        }
    }

    static void ScanWide(byte[] b, int n, ulong baseAddr) {
        int len = 0;
        for (int i = 0; i + 1 < n; i += 2) {
            char c = (char)(b[i] | (b[i + 1] << 8));
            bool ok = (c >= 0x20 && c < 0x7F) || (c >= 0xFF01 && c <= 0xFF5E) || c == 0x3000;
            if (ok) {
                if (len >= MAXRUN) { ProcessRun(len, baseAddr + (ulong)i, true); len = 0; }
                run[len++] = c;
            } else {
                if (len >= minLen) ProcessRun(len, baseAddr + (ulong)(i - len * 2), true);
                len = 0;
            }
        }
        if (len >= minLen) ProcessRun(len, baseAddr + (ulong)(n - len * 2), true);
    }

    static void ProcessRun(int len, ulong addr, bool wide) {
        StringsSeen++;
        if (dump != null) dump.WriteLine((wide ? "W " : "A ") + new string(run, 0, len));
        int s = 0;
        for (int i = 0; i < len; i++) {
            char c = Nrm(run[i]);
            if (c >= 128) { s = 0; continue; }
            s = go[s][c];
            List<int> o = outp[s];
            if (o != null) foreach (int k in o) Record(k, i, len, wide, addr);
        }
    }

    static void Record(int k, int endIdx, int len, bool wide, ulong addr) {
        OnyxHit h = hitArr[k];
        if (h == null) {
            h = new OnyxHit(); h.Keyword = kw[k]; h.Category = cat[k]; h.Severity = sev[k]; h.FirstAddr = addr;
            hitArr[k] = h; HitCount++;
        }
        h.Count++;
        if (wide) h.Wide = true; else h.Ascii = true;
        if (h.Samples.Count < 8) {
            int st = Math.Max(0, endIdx - klen[k] + 1 - 50);
            int en = Math.Min(len, endIdx + 1 + 70);
            string s = new string(run, st, en - st);
            if (h.SampleSet.Add(s)) h.Samples.Add(s);
        }
    }
}
'@
}

# ---------------------------------------------------------------- keyword database
$DefaultKeywords = @'
3|Known client|vape.gg;vapeclient;vapelite;liquidbounce;rusherhack;konas;futureclient;impactclient;aristois;novoline;pandaware;riseclient;rise.today;doomsdayclient;doomsday.jar;novaclient;dqrkis;catleanclient;prestigeclient;xenonclient;asteriaclient;gypsyclient;argonclient;virginclient;grimclient;fdp-client;intent.store;skid.krypton;skid/krypton;dev.krypton;dev/krypton
2|Known client|meteordevelopment;meteorclient;meteor-client
3|Client package|org.chainlibs;org/chainlibs;xyz.greaj;xyz/greaj;dev.gambleclient;dev.virel;cc/novoline;net/ccbluex;net.ccbluex;today/opai;club/maxstats;wtf/moonlight;me/zeroeightsix;com/alan/clients;phantom-refmap.json;client-refmap.json;cheat-refmap.json
3|Combat module|autocrystal;auto crystal;autohitcrystal;crystalaura;autoanchor;auto anchor;doubleanchor;safeanchor;airanchor;anchoraura;anchortweaks;anchor macro;autodoublehand;autototem;auto totem;hovertotem;hover totem;inventorytotem;legittotem;autopot;autopotrefill;shieldbreaker;shielddisabler;triggerbot;trigger bot;aimassist;aim assist;aimbot;silentaim;killaura;clickaura;multiaura;autoclicker;maceswap;stunslam;axespam;webmacro;autoweb;keypearl;pingspoof;fakelag;lagreach;popswitch;lootyeeter;autobreach;antiknockback;hitboxexpand;reachhack;bedaura;autonethpot;autodtap;autotpa;walksyoptimizer;walskyoptimizer;lwfh crystal;fakepunch
3|Credential stealer|tokenlogger;tokengrabber;sessionstealer;discordtoken
2|Combat / utility|autoarmor;autofirework;elytraswap;fastxp;fastexp;autocrit;critbypass;alwayscrit;sprintreset;wtap;targetstrafe;autogap;autopearl;autosword;autoweapon;blockesp;antibot;antimissclick;fakeinv;packspoof;bowaimbot;autobow;velocityspoof;grimvelocity;grimdisabler;grimbypass;vulcanbypass;matrixbypass;intavebypass;watchdogbypass;verusdisabler;aacbypass;selfdestruct;self destruct;hideclient;authbypass;obfuscatedauth;licensecheckmixin;jnativehook;nativekeylistener;imgui.gl3;imgui.glfw;keylogger;reverseshell;c2server
2|Movement / exploit|flyhack;packetfly;boatfly;airjump;speedhack;bunnyhop;nofalldamage;noslowdown;waterwalk;liquidwalk;scaffoldwalk;fastbridge;nuker;instantbreak;ghosthand;noswing;packetmine;packetcancel;packetdupe;packetspam;itemexploit;freezeplayer
2|Visual / ESP|playeresp;mobesp;itemesp;storageesp;chestesp;oreesp;wallhack;xrayhack;orefinder;cavefinder;stashfinder;trailfinder;basefinder;newchunks;targethud
2|Module setting|silent rotations;click simulation;glowstone delay;explode delay;predict crystals;auto inventory totem;horizontal aim speed;vertical aim speed;stop on kill;place chance;break chance;totem slot;strict one-tick;require crit;only on pop;mace priority;activate on right click;holdcrystal;dontplacecrystal;dontbreakcrystal;canplacecrystalserver;autocrystalplaceclock;attackregisteredthisclick;findknockbacksword;swapbacktooriginalslot;pot_cheats;lvstrng;breaking shield with axe;failed to switch to mace after axe
2|Obfuscator|skidfuscator;paramorphism;zkmflow;superblaubeere;qprotect;branchlock;binscure;caesium;bozar
1|Weak marker|invokedoattack;invokedoitemuse;invokeonmousebutton;setblockbreakingcooldown;setitemusecooldown;clientplayerinteractionmanageraccessor;freecam;invsee;donut;refill;blatant;nobounce;tracers;bhop;autosprint;antiafk;autorespawn;fastplace;noslow;criticals;jumpreset;replace mod;fakenick;fakeitem;bowaim
'@

function Get-KeywordTable {
    $text = $DefaultKeywords
    if ($KeywordFile -and (Test-Path $KeywordFile)) { $text += "`n" + (Get-Content -Raw $KeywordFile) }
    $map = @{}
    foreach ($line in ($text -split "`r?`n")) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $p = $line.Split('|', 3)
        if ($p.Count -lt 3) { continue }
        $s = 0; if (-not [int]::TryParse($p[0], [ref]$s)) { continue }
        foreach ($w in ($p[2] -split ';')) {
            $w = $w.Trim().ToLowerInvariant()
            if ($w.Length -lt 3) { continue }
            if (-not $map.ContainsKey($w) -or $map[$w].Sev -lt $s) { $map[$w] = @{ Sev = $s; Cat = $p[1].Trim() } }
        }
    }
    $words = @($map.Keys | Sort-Object)
    [pscustomobject]@{
        Words = [string[]]$words
        Cats  = [string[]]($words | ForEach-Object { $map[$_].Cat })
        Sevs  = [int[]]($words | ForEach-Object { $map[$_].Sev })
    }
}

# ---------------------------------------------------------------- ui helpers
function W { param([string]$T = '', [ConsoleColor]$C = 'Gray', [switch]$NoNewline)
    if ($NoNewline) { Write-Host $T -ForegroundColor $C -NoNewline } else { Write-Host $T -ForegroundColor $C } }
function Bar { param([double]$V, [double]$M, [int]$Width)
    if ($M -le 0) { $M = 1 }
    $f = [int][Math]::Round($Width * [Math]::Min(1.0, $V / $M))
    return (('█' * $f) + ('░' * ($Width - $f))) }
function Fmt-Bytes { param([double]$B)
    if ($B -ge 1GB) { return ('{0:N2} GB' -f ($B / 1GB)) }
    if ($B -ge 1MB) { return ('{0:N0} MB' -f ($B / 1MB)) }
    return ('{0:N0} KB' -f ($B / 1KB)) }

function Show-Banner {
    Clear-Host
    $rows = @(
        '   ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗',
        '  ██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝',
        '  ██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ',
        '  ██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗ ',
        '  ╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗',
        '   ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝'
    )
    $colors = @('Cyan', 'Cyan', 'DarkCyan', 'DarkCyan', 'Blue', 'Blue')
    W ''
    for ($i = 0; $i -lt $rows.Count; $i++) { W ('        ' + $rows[$i]) $colors[$i] }
    W ''
    W '        M E M O R Y   S T R I N G   A N A L Y Z E R' 'Cyan'
    W '        v0.2.0  •  read-only  •  indicators, not verdicts' 'DarkGray'
    W ''
    W ('─' * 78) 'DarkCyan'
}

function Get-Candidates {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction SilentlyContinue)
    $out = foreach ($p in $procs) {
        $cl = [string]$p.CommandLine
        $ws = 0; try { $ws = (Get-Process -Id $p.ProcessId -ErrorAction Stop).WorkingSet64 } catch { }
        [pscustomobject]@{
            Pid     = [int]$p.ProcessId
            Name    = $p.Name
            Cmd     = $cl
            IsMc    = [bool]($cl -match '(?i)minecraft|fabricmc|fabric-loader|--gameDir|--assetsDir|modrinth|prism|lunar|badlion|tlauncher|launchwrapper|forge')
            Created = $p.CreationDate
            WS      = $ws
        }
    }
    @($out | Sort-Object @{e = 'IsMc'; Descending = $true }, @{e = 'WS'; Descending = $true })
}

function Get-JvmFindings { param([string]$Cmd)
    $r = New-Object System.Collections.Generic.List[object]
    if (-not $Cmd) { return $r }
    $legit = 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus|opentelemetry|datadog'
    foreach ($m in [regex]::Matches($Cmd, '-javaagent:("[^"]+"|[^\s]+)')) {
        $a = $m.Groups[1].Value.Trim('"')
        if ($a -notmatch $legit) { $r.Add(@{ T = 'Unrecognized -javaagent'; D = $a }) }
    }
    $flags = @(
        @('-Xbootclasspath/p:', 'prepends to bootstrap classpath'),
        @('-Xbootclasspath/a:', 'appends to bootstrap classpath'),
        @('-agentlib:jdwp', 'JDWP remote debugging enabled'),
        @('-agentpath:', 'native agent loaded')
    )
    foreach ($f in $flags) { if ($Cmd.IndexOf($f[0], [StringComparison]::OrdinalIgnoreCase) -ge 0) { $r.Add(@{ T = "JVM flag $($f[0])"; D = $f[1] }) } }
    return $r
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$kwTable = Get-KeywordTable
$sevMeta = @{
    3 = @{ L = ' HIGH '; C = 'Red';      F = 'White' }
    2 = @{ L = ' MED  '; C = 'Yellow';   F = 'Black' }
    1 = @{ L = ' LOW  '; C = 'DarkGray'; F = 'White' }
}
try { $w = [Math]::Min(100, $Host.UI.RawUI.WindowSize.Width - 2) } catch { $w = 78 }
if ($w -lt 60) { $w = 60 }

function Wrap-List { param([string[]]$Items, [int]$Width)
    $lines = New-Object System.Collections.Generic.List[string]; $cur = ''
    foreach ($i in $Items) {
        $add = if ($cur) { ', ' + $i } else { $i }
        if ($cur -and (($cur.Length + $add.Length) -gt $Width)) { $lines.Add($cur + ','); $cur = $i } else { $cur += $add }
    }
    if ($cur) { $lines.Add($cur) }
    return $lines
}
function Box-Line { param([string]$T, [ConsoleColor]$C = 'Gray')
    W ('║ ' + $T.PadRight($w - 4) + ' ║') $C }

do {
    $again = $false
    Show-Banner

    $cands = @(Get-Candidates)
    if ($ProcessId -gt 0) { $cands = @($cands | Where-Object { $_.Pid -eq $ProcessId }) }
    if ($cands.Count -eq 0) {
        W '  ✗ No java/javaw process found. Launch Minecraft, get in-game, then run again.' 'Red'
        break
    }
    $target = $cands[0]
    if ($cands.Count -gt 1 -and -not $NoPause) {
        W '  Multiple Java processes found:' 'Yellow'
        for ($i = 0; $i -lt $cands.Count; $i++) {
            $tag = if ($cands[$i].IsMc) { 'minecraft?' } else { '' }
            W ('   [{0}] PID {1,-6} {2,-10} {3,10}  {4}' -f ($i + 1), $cands[$i].Pid, $cands[$i].Name, (Fmt-Bytes $cands[$i].WS), $tag) 'Gray'
        }
        $sel = Read-Host '  Select target # (Enter = 1)'
        $n = 0
        if ([int]::TryParse($sel, [ref]$n) -and $n -ge 1 -and $n -le $cands.Count) { $target = $cands[$n - 1] }
        W ''
    }

    $ver = ''
    if ($target.Cmd -match '--version\s+"?([^\s"]+)') { $ver = $Matches[1] }
    $uptime = ''
    try { $u = (Get-Date) - $target.Created; $uptime = '{0}h {1}m' -f [int][Math]::Floor($u.TotalHours), $u.Minutes } catch { }
    $privTxt = if ($isAdmin) { 'elevated' } else { 'not elevated' }
    W ('  {0}  PID {1}  •  {2}  •  up {3}  •  {4}' -f $target.Name, $target.Pid, (Fmt-Bytes $target.WS), $uptime, $ver) 'White'
    W ('  {0} keywords  •  {1}' -f $kwTable.Words.Count, $privTxt) 'DarkGray'
    W ''

    $dumpPath = $null
    if ($DumpStrings) { $dumpPath = Join-Path $env:TEMP ('Onyx_strings_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }

    [OnyxScan]::Init($kwTable.Words, $kwTable.Cats, $kwTable.Sevs)
    [OnyxScan]::Start($target.Pid, $MinLength, $dumpPath)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $spin = @('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'); $si = 0
    while (-not [OnyxScan]::Done) {
        Start-Sleep -Milliseconds 120
        $tot = [OnyxScan]::TotalBytes; $dn = [OnyxScan]::DoneBytes
        $pct = if ($tot -gt 0) { [Math]::Min(100, [int](100 * $dn / $tot)) } else { 0 }
        $line = '  {0} {1} {2,3}%  {3}/{4}  hits {5}  {6:mm\:ss}' -f $spin[$si % 10], (Bar $dn $tot 20), $pct, (Fmt-Bytes $dn), (Fmt-Bytes $tot), [OnyxScan]::HitCount, $sw.Elapsed
        Write-Host ("`r" + $line.PadRight($w - 1)) -ForegroundColor Cyan -NoNewline
        $si++
    }
    Write-Host ("`r" + (' ' * ($w - 1)) + "`r") -NoNewline
    $sw.Stop()

    if ([OnyxScan]::Error) { W ('  ✗ ' + [OnyxScan]::Error) 'Red'; break }

    # ---- findings: merge spacing variants (hover totem / hovertotem), drop keywords nested in a longer hit
    $raw = @([OnyxScan]::GetHits() | ForEach-Object {
            [pscustomobject]@{
                Keyword = $_.Keyword; Category = $_.Category; Sev = [int]$_.Severity; Count = [long]$_.Count
                Samples = @($_.Samples)
            } })
    $merged = @($raw | Group-Object { $_.Keyword -replace '[\s_]', '' } | ForEach-Object {
            $g = @($_.Group | Sort-Object Count -Descending)
            [pscustomobject]@{
                Keyword  = $g[0].Keyword; Category = $g[0].Category
                Sev      = [int](($g | Measure-Object Sev -Maximum).Maximum)
                Count    = [long](($g | Measure-Object Count -Sum).Sum)
                Samples  = @($g | ForEach-Object { $_.Samples })
            } })
    $findings = @($merged | Where-Object {
            $a = $_
            -not ($merged | Where-Object { $_.Keyword -ne $a.Keyword -and $_.Keyword.Contains($a.Keyword) -and $_.Count -ge $a.Count })
        } | Sort-Object @{e = 'Sev'; Descending = $true }, @{e = 'Count'; Descending = $true })

    $jvm = Get-JvmFindings $target.Cmd
    $hi = @($findings | Where-Object { $_.Sev -eq 3 }).Count
    $me = @($findings | Where-Object { $_.Sev -eq 2 }).Count + $jvm.Count
    $lo = @($findings | Where-Object { $_.Sev -eq 1 }).Count
    $score = 100 - [Math]::Min(75, $hi * 25) - [Math]::Min(20, $me * 4) - [Math]::Min(5, $lo)
    $grade = if ($score -ge 90) { 'A' } elseif ($score -ge 75) { 'B' } elseif ($score -ge 60) { 'C' } elseif ($score -ge 40) { 'D' } else { 'F' }
    $risk = if ($hi -ge 3) { 'CRITICAL' } elseif ($hi -ge 1) { 'HIGH' } elseif ($me -ge 1) { 'REVIEW' } else { 'NO INDICATORS' }
    $riskC = switch ($risk) { 'CRITICAL' { 'Red' } 'HIGH' { 'Red' } 'REVIEW' { 'Yellow' } default { 'Green' } }

    # ---- summary
    W ('╔' + ('═' * ($w - 2)) + '╗') 'DarkGray'
    Box-Line ('{0}  {1}/100  GRADE {2}   RISK {3}' -f (Bar $score 100 20), $score, $grade, $risk) $riskC
    Box-Line ('HIGH {0}    MED {1}    LOW {2}' -f $hi, $me, $lo) 'Gray'
    Box-Line ('{0:N0} strings  •  {1}  •  {2:N1}s' -f [OnyxScan]::StringsSeen, (Fmt-Bytes ([OnyxScan]::DoneBytes)), $sw.Elapsed.TotalSeconds) 'DarkGray'
    W ('╚' + ('═' * ($w - 2)) + '╝') 'DarkGray'
    W ''

    # ---- findings: one line each (HIGH + MED), LOW collapsed
    if ($findings.Count -eq 0) {
        W '  ✓ No keyword indicators in readable javaw memory.' 'Green'
        W '    (No match is not proof of clean: strings can be encrypted or built at runtime.)' 'DarkGray'
    }
    foreach ($f in @($findings | Where-Object { $_.Sev -ge 2 })) {
        $m = $sevMeta[$f.Sev]
        W '  ' -NoNewline
        Write-Host $m.L -ForegroundColor $m.F -BackgroundColor $m.C -NoNewline
        W ('  ' + $f.Keyword.PadRight(22)) 'White' -NoNewline
        W (('×{0:N0}' -f $f.Count).PadLeft(7)) 'Gray' -NoNewline
        W ('  ' + $f.Category) 'DarkGray'
        if ($Detail) {
            foreach ($s in @($f.Samples | Select-Object -First $Samples)) {
                $t = ($s -replace '[\x00-\x1F]', ' ')
                if ($t.Length -gt ($w - 10)) { $t = $t.Substring(0, $w - 13) + '...' }
                W ('        ' + $t) 'DarkGray'
            }
        }
    }
    $lows = @($findings | Where-Object { $_.Sev -eq 1 } | ForEach-Object { '{0} ×{1:N0}' -f $_.Keyword, $_.Count })
    if ($lows.Count -gt 0) {
        W ''
        $first = $true
        foreach ($l in (Wrap-List $lows ($w - 10))) {
            if ($first) { W '  ' -NoNewline; Write-Host $sevMeta[1].L -ForegroundColor White -BackgroundColor DarkGray -NoNewline; W ('  ' + $l) 'DarkGray'; $first = $false }
            else { W ('        ' + $l) 'DarkGray' }
        }
    }

    # ---- origin hints: package prefixes seen in the matching strings
    $origin = @{}
    foreach ($f in $findings) {
        foreach ($s in $f.Samples) {
            foreach ($m in [regex]::Matches($s.ToLower(), '([a-z][a-z0-9_-]+[/.][a-z][a-z0-9_-]+)[/.](?:modules?|features?|hacks?|cheats?|combat|client)\b')) {
                $k = $m.Groups[1].Value -replace '\.', '/'
                $origin[$k] = 1 + [int]$origin[$k]
            }
        }
    }
    if ($origin.Count -gt 0) {
        $top = @($origin.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })
        W ''
        W '  Origin hint  ' 'Cyan' -NoNewline; W ($top -join ', ') 'White'
        W '  (package seen in the matching strings; find which jar owns it)' 'DarkGray'
    }

    # ---- JVM
    W ''
    if ($jvm.Count -eq 0) { W '  ✓ JVM: no unrecognized agent or risky flags' 'Green' }
    foreach ($j in $jvm) { W ('  ◉ {0}  {1}' -f $j.T, $j.D) 'Yellow' }
    W ''
    W ('━' * ($w - 1)) 'DarkCyan'
    W '  Indicators, not proof. Legit mods/anticheat/chat can contain these strings.' 'DarkGray'
    if ($dumpPath) { W ('  Strings dump: ' + $dumpPath) 'DarkGray' }

    if (-not $NoPause) {
        W ''
        W '  [R]' 'Cyan' -NoNewline; W ' Rescan   ' 'Gray' -NoNewline
        W '[Q]' 'Cyan' -NoNewline; W ' Quit' 'Gray'
        while ($true) {
            try { $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character.ToString().ToUpper() } catch { break }
            if ($k -eq 'R') { $again = $true; break }
            if ($k -eq 'Q') { break }
        }
    }
} while ($again)
