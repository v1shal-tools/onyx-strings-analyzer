[CmdletBinding()]
param(
    [int]$ProcessId = 0,
    [int]$MinLength = 4,
    [int]$Samples   = 2,
    [string]$KeywordFile,
    [switch]$Detail,
    [switch]$DumpStrings,
    [switch]$NoPause
)
 
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 | Out-Null
} catch { }
 
if (-not [Environment]::Is64BitProcess) {
    Write-Host 'Run this in 64-bit PowerShell (not the x86 one).' -ForegroundColor Red
    return
}
 
if (-not ('OnyxScan' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
 
public class OnyxHit {
    public string Keyword; public string Category; public int Severity;
    public long Count; public long CodeCount;
    public bool Ascii; public bool Wide; public ulong FirstAddr;
    public List<string> Samples = new List<string>();
    public HashSet<string> SampleSet = new HashSet<string>();
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
 
    const int CHUNK = 1024 * 1024;
    const int MAXRUN = 2048;
    const ulong MEM_IMAGE = 0x1000000;
 
    static char[] run = new char[MAXRUN];
    static char[] nb = new char[MAXRUN];
    static int[] nm = new int[MAXRUN];
    static int[][] go;
    static List<int>[] outp;
    static string[] kw, cat;
    static int[] sev, klen;
    static OnyxHit[] hitArr;
    static StreamWriter dump;
    static int minLen;
    static bool imageRegion;
 
    static char Fold(char c) {
        if (c >= 0xFF01 && c <= 0xFF5E) c = (char)(c - 0xFEE0);
        else if (c == 0x3000) c = ' ';
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c == '\\' || c == '/') c = '.';
        return c;
    }
 
    static bool Skip(char c) {
        return c == ' ' || c == '_' || c == '-' || c == '\t';
    }
 
    public static void Init(string[] words, string[] cats, int[] sevs) {
        kw = words; cat = cats; sev = sevs;
        klen = new int[words.Length];
        hitArr = new OnyxHit[words.Length];
        HitCount = 0;
        List<int[]> g = new List<int[]>();
        List<int> fail = new List<int>();
        List<List<int>> o = new List<List<int>>();
        Func<int> newNode = delegate() {
            int[] a = new int[128];
            for (int i = 0; i < 128; i++) a[i] = -1;
            g.Add(a); fail.Add(0); o.Add(null);
            return g.Count - 1;
        };
        newNode();
        for (int i = 0; i < words.Length; i++) {
            int s = 0, l = 0;
            foreach (char raw in words[i]) {
                char c = Fold(raw);
                if (Skip(c) || c >= 128) continue;
                l++;
                if (g[s][c] == -1) { int n = newNode(); g[s][c] = n; }
                s = g[s][c];
            }
            klen[i] = l;
            if (l == 0) continue;
            if (o[s] == null) o[s] = new List<int>();
            o[s].Add(i);
        }
        Queue<int> q = new Queue<int>();
        for (int c = 0; c < 128; c++) {
            int n = g[0][c];
            if (n == -1) g[0][c] = 0; else { fail[n] = 0; q.Enqueue(n); }
        }
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
                    regs.Add(new ulong[] { b, s, m.Type }); TotalBytes += (long)s;
                }
                ulong nx = b + s; if (nx <= addr) break; addr = nx;
                if (addr > 0x7FFFFFFFFFFFUL) break;
            }
            byte[] buf = new byte[CHUNK];
            foreach (ulong[] rg in regs) {
                imageRegion = rg[2] == MEM_IMAGE;
                ulong off = 0;
                while (off < rg[1]) {
                    int want = (int)Math.Min((ulong)CHUNK, rg[1] - off);
                    ReadScan(h, rg[0] + off, want, buf);
                    off += (ulong)want; DoneBytes += want;
                }
            }
        }
        catch (Exception ex) { Error = ex.Message; }
        finally {
            if (dump != null) { dump.Flush(); dump.Dispose(); dump = null; }
            CloseHandle(h); Done = true;
        }
    }
 
    // when a block can't be read, split it and retry so one bad page doesn't hide the rest
    static void ReadScan(IntPtr h, ulong addr, int size, byte[] buf) {
        UIntPtr got;
        if (ReadProcessMemory(h, (IntPtr)(long)addr, buf, (UIntPtr)size, out got) && got != UIntPtr.Zero) {
            int n = (int)(ulong)got;
            ScanAscii(buf, n, addr);
            ScanWide(buf, n, addr);
            return;
        }
        if (size <= 4096) return;
        int half = (size / 2) & ~4095;
        if (half == 0) half = 4096;
        ReadScan(h, addr, half, buf);
        ReadScan(h, addr + (ulong)half, size - half, buf);
    }
 
    // plain ascii plus utf-8 fullwidth (EF BC xx / EF BD xx), which is how class constants store it
    static void ScanAscii(byte[] b, int n, ulong baseAddr) {
        int len = 0, start = 0, i = 0;
        while (i <= n) {
            int c = i < n ? b[i] : 0;
            int step = 1;
            char ch = '\0';
            bool ok = false;
            if ((c >= 0x20 && c < 0x7F) || c == 9) { ch = (char)c; ok = true; }
            else if (c == 0xEF && i + 2 < n &&
                     ((b[i + 1] == 0xBC && b[i + 2] >= 0x81 && b[i + 2] <= 0xBF) ||
                      (b[i + 1] == 0xBD && b[i + 2] >= 0x80 && b[i + 2] <= 0x9E))) {
                ch = (char)(b[i + 1] == 0xBC ? 0xFF00 + (b[i + 2] - 0x80) : 0xFF40 + (b[i + 2] - 0x80));
                ok = true; step = 3;
            }
            else if (c == 0xE3 && i + 2 < n && b[i + 1] == 0x80 && b[i + 2] == 0x80) { ch = ' '; ok = true; step = 3; }
            if (ok) {
                if (len == 0) start = i;
                if (len >= MAXRUN) { ProcessRun(len, baseAddr + (ulong)start, false); len = 0; start = i; }
                run[len++] = ch;
            } else {
                if (len >= minLen) ProcessRun(len, baseAddr + (ulong)start, false);
                len = 0;
            }
            i += step;
        }
    }
 
    static void ScanWide(byte[] b, int n, ulong baseAddr) {
        int len = 0, start = 0;
        for (int i = 0; i + 1 < n; i += 2) {
            char c = (char)(b[i] | (b[i + 1] << 8));
            bool ok = (c >= 0x20 && c < 0x7F) || (c >= 0xFF01 && c <= 0xFF5E) || c == 0x3000;
            if (ok) {
                if (len == 0) start = i;
                if (len >= MAXRUN) { ProcessRun(len, baseAddr + (ulong)start, true); len = 0; start = i; }
                run[len++] = c;
            } else {
                if (len >= minLen) ProcessRun(len, baseAddr + (ulong)start, true);
                len = 0;
            }
        }
        if (len >= minLen) ProcessRun(len, baseAddr + (ulong)start, true);
    }
 
    static void ProcessRun(int len, ulong addr, bool wide) {
        StringsSeen++;
        if (dump != null) dump.WriteLine((wide ? "W " : "A ") + new string(run, 0, len));
        int n = 0;
        for (int i = 0; i < len; i++) {
            char c = Fold(run[i]);
            if (Skip(c)) continue;
            nb[n] = c >= 128 ? '\u0001' : c;
            nm[n] = i;
            n++;
        }
        if (n < 4) return;
        int s = 0;
        for (int j = 0; j < n; j++) {
            s = go[s][nb[j]];
            List<int> o = outp[s];
            if (o == null) continue;
            foreach (int k in o) Record(k, nm[j - klen[k] + 1], nm[j], len, wide, addr);
        }
    }
 
    // the match has to start and end on a word edge; camelCase humps count as edges
    static bool EdgeOk(int a, int b, int len, bool wide) {
        bool left = a == 0 || !char.IsLetter(run[a - 1]);
        if (!left) {
            char p = run[a - 1];
            if (char.IsLower(p) && char.IsUpper(run[a])) left = true;
            else if (!wide && a == 1) left = true; // class files put a length byte in front of names
            else if (p == 'L' && char.IsUpper(run[a]) && (a == 1 || !char.IsLetter(run[a - 2]))) left = true; // LName;
        }
        if (!left) return false;
        if (b + 1 >= len) return true;
        char q = run[b + 1];
        if (!char.IsLetter(q)) return true;
        return char.IsLower(run[b]) && char.IsUpper(q);
    }
 
    static bool CodeChar(char c) {
        return char.IsLetter(c) || c == '/' || c == '$' || c == ';' || c == '(' || c == '_' || c == '"' || c == '\'' || c == '.';
    }
 
    // identifier or standalone string vs a keyword dropped in the middle of a sentence
    static bool CodeLike(int a, int b, int len) {
        if (b - a + 2 >= len) return true;
        char l = a > 0 ? run[a - 1] : ' ';
        char r = b + 1 < len ? run[b + 1] : ' ';
        if (r == '.') {
            if (b + 2 < len && char.IsLetterOrDigit(run[b + 2])) return true;
            r = ' ';
        }
        return CodeChar(l) || (r != ' ' && CodeChar(r));
    }
 
    static void Record(int k, int a, int b, int len, bool wide, ulong addr) {
        if (imageRegion && sev[k] < 3) return;
        if (!EdgeOk(a, b, len, wide)) return;
        OnyxHit h = hitArr[k];
        if (h == null) {
            h = new OnyxHit(); h.Keyword = kw[k]; h.Category = cat[k]; h.Severity = sev[k]; h.FirstAddr = addr;
            hitArr[k] = h; HitCount++;
        }
        bool code = CodeLike(a, b, len);
        h.Count++;
        if (code) h.CodeCount++;
        if (wide) h.Wide = true; else h.Ascii = true;
        if (h.Samples.Count < 6 && (code || h.Samples.Count < 2)) {
            int st = Math.Max(0, a - 50);
            int en = Math.Min(len, b + 71);
            string s = new string(run, st, en - st);
            if (h.SampleSet.Add(s)) h.Samples.Add(s);
        }
    }
}
'@
}
 
$DefaultKeywords = @'
3|Known client|vape.gg;vapeclient;vapelite;liquidbounce;rusherhack;konas;futureclient;impactclient;aristois;novoline;pandaware;riseclient;rise.today;doomsdayclient;doomsday.jar;novaclient;novoclient;novoware;api.novaclient.lol;dqrkis;dqrkis.xyz;catleanclient;prestigeclient;prestigeclient.vip;xenonclient;asteriaclient;gypsyclient;argonclient;virginclient;grimclient;fdp-client;intent.store;intentclient;skid.krypton;dev.krypton;198macros;wurstclient;bleachhack;thunderhack
2|Known client|meteordevelopment;meteorclient;meteor-client;moonclient
3|Known IOC|aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA
3|Client package|org.chainlibs;xyz.greaj;dev.gambleclient;dev.virel;cc.novoline;net.ccbluex;today.opai;club.maxstats;wtf.moonlight;com.alan.clients;me.zeroeightsix.kami;phantom-refmap.json;client-refmap.json;cheat-refmap.json
3|Combat module|autocrystal;crystalaura;autohitcrystal;lwfh crystal;autoanchor;anchoraura;anchormacro;anchortweaks;doubleanchor;safeanchor;airanchor;autodoublehand;autototem;hovertotem;inventorytotem;legittotem;autopot;autopotrefill;shieldbreaker;shielddisabler;triggerbot;aimassist;aimbot;silentaim;killaura;clickaura;multiaura;autoclicker;maceswap;automace;spearswap;stunslam;axespam;webmacro;autoweb;keypearl;pingspoof;fakelag;lagreach;popswitch;lootyeeter;autobreach;antiknockback;hitboxexpand;reachhack;bedaura;autonethpot;autodtap;walksyoptimizer;walskyoptimizer;fakepunch;macro198
3|Credential stealer|tokenlogger;tokengrabber;sessionstealer;discordtoken
2|Combat / utility|autoarmor;autofirework;elytraswap;fastxp;fastexp;autocrit;critbypass;alwayscrit;sprintreset;wtap;targetstrafe;autogap;autopearl;autosword;autoweapon;autotpa;blockesp;antibot;antimissclick;fakeinv;packspoof;bowaimbot;autobow;bowspam;offhandtotem;totemswitch;autobed;bedbomb;autocity;holefiller;antisurround;antiburrow;selftrap;noknockback;kbreduce;legitaura;headsnap;doubleclicker;jitterclick;butterflyclick;cpsboost;cheststealer;invmovebypass
2|Anticheat bypass|grimvelocity;grimdisabler;grimbypass;vulcanbypass;matrixbypass;intavebypass;watchdogbypass;verusdisabler;aacbypass;velocityspoof;fakelatency;fakeping;spoofrotation;positionspoof;selfdestruct;hideclient;authbypass;obfuscatedauth;licensecheckmixin
2|Remote access|keylogger;reverseshell;c2server
2|Movement / exploit|flyhack;packetfly;boatfly;creativeflight;airjump;speedhack;bunnyhop;nofalldamage;noslowdown;waterwalk;liquidwalk;lavawalk;scaffoldwalk;fastbridge;nuker;instantbreak;ghosthand;noswing;packetmine;packetwalk;packetsneak;packetcancel;packetdupe;packetspam;itemexploit;freezeplayer;stephack;fastclimb;instantelytra
2|Visual / ESP|playeresp;mobesp;itemesp;storageesp;chestesp;oreesp;wallhack;xrayhack;orefinder;cavefinder;stashfinder;trailfinder;basefinder;tunnelfinder;newchunks;targethud
2|Module setting|silent rotations;smooth rotations;click simulation;glowstone delay;glowstone chance;explode delay;explode chance;explode slot;predict crystals;predict damage;auto inventory totem;horizontal aim speed;vertical aim speed;stop on kill;stop on crystal;place chance;break chance;totem slot;totem first;strict one-tick;require crit;require hold axe;require elytra;only on pop;only charge;mace priority;activate on right click;activates above;hold crystal;dont place crystal;dont break crystal;can place crystal server;autocrystalplaceclock;attack registered this click;find knockback sword;swap back to original slot;pot_cheats;lvstrng;breaking shield with axe;failed to switch to mace after axe;places two anchors for massive damage;automatically switches to sword when hitting with totem;removes the crystal bounce animation;no count glitch;anti weakness;easing strength;use easing;min totems;min pearls;loot yeeter;fake punch;double_escape;double_rightclick_first;double_rightclick_second;post_cycle_delay;place_obi;wait_obi;reoffhand_totem;heal pot slot;speed pot slot;strength pot slot;prevent sword block breaking;prevent sword block attack
2|Obfuscator|skidfuscator;paramorphism;zkmflow;superblaubeere;qprotect;branchlock;binscure;caesium;bozar;itzsomebody.radon;licel.stringer;jnic.obf;scutiobf
1|Weak marker|invokedoattack;invokedoitemuse;invokeonmousebutton;setblockbreakingcooldown;setitemusecooldown;clientplayerinteractionmanageraccessor;onpushoutofblocks;onisglowing;freecam;criticals;jumpreset;fastplace;autosprint;tracers;nobounce;jnativehook;nativekeylistener;imgui.gl3;imgui.glfw;imgui.binding
'@
 
function ConvertTo-Key {
    param([string]$Text)
    $t = $Text.ToLowerInvariant().Replace('\', '.').Replace('/', '.')
    return ($t -replace '[\s_\-]', '')
}
 
function Get-KeywordTable {
    $text = $DefaultKeywords
    if ($KeywordFile -and (Test-Path $KeywordFile)) { $text += "`n" + (Get-Content -Raw -Encoding UTF8 $KeywordFile) }
    $map = @{}
    foreach ($line in ($text -split "`r?`n")) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $p = $line.Split('|', 3)
        if ($p.Count -lt 3) { continue }
        $sev = 0
        if (-not [int]::TryParse($p[0], [ref]$sev) -or $sev -lt 1 -or $sev -gt 3) { continue }
        foreach ($word in ($p[2] -split ';')) {
            $word = $word.Trim()
            $key = ConvertTo-Key $word
            if ($key.Length -lt 4) { continue }
            if (-not $map.ContainsKey($key) -or $map[$key].Sev -lt $sev) {
                $map[$key] = @{ Sev = $sev; Cat = $p[1].Trim(); Name = $word.ToLowerInvariant() }
            }
        }
    }
    $keys = @($map.Keys | Sort-Object)
    [pscustomobject]@{
        Words = [string[]]@($keys | ForEach-Object { $map[$_].Name })
        Cats  = [string[]]@($keys | ForEach-Object { $map[$_].Cat })
        Sevs  = [int[]]@($keys | ForEach-Object { $map[$_].Sev })
    }
}
 
function Say {
    param([string]$Text = '', [ConsoleColor]$Color = 'Gray', [switch]$NoNewline)
    if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
    else { Write-Host $Text -ForegroundColor $Color }
}
 
function New-Bar {
    param([double]$Value, [double]$Max, [int]$Size)
    if ($Max -le 0) { $Max = 1 }
    $fill = [int][Math]::Round($Size * [Math]::Min(1.0, $Value / $Max))
    return (('█' * $fill) + ('░' * ($Size - $fill)))
}
 
function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N0} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}
 
function Limit-Text {
    param([string]$Text, [int]$Max)
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, [Math]::Max(0, $Max - 1)) + '…'
}
 
function Write-BoxLine {
    param([string]$Text, [ConsoleColor]$Color = 'Gray')
    $inner = $width - 4
    Say ('║ ' + (Limit-Text $Text $inner).PadRight($inner) + ' ║') $Color
}
 
function Write-Wrapped {
    param([string[]]$Items, [int]$Max, [string]$Indent)
    $cur = ''
    foreach ($i in $Items) {
        $next = if ($cur) { $cur + ', ' + $i } else { $i }
        if ($cur -and $next.Length -gt $Max) { Say ($Indent + $cur + ',') DarkGray; $cur = $i }
        else { $cur = $next }
    }
    if ($cur) { Say ($Indent + $cur) DarkGray }
}
 
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
    Say ''
    for ($i = 0; $i -lt $rows.Count; $i++) { Say ('        ' + $rows[$i]) $colors[$i] }
    Say ''
    Say '        M E M O R Y   S T R I N G   A N A L Y Z E R' Cyan
    Say '        v0.4.0  •  read-only memory scan' DarkGray
    Say ''
    Say ('─' * ($width - 1)) DarkCyan
    Say ''
}
 
function Get-Candidates {
    $procs = @(Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction SilentlyContinue)
    $out = foreach ($p in $procs) {
        $cl = [string]$p.CommandLine
        $ws = 0
        try { $ws = (Get-Process -Id $p.ProcessId -ErrorAction Stop).WorkingSet64 } catch { }
        [pscustomobject]@{
            Pid     = [int]$p.ProcessId
            Name    = $p.Name
            Cmd     = $cl
            IsMc    = [bool]($cl -match '(?i)minecraft|fabricmc|fabric-loader|--gameDir|--assetsDir|modrinth|prism|lunar|badlion|tlauncher|launchwrapper|forge')
            Created = $p.CreationDate
            WS      = $ws
        }
    }
    @($out | Sort-Object @{ e = 'IsMc'; Descending = $true }, @{ e = 'WS'; Descending = $true })
}
 
function Select-Target {
    $found = @(Get-Candidates)
    if ($ProcessId -gt 0) { $found = @($found | Where-Object { $_.Pid -eq $ProcessId }) }
    if ($found.Count -eq 0) {
        Say '  ✗ No java/javaw process found. Launch Minecraft, get in-game, then run again.' Red
        return $null
    }
    if ($found.Count -eq 1) { return $found[0] }
    $mc = @($found | Where-Object { $_.IsMc })
    if ($mc.Count -eq 1) { return $mc[0] }
    if ($NoPause) { return $found[0] }
 
    Say '  Multiple Java processes found:' Yellow
    for ($i = 0; $i -lt $found.Count; $i++) {
        $tag = if ($found[$i].IsMc) { 'minecraft?' } else { '' }
        Say ('   [{0}] PID {1,-6} {2,-10} {3,10}  {4}' -f ($i + 1), $found[$i].Pid, $found[$i].Name, (Format-Size $found[$i].WS), $tag) Gray
    }
    $sel = Read-Host '  Select target # (Enter = 1)'
    $n = 0
    Say ''
    if ([int]::TryParse($sel, [ref]$n) -and $n -ge 1 -and $n -le $found.Count) { return $found[$n - 1] }
    return $found[0]
}
 
function Show-Target {
    param($Target)
    $ver = ''
    if ($Target.Cmd -match '--version\s+"?([^\s"]+)') { $ver = $Matches[1] }
    $up = ''
    try { $u = (Get-Date) - $Target.Created; $up = 'up {0}h {1}m' -f [int][Math]::Floor($u.TotalHours), $u.Minutes } catch { }
    $parts = @($Target.Name, "PID $($Target.Pid)", (Format-Size $Target.WS), $up, $ver) | Where-Object { $_ }
    $priv = if ($isAdmin) { 'elevated' } else { 'not elevated' }
    Say ('  ' + ($parts -join '  •  ')) White
    Say ('  {0} keywords  •  {1}' -f $kw.Words.Count, $priv) DarkGray
    Say ''
}
 
function Get-JvmFindings {
    param([string]$Cmd)
    $list = New-Object System.Collections.Generic.List[object]
    if (-not $Cmd) { return , $list }
    $trusted = 'jmxremote|yjp|jrebel|newrelic|jacoco|theseus|opentelemetry|datadog|authlib-injector'
    foreach ($m in [regex]::Matches($Cmd, '-javaagent:("[^"]+"|[^\s]+)')) {
        $agent = $m.Groups[1].Value.Trim('"')
        if ($agent -notmatch $trusted) { $list.Add([pscustomobject]@{ Title = 'Unrecognized -javaagent'; Info = $agent }) }
    }
    $flags = @(
        @('-Xbootclasspath/p:', 'prepends to bootstrap classpath'),
        @('-Xbootclasspath/a:', 'appends to bootstrap classpath'),
        @('-agentlib:jdwp', 'JDWP remote debugging enabled'),
        @('-agentpath:', 'native agent loaded')
    )
    foreach ($f in $flags) {
        if ($Cmd.IndexOf($f[0], [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $list.Add([pscustomobject]@{ Title = "JVM flag $($f[0])"; Info = $f[1] })
        }
    }
    return , $list
}
 
function Get-Findings {
    $rows = @(foreach ($h in [OnyxScan]::GetHits()) {
        $level = [int]$h.Severity
        $code = [long]$h.CodeCount
        if ($code -lt 2) { $level-- }
        if ($code -eq 0) { $level-- }
        if ($level -lt 1) { $level = 1 }
        [pscustomobject]@{
            Keyword  = $h.Keyword
            Key      = ConvertTo-Key $h.Keyword
            Category = $h.Category
            Sev      = $level
            Count    = [long]$h.Count
            Code     = $code
            Weak     = ($code -lt 2)
            Samples  = @($h.Samples)
        }
    })
 
    $settingsSeen = @($rows | Where-Object { $_.Category -eq 'Module setting' -and $_.Code -ge 1 }).Count
    if ($settingsSeen -lt 2) {
        foreach ($r in $rows) { if ($r.Category -eq 'Module setting') { $r.Sev = 1 } }
    }
 
    $kept = @($rows | Where-Object {
        $a = $_
        -not ($rows | Where-Object { $_.Key -ne $a.Key -and $_.Key.Contains($a.Key) -and $_.Count -ge $a.Count })
    })
    @($kept | Sort-Object @{ e = 'Sev'; Descending = $true }, @{ e = 'Count'; Descending = $true })
}
 
function Start-Scan {
    param($Target)
    $dumpPath = $null
    if ($DumpStrings) { $dumpPath = Join-Path $env:TEMP ('Onyx_strings_{0}.txt' -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }
 
    [OnyxScan]::Init($kw.Words, $kw.Cats, $kw.Sevs)
    [OnyxScan]::Start($Target.Pid, $MinLength, $dumpPath)
 
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $spin = @('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')
    $frame = 0
    while (-not [OnyxScan]::Done) {
        Start-Sleep -Milliseconds 120
        $total = [OnyxScan]::TotalBytes
        $done = [OnyxScan]::DoneBytes
        $pct = if ($total -gt 0) { [Math]::Min(100, [int](100 * $done / $total)) } else { 0 }
        $line = '  {0} {1} {2,3}%  {3} / {4}  hits {5}  {6:mm\:ss}' -f $spin[$frame % 10], (New-Bar $done $total 24), $pct, (Format-Size $done), (Format-Size $total), [OnyxScan]::HitCount, $clock.Elapsed
        Write-Host ("`r" + $line.PadRight($width - 1)) -ForegroundColor Cyan -NoNewline
        $frame++
    }
    $clock.Stop()
    Write-Host ("`r" + (' ' * ($width - 1)) + "`r") -NoNewline
 
    if ([OnyxScan]::Error) {
        Say ('  ✗ ' + [OnyxScan]::Error) Red
        return $null
    }
 
    [pscustomobject]@{
        Findings = @(Get-Findings)
        Jvm      = @(Get-JvmFindings $Target.Cmd)
        Strings  = [OnyxScan]::StringsSeen
        Bytes    = [OnyxScan]::DoneBytes
        Seconds  = $clock.Elapsed.TotalSeconds
        DumpPath = $dumpPath
    }
}
 
function Show-Report {
    param($Scan)
    $all = @($Scan.Findings)
    $jvm = @($Scan.Jvm)
    $hi = @($all | Where-Object { $_.Sev -eq 3 }).Count
    $me = @($all | Where-Object { $_.Sev -eq 2 }).Count + $jvm.Count
    $weak = @($all | Where-Object { $_.Sev -eq 1 })
 
    $score = 100 - [Math]::Min(75, $hi * 25) - [Math]::Min(20, $me * 4)
    $grade = if ($score -ge 90) { 'A' } elseif ($score -ge 75) { 'B' } elseif ($score -ge 60) { 'C' } elseif ($score -ge 40) { 'D' } else { 'F' }
    $risk = if ($hi -ge 3) { 'CRITICAL' } elseif ($hi -ge 1) { 'HIGH' } elseif ($me -ge 1) { 'REVIEW' } else { 'NO INDICATORS' }
    $riskColor = switch ($risk) { 'CRITICAL' { 'Red' } 'HIGH' { 'Red' } 'REVIEW' { 'Yellow' } default { 'Green' } }
 
    Say ('╔' + ('═' * ($width - 2)) + '╗') DarkGray
    Write-BoxLine ('{0}  {1}/100  GRADE {2}   RISK {3}' -f (New-Bar $score 100 20), $score, $grade, $risk) $riskColor
    Write-BoxLine ('HIGH {0}    MED {1}    WEAK {2}' -f $hi, $me, $weak.Count) Gray
    Write-BoxLine ('{0:N0} strings  •  {1}  •  {2:N1}s' -f $Scan.Strings, (Format-Size $Scan.Bytes), $Scan.Seconds) DarkGray
    Say ('╚' + ('═' * ($width - 2)) + '╝') DarkGray
    Say ''
 
    $shown = @($all | Where-Object { $_.Sev -ge 2 })
    if ($shown.Count -eq 0) {
        Say '  ✓ No keyword indicators found in readable process memory.' Green
        Say '    A clean result is not proof: strings can be encrypted or built at runtime.' DarkGray
    }
    else {
        Say '  FINDINGS' White
        Say ('  ' + ('─' * ($width - 4))) DarkGray
        Say ('  {0}  {1}  {2}  {3}' -f 'LEVEL', 'KEYWORD'.PadRight(30), 'HITS'.PadLeft(8), 'CATEGORY') DarkGray
        foreach ($f in $shown) {
            $s = $sevStyle[$f.Sev]
            Say '  ' -NoNewline
            Write-Host $s.Label -ForegroundColor $s.Fore -BackgroundColor $s.Back -NoNewline
            Say ('  ' + (Limit-Text $f.Keyword 30).PadRight(30)) White -NoNewline
            Say (('×{0:N0}' -f $f.Count).PadLeft(8)) Gray -NoNewline
            Say ('  ' + $f.Category) DarkGray -NoNewline
            if ($f.Weak) { Say '  weak' DarkYellow -NoNewline }
            Say ''
            if ($script:showDetail) {
                foreach ($smp in @($f.Samples | Select-Object -First $Samples)) {
                    $t = $smp -replace '[\x00-\x1F]', ' '
                    Say ('        ' + (Limit-Text $t ($width - 10))) DarkGray
                }
            }
        }
        if (@($shown | Where-Object { $_.Weak }).Count -gt 0) {
            Say ''
            Say '  weak = seen once, or only inside plain text, so the level was lowered' DarkGray
        }
    }
 
    if ($script:showDetail -and $weak.Count -gt 0) {
        Say ''
        Say '  WEAK SIGNALS (not scored)' White
        $items = @($weak | ForEach-Object { '{0} ×{1:N0}' -f $_.Keyword, $_.Count })
        Write-Wrapped $items ($width - 8) '    '
    }
 
    $origin = @{}
    foreach ($f in $shown) {
        foreach ($smp in $f.Samples) {
            foreach ($m in [regex]::Matches($smp.ToLower(), '([a-z][a-z0-9_-]+[/.][a-z][a-z0-9_-]+)[/.](?:modules?|features?|hacks?|cheats?|combat|client)\b')) {
                $k = $m.Groups[1].Value -replace '\.', '/'
                $origin[$k] = 1 + [int]$origin[$k]
            }
        }
    }
    if ($origin.Count -gt 0) {
        $top = @($origin.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { '{0} ({1})' -f $_.Key, $_.Value })
        Say ''
        Say '  Origin hint  ' Cyan -NoNewline
        Say ($top -join ', ') White
        Say '  package seen in the matching strings, check which jar owns it' DarkGray
    }
 
    Say ''
    Say '  JVM' White
    Say ('  ' + ('─' * ($width - 4))) DarkGray
    if ($jvm.Count -eq 0) { Say '  ✓ no unrecognized agent or risky flags' Green }
    foreach ($j in $jvm) { Say ('  ◉ {0}  {1}' -f $j.Title, $j.Info) Yellow }
 
    Say ''
    Say ('━' * ($width - 1)) DarkCyan
    Say '  Findings are indicators, not proof. Check the context before deciding.' DarkGray
    if ($Scan.DumpPath) { Say ('  Strings dump: ' + $Scan.DumpPath) DarkGray }
}
 
function Show-Keys {
    Say ''
    Say '  [R]' Cyan -NoNewline; Say ' Rescan    ' Gray -NoNewline
    Say '[D]' Cyan -NoNewline; Say ' Details on/off    ' Gray -NoNewline
    Say '[Q]' Cyan -NoNewline; Say ' Quit' Gray
}
 
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$kw = Get-KeywordTable
$script:showDetail = [bool]$Detail
$sevStyle = @{
    3 = @{ Label = ' HIGH '; Back = 'Red';      Fore = 'White' }
    2 = @{ Label = ' MED  '; Back = 'Yellow';   Fore = 'Black' }
    1 = @{ Label = ' LOW  '; Back = 'DarkGray'; Fore = 'White' }
}
try { $width = [Math]::Min(100, $Host.UI.RawUI.WindowSize.Width - 2) } catch { $width = 78 }
if ($width -lt 60) { $width = 60 }
 
do {
    $again = $false
    Show-Banner
 
    $target = Select-Target
    if (-not $target) { break }
    Show-Target $target
 
    $scan = Start-Scan $target
    if (-not $scan) { break }
    Show-Report $scan
 
    if (-not $NoPause) {
        Show-Keys
        while ($true) {
            try { $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character.ToString().ToUpper() } catch { break }
            if ($key -eq 'R') { $again = $true; break }
            if ($key -eq 'Q') { break }
            if ($key -eq 'D') {
                $script:showDetail = -not $script:showDetail
                Show-Banner
                Show-Target $target
                Show-Report $scan
                Show-Keys
            }
        }
    }
} while ($again
