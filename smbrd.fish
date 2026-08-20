function smbrd --description "full SMB enumeration, null session first"
    set -l ip $argv[1]
    echo "=== shares (anonymous)"
    smbclient -L //$ip -N 2>/dev/null
    echo "=== rpcclient null session"
    for c in querydominfo enumdomusers enumdomgroups enumprinters
        echo "--- $c"
        rpcclient -U "" -N $ip -c $c 2>/dev/null
    end
    echo "=== enum4linux"
    enum4linux-ng -A $ip 2>/dev/null | head -80
end
