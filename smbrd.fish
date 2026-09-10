function smbrd --description "full SMB enumeration, null session first"
    if test (count $argv) -eq 0
        echo "usage: smbrd IP"; return 1
    end
    set -l ip $argv[1]

    __run sh -c "smbclient -L //$ip -N 2>/dev/null"

    for c in querydominfo enumdomusers enumdomgroups enumprinters
        __run sh -c "rpcclient -U \"\" -N $ip -c $c 2>/dev/null"
    end

    # pipefail, else the banner reports head's exit status and a dead tool logs as success
    __run bash -c "set -o pipefail; enum4linux-ng -A $ip 2>/dev/null | head -80"
end
