function smbr --description "enumerate shares, anonymous first"
    if test (count $argv) -eq 0
        echo "usage: smbr IP"; return 1
    end
    set -l ip $argv[1]

    __run sh -c "smbclient -L //$ip -N 2>/dev/null"
    # pipefail, else the banner reports head's exit status and a dead tool logs as success
    __run bash -c "set -o pipefail; enum4linux-ng -A $ip 2>/dev/null | head -60"
end
