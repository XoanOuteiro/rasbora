function snmpr --description "snmp enumeration with common strings"
    if test (count $argv) -eq 0
        echo "usage: snmpr IP"; return 1
    end
    set -l ip $argv[1]

    __run onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $ip
    # pipefail, else the banner reports head's exit status and a dead tool logs as success
    __run bash -c "set -o pipefail; snmpwalk -c public -v1 -t 5 $ip 2>/dev/null | head -100"
end
