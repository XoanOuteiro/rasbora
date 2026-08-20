function snmp --description "snmp enumeration with common strings"
    onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $argv[1]
    snmpwalk -c public -v1 -t 5 $argv[1] 2>/dev/null | head -100
end
