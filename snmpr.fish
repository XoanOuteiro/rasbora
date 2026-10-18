function snmpr --description "full SNMP walk from the root, every community, rendered and diffed"
    argparse 'c/community=+' 'p/port=' 'w/wordlist=' 'n/nobrute' 'q/quiet' -- $argv
    or return 1

    if test (count $argv) -ne 1
        echo "usage: snmpr IP [-c COMMUNITY]... [-p PORT] [-w LIST] [-n] [-q]"
        echo "  -c  community string, repeatable. None given: onesixtyone finds them"
        echo "  -p  port, default 161"
        echo "  -w  community wordlist for onesixtyone"
        echo "  -n  no brute, just try public and private"
        echo "  -q  write the report, do not print it"
        echo "  walks .1 not mib-2, so the enterprise tree (extend, ucd, lanmanager) is in"
        return 1
    end
    set -l ip $argv[1]
    set -l port 161
    set -q _flag_port; and set port $_flag_port
    set -l outdir "snmpr-$ip"
    mkdir -p $outdir

    # ---- which communities ---------------------------------------------
    set -l comms $_flag_community
    if test (count $comms) -eq 0
        if set -q _flag_nobrute
            set comms public private
        else
            set -l wl
            if set -q _flag_wordlist
                set wl $_flag_wordlist
            else
                for cand in /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
                            /usr/share/seclists/Discovery/SNMP/snmp.txt \
                            /usr/share/doc/onesixtyone/dict.txt
                    test -r $cand; and set wl $cand; and break
                end
            end
            if test -z "$wl"
                echo "[!] no community wordlist found, falling back to public/private (-w LIST)"
                set comms public private
            else
                # onesixtyone prints:  IP [community] sysDescr
                __run bash -c "set -o pipefail; onesixtyone -c $wl -p $port $ip 2>/dev/null | tee $outdir/onesixtyone.txt"
                set comms (string replace -rf '^\S+ \[([^\]]+)\].*' '$1' <$outdir/onesixtyone.txt)
                if test (count $comms) -eq 0
                    echo "[!] onesixtyone found nothing, trying public/private anyway"
                    set comms public private
                end
            end
        end
    end
    set -l uniq
    for c in $comms
        contains -- $c $uniq; or set -a uniq $c
    end
    set comms $uniq
    echo "[*] communities: "(string join ', ' $comms)

    # ---- walk every community from the root --------------------------------
    # .1 and not the default start, because the default is mib-2 and the walk
    # stops dead at the first enterprise OID. -On so the record is numeric and
    # the report keys on prefixes that never depend on which MIBs you have.
    # -Cc keeps going past non-increasing OIDs, which some agents emit mid-tree;
    # timeout bounds the loop that -Cc makes possible on a truly broken one.
    set -l walked
    set -l empty
    for c in $comms
        set -l tag (string replace -ra '[^A-Za-z0-9_.-]' '_' -- $c)
        set -l walk "$outdir/walk-$tag-v2c.txt"
        set -l prev
        if test -s $walk
            set prev "$walk.prev"
            mv $walk $prev
        end

        __run bash -c "timeout 900 snmpbulkwalk -v2c -c \"$c\" -On -Cc -Cr50 -t 3 -r 2 $ip:$port .1 > $walk 2>$walk.err"

        if not test -s $walk
            rm -f $walk          # a zero-byte v2c file next to a real v1 one just confuses
            # v2c dead: v1 still answers on old agents. v1 silently drops
            # Counter64, which is why it is the fallback and not the default.
            set walk "$outdir/walk-$tag-v1.txt"
            if test -s $walk
                set prev "$walk.prev"
                mv $walk $prev
            end
            __run bash -c "timeout 900 snmpwalk -v1 -c \"$c\" -On -Cc -t 3 -r 2 $ip:$port .1 > $walk 2>$walk.err"
        end

        if not test -s $walk
            rm -f $walk
            set -a empty $c
            echo "[!] $c: nothing came back. wrong string, view-restricted, or not 161/udp"
            test -s $walk.err; and head -3 $walk.err
            rm -f $walk.err
            continue
        end
        test -s $walk.err; or rm -f $walk.err
        set -a walked $walk

        set -l report "$outdir/report-$tag.txt"
        if set -q _flag_quiet
            __snmpr_report $walk $report $prev >/dev/null
        else
            __snmpr_report $walk $report $prev
        end
        echo
        echo "[*] $c: "(wc -l <$walk)" lines -> $walk"
        echo "[*] report -> $report"
    end

    if test (count $empty) -gt 0
        echo "[!] no data from: "(string join ', ' $empty)
    end
    if test (count $walked) -gt 0
        echo
        echo "[*] next:"
        echo "    grep -i -E 'pass|pwd|cred|key|token|secret' $outdir/walk-*.txt   # words, if they used them"
        echo "    snmpget -v2c -c COMMUNITY $ip 1.3.6.1.2.1.1.4.0            # then snmpset the same value back:"
        echo "    snmpset -v2c -c COMMUNITY $ip 1.3.6.1.2.1.1.4.0 s 'SAME'   # RW if it succeeds, nothing changed. RW + net-snmp = extend RCE"
        echo "    servrec 161"
    end
    test (count $walked) -gt 0
end
