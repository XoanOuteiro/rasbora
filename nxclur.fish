function nxclur --description "nxc LDAP user recon, three views merged into one roster"
    if test (count $argv) -lt 3
        echo "usage: nxclur IP USER SECRET"
        echo "  IP is the DC. Pass \$IP if you set it with target, or any host."
        echo "  SECRET is a password, or an NTLM hash (32 hex, or LM:NT) for pass-the-hash."
        echo "  runs nxc ldap --users, --active-users and --admin-count, then merges:"
        echo "  who is disabled (skip them), who is an admin, who is both (go there first)"
        return 1
    end

    # host first, like every other target-touching function here. No default to
    # $IP: nothing in this repo reads it silently, target just exports it so you
    # can type it yourself. nxclur $IP eric.wallows 'pw' when you want that.
    set -l ip $argv[1]
    set -l user $argv[2]
    set -l secret $argv[3]

    # LDAP speaks NTLM, so SECRET can be a password or a hash. An NTLM hash is
    # 32 hex (NT) or LM:NT; anything else is a password. -H is pass-the-hash,
    # -p is a password. A real password that is exactly 32 hex is vanishingly
    # rare, and __run prints the chosen flag, so a wrong guess is visible at once.
    set -l sflag -p
    if string match -rq '^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$' -- $secret
        set sflag -H
        echo "[*] auth: NTLM hash (pass-the-hash)"
    else
        echo "[*] auth: password"
    end

    set -l uf "ldap-users-$ip.txt"
    set -l af "ldap-active-$ip.txt"
    set -l cf "ldap-admins-$ip.txt"

    # Creds go to __run as plain list args, never spliced into a bash string.
    # That is what makes a password with a space, a $ or a quote safe: fish
    # hands $secret to `command nxc` as one argv element and nothing re-parses it.
    # A literal single quote only costs banner prettiness (string escape falls
    # back to backslashes), the value logged and run is still exact. The pipe to
    # tee is at fish level, OUTSIDE __run, so the "no pipes in __run" rule holds:
    # tee shows the run live and saves it, and $pipestatus[1] is nxc's real exit.
    __run nxc ldap $ip -u $user $sflag $secret --users | tee $uf
    if test $pipestatus[1] -ne 0
        echo "[!] --users failed. Bad creds, no LDAP, or nxc missing. The other two"
        echo "    would fail the same way, so stopping here."
        return 1
    end
    __run nxc ldap $ip -u $user $sflag $secret --active-users | tee $af
    __run nxc ldap $ip -u $user $sflag $secret --admin-count | tee $cf

    # ---- parse ------------------------------------------------------------
    set -l all
    for n in (__nxclur_names $uf)
        contains -- $n $all; or set -a all $n        # AD order, deduped
    end
    set -l active (__nxclur_names $af)
    set -l admins (__nxclur_names $cf)

    if test (count $all) -eq 0
        echo "[!] parsed no users out of $uf. nxc's format may have changed;"
        echo "    the raw file is intact, eyeball it."
        return 1
    end

    # --active-users died but --users lived: don't mark everyone disabled off a
    # blank list, that is a worse lie than saying nothing.
    if test (count $active) -eq 0
        echo "[!] --active-users returned nothing, cannot separate active from"
        echo "    disabled. Treating all as active. Check $af."
        set active $all
    end

    # Descriptions, best effort. The middle column is 'date time' or '<never>',
    # then the badpw count, then the description if there is one. Anchoring on
    # that digit avoids miscutting a description that has its own numbers.
    set -l duser
    set -l dtext
    for pair in (sed -r 's/\x1b\[[0-9;]*m//g' $uf \
            | grep -E '^LDAP' | grep -vE '\[[-*+]\]' | grep -vE -- '-Username-' \
            | sed -E 's/^LDAPS?[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+//' \
            | sed -nE 's/^([^[:space:]]+)[[:space:]]+([^[:space:]]+[[:space:]]+[^[:space:]]+|<never>)[[:space:]]+[0-9]+[[:space:]]+(.+)$/\1\t\3/p')
        set -l kv (string split -m1 (printf '\t') -- $pair)
        set -a duser $kv[1]
        set -a dtext (string trim -- $kv[2])
    end

    # ---- derive -----------------------------------------------------------
    set -l disabled
    for u in $all
        contains -- $u $active; or set -a disabled $u
    end

    set -l builtin Administrator Guest krbtgt DefaultAccount WDAGUtilityAccount

    # group, AD order kept inside each group
    set -l order
    set -l otag
    for u in $all
        if contains -- $u $active; and contains -- $u $admins
            set -a order $u; set -a otag aa
        end
    end
    for u in $all
        if contains -- $u $active; and not contains -- $u $admins
            set -a order $u; set -a otag a
        end
    end
    for u in $all
        contains -- $u $active; and continue
        set -a order $u; set -a otag d
    end

    # ---- draw -------------------------------------------------------------
    set -l C (set_color -o cyan)
    set -l N (set_color normal)
    set -l D (set_color brblack)
    set -l G (set_color green)
    set -l Y (set_color yellow)
    set -l R (set_color -o red)

    echo
    printf "  %s%d users%s · %s%d active%s · %s%d disabled%s · %s%d admin%s\n" \
        $C (count $all) $N $G (count $active) $N $D (count $disabled) $N $R (count $admins) $N

    set -l last ""
    for i in (seq (count $order))
        set -l u $order[$i]
        set -l tag $otag[$i]

        if test "$tag" != "$last"
            set last $tag
            echo
            switch $tag
                case aa; echo "  $R── admin · active ──$N  $D(go here first)$N"
                case a;  echo "  $G── active ──$N"
                case d;  echo "  $D── disabled · cannot log in, skip them ──$N"
            end
        end

        set -l flags ""
        if contains -- $u $admins
            set flags $R"[admin]"$N
            contains -- $u $builtin; or set flags "$flags "$Y"[non-default]"$N
        end

        set -l desc ""
        set -l di (contains -i -- $u $duser)
        test -n "$di"; and set desc $dtext[$di]

        set -l ucol $N
        test "$tag" = d; and set ucol $D

        printf "  %s%-26s%s %s" $ucol $u $N $flags
        test -n "$desc"; and printf "  %s%s%s" $D $desc $N
        echo
    end

    # ---- the tom_admin call-out -------------------------------------------
    # an admin that is not a built-in was created by someone. On a lab box that
    # is almost always the intended path to Domain Admin.
    set -l custom_admin
    for u in $admins
        contains -- $u $builtin; or set -a custom_admin $u
    end
    if test (count $custom_admin) -gt 0
        echo
        echo "  "$Y"[*] non-default admin: "(string join ', ' -- $custom_admin)"$N"
        echo "  $D    not built-in, someone made it. Usually the way up.$N"
    end

    # admin-count named someone --users did not (rare, but don't swallow it)
    set -l ghost
    for u in $admins
        contains -- $u $all; or set -a ghost $u
    end
    test (count $ghost) -gt 0
    and echo "  "$Y"[*] admin not seen in --users: "(string join ', ' -- $ghost)"$N"

    # ---- hand off to the next step ----------------------------------------
    # Active accounts only, one per line. Disabled ones cannot authenticate,
    # so they are noise in AS-REP roasting, kerberoasting and spraying alike.
    set -l list "ldap-names-$ip.txt"
    printf '%s\n' $active | sort -u >$list

    set -l domain (sed -r 's/\x1b\[[0-9;]*m//g' $uf | grep -oE 'domain:[^ )]+' | head -1 | string split -m1 ':')[2]
    test -z "$domain"; and set domain DOMAIN

    echo
    echo "  "$D"[*] active usernames -> $list  ("(count $active)" names)$N"
    set -l hintsecret "-p PASS"
    test "$sflag" = -H; and set hintsecret "-H HASH"
    echo "  $D    impacket-GetNPUsers $domain/ -usersfile $list -dc-ip $ip -no-pass -format hashcat$N"
    echo "  $D    spray $ip -U $list $hintsecret   # every protocol, this is the next move$N"
    echo
end