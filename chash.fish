function chash --description "identify a hash, say whether it is worth attacking, print both commands"
    if test (count $argv) -eq 0
        echo "usage: chash HASH"
        echo "       chash FILE [WORDLIST]"
        echo "  wordlist defaults to /usr/share/wordlists/rockyou.txt"
        return 1
    end

    set -l subject $argv[1]
    set -l wl /usr/share/wordlists/rockyou.txt
    test (count $argv) -ge 2; and set wl $argv[2]
    set -l rules /usr/share/hashcat/rules/best64.rule

    set -l C (set_color -o cyan)
    set -l N (set_color normal)
    set -l B (set_color -o)
    set -l D (set_color brblack)
    set -l Y (set_color yellow)
    set -l G (set_color green)
    set -l R (set_color -o red)

    # ---- files that are not hashes yet ------------------------------------
    # A .zip or an id_rsa contains a hash, it is not one. Print the extraction
    # step instead of a cracking command nobody can run.
    if test -f "$subject" -a -r "$subject"
        set -l base (string lower -- (basename $subject))
        set -l magic (od -An -tx1 -N8 $subject 2>/dev/null | string join '' | string replace -a ' ' '')
        set -l helper ""
        set -l pkg john
        set -l after ""

        # extension first: a .docx is also a zip, and zip2john is the wrong answer
        switch $base
            case '*.docx' '*.xlsx' '*.pptx' '*.doc' '*.xls' '*.ppt'
                set helper office2john.py
                set after "-m 9400 / 9500 / 9600, or 9700 / 9800 for Office 2003 and older"
            case '*.zip'
                set helper zip2john
                set after "-m 13600 for WinZip AES, 17200 through 17230 for PKZIP"
            case '*.rar'
                set helper rar2john
                set after "-m 12500 for RAR3, 13000 for RAR5"
            case '*.7z'
                set helper 7z2john.pl
                set after "-m 11600"
            case '*.kdbx' '*.kdb'
                set helper keepass2john
                set after "-m 13400, or 29700 for a keyfile-only database"
            case '*.pdf'
                set helper pdf2john.pl
                set after "-m 10400 through 10700, the PDF version decides"
            case '*.dmg'
                set helper dmg2john
                set after "john only. hashcat has no DMG mode, 21100 is something else entirely"
            case '*.vhd' '*.vhdx' '*.bitlocker'
                set helper bitlocker2john
                set after "-m 22100"
            case '*.pcap' '*.pcapng' '*.cap'
                set helper hcxpcapngtool
                set pkg hcxtools
                set after "-m 22000. For john instead: wpapcap2john $subject > hash.txt, the two tools do not share a format here. No handshake and no PMKID in the capture means no hash at all"
            case 'id_rsa' 'id_dsa' 'id_ecdsa' 'id_ed25519' '*.pem' '*.key'
                set helper ssh2john.py
                set after "-m 22911 through 22951, the KDF decides which"
            case 'shadow' 'shadow.bak' 'passwd'
                set helper unshadow
                set after "then run chash on the result, the crypt prefix decides the mode"
        end

        if test -z "$helper"
            switch $magic
                case '504b0304*'
                    set helper zip2john
                    set after "-m 13600 for WinZip AES, 17200 through 17230 for PKZIP"
                case '526172211a07*'
                    set helper rar2john
                    set after "-m 12500 for RAR3, 13000 for RAR5"
                case '377abcaf271c*'
                    set helper 7z2john.pl
                    set after "-m 11600"
                case '03d9a29a*' '03d9a29b*'
                    set helper keepass2john
                    set after "-m 13400"
                case '25504446*'
                    set helper pdf2john.pl
                    set after "-m 10400 through 10700"
                case '2d2d2d2d2d424547*'
                    set helper ssh2john.py
                    set after "-m 22911 through 22951"
            end
        end

        if test -n "$helper"
            # locate it: PATH first, then the Kali layout, where the scripts
            # live in /usr/share/john and only the binaries are on PATH
            set -l loc (command -v $helper 2>/dev/null)
            test -z "$loc" -a -f /usr/share/john/$helper; and set loc /usr/share/john/$helper

            set -l run $helper
            if test -n "$loc"
                set run $loc
                switch $helper
                    case '*.py'
                        set run "python3 $loc"
                    case '*.pl'
                        set run "perl $loc"
                end
            end

            echo
            printf "  %s%-48s%s %s%s%s\n" $B (basename $subject) $N $Y "not a hash yet" $N
            echo
            echo "  This is a container. Pull the hash out of it first."
            echo

            if test "$helper" = unshadow
                echo "    $run /etc/passwd $subject > hash.txt"
            else if test "$helper" = hcxpcapngtool
                echo "    $run -o hash.txt $subject"
            else
                echo "    $run $subject > hash.txt"
            end
            echo "    chash hash.txt"
            echo
            echo "  $D""then: $after$N"

            if test -z "$loc"
                echo
                echo "  $R$helper is not on PATH and not in /usr/share/john.$N"
                echo "  $D""apt install $pkg$N"
            end
            echo
            return 0
        end
    end

    # ---- collect the subjects ---------------------------------------------
    set -l lines
    set -l nums
    set -l from_file 0

    if test -f "$subject" -a -r "$subject"
        set from_file 1
        set -l n 0
        while read -l l
            set n (math $n + 1)
            set l (string trim -- $l)
            set l (string trim --chars='"' -- $l)
            set l (string trim --chars="'" -- $l)
            test -z "$l"; and continue                  # blanks are not misses
            string match -q '#*' -- $l; and continue    # nor are comments
            set -a lines $l
            set -a nums $n
        end <$subject
    else
        set -l l (string trim -- $subject)
        set l (string trim --chars='"' -- $l)
        set l (string trim --chars="'" -- $l)
        set -a lines $l
        set -a nums 1
    end

    if test (count $lines) -eq 0
        echo "[!] nothing to identify in $subject"
        return 1
    end

    # pwdump lines carry two hashes. Report the NT field, and the LM field only
    # when it is not the empty placeholder.
    set -l subjects
    set -l saw_pwdump 0
    for i in (seq (count $lines))
        set -l pw (string match -r '^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):' -- $lines[$i])
        if test (count $pw) -gt 0
            set saw_pwdump 1
            string match -qr '^(?i)aad3b435b51404eeaad3b435b51404ee$' -- $pw[4]
            or set -a subjects "$nums[$i]~lm~$pw[4]"
            set -a subjects "$nums[$i]~auto~$pw[5]"
        else
            set -a subjects "$nums[$i]~auto~$lines[$i]"
        end
    end

    # ---- group ------------------------------------------------------------
    set -l keys
    set -l recs
    set -l counts
    set -l samples
    set -l unrec

    for s in $subjects
        set -l p (string split -m2 '~' -- $s)
        set -l rec
        if test "$p[2]" = lm
            set rec "lm~LM hash~3000~LM~crack~fast~Case insensitive and broken into two seven character halves, so it falls fast. Crack it, then recover the real case from the NT hash.~"
        else
            set rec (__chash_id $p[3])
        end

        set -l key (string split -m1 '~' -- $rec)[1]
        if contains -- $key $keys
            set -l idx (contains -i -- $key $keys)
            set counts[$idx] (math $counts[$idx] + 1)
        else
            set -a keys $key
            set -a recs $rec
            set -a counts 1
            set -a samples $p[3]
        end
        test "$key" = unknown; and set -a unrec "$p[1]~$p[3]"
    end

    # ---- draw -------------------------------------------------------------
    set -l ntypes 0
    for k in $keys
        test "$k" = unknown; or set ntypes (math $ntypes + 1)
    end

    set -l tgt hash.txt
    test $from_file -eq 1; and set tgt $subject

    echo
    if test $from_file -eq 1
        printf "  %s%d lines, %d %s, %d unrecognised%s\n" $C (count $lines) $ntypes \
            (test $ntypes -eq 1; and echo type; or echo types) (count $unrec) $N
    end

    set -l want_backend 0
    set -l want_potfile 0
    set -l want_save 0

    for i in (seq (count $keys))
        test "$keys[$i]" = unknown; and continue

        set -l f (string split -m7 '~' -- $recs[$i])
        set -l name $f[2]
        set -l hc $f[3]
        set -l jf $f[4]
        set -l use $f[5]
        set -l hard $f[6]
        set -l note $f[7]
        set -l alt $f[8]

        # two independent questions, so two labels. What is it good for as it
        # stands, and separately, what does cracking it cost.
        set -l ulabel ""
        set -l ucol $N
        set -l ublurb ""
        switch $use
            case asis
                set ulabel "USE AS-IS"; set ucol $G
                set ublurb "This is the credential itself, not a derivation of it. Authenticate with it directly, there is nothing to crack first."
            case relay
                set ulabel "RELAY OR CRACK"; set ucol $Y
                set ublurb "Captured off the wire. This cannot be passed. It is a challenge response, not the NT hash, however much it looks like one. Two real options, relay it or crack it."
            case crackonly
                set ulabel "CRACK ONLY"; set ucol $R
                set ublurb "Useless until cracked, and it cannot be passed under any circumstances. People assume it can because it came out of a Windows dump."
            case crack
                set ulabel "MUST CRACK"; set ucol $D
            case decode
                set ulabel "DECODE"; set ucol $G
                set ublurb "Reversible obfuscation, not a digest. There is nothing to crack, it decodes instantly."
            case none
                set ulabel "NOTHING HERE"; set ucol $D
        end

        set -l hlabel ""
        set -l hcol $N
        set -l hblurb ""
        switch $hard
            case trivial
                set hlabel "trivial"; set hcol $G
                set hblurb "Seconds against any wordlist."
            case fast
                set hlabel "fast"; set hcol $G
                set hblurb "Unsalted or cheap. If the password is anywhere near a wordlist this falls in minutes, so put rules on from the start."
            case moderate
                set hlabel "moderate"; set hcol $G
                set hblurb "Salted and iterated, but not punishing. A wordlist pass is worth running."
            case slow
                set hlabel "slow"; set hcol $Y
                set hblurb "Built to resist. This is a leave-it-running-while-you-do-something-else hash, not a wait-for-it hash."
            case futile
                set hlabel "usually futile"; set hcol $R
                set hblurb "If it does not fall to rockyou plus best64 in the first few minutes, it is not the intended path and the time goes better elsewhere."
        end

        echo
        if test $from_file -eq 1
            set -l cnt "$counts[$i] "(test $counts[$i] -eq 1; and echo hash; or echo hashes)
            printf "  %s%-30s%s %s%-9s%s %s%s%s" $B $name $N $D $cnt $N $ucol $ulabel $N
        else
            printf "  %s%-38s%s %s%s%s" $B $name $N $ucol $ulabel $N
        end
        test -n "$hlabel"; and printf " %s·%s %s%s%s" $D $N $hcol $hlabel $N
        echo

        for b in $ublurb $hblurb $note
            test -n "$b"; or continue
            # the hardness line is noise when nobody is going to crack it
            test "$b" = "$hblurb" -a "$use" = asis; and continue
            test "$b" = "$hblurb" -a "$use" = decode; and continue
            echo
            echo "  $b" | fold -s -w 76 | sed 's/^/  /;1s/^  //'
        end

        if test "$use" = asis
            echo
            if test $from_file -eq 1
                echo "    Pass these. Run chash on a single one for the commands."
            else
                echo "    nxc smb TARGET -u USER -H $samples[$i]"
                echo "    evil-winrm -i TARGET -u USER -H $samples[$i]"
                echo "    impacket-psexec DOM/USER@TARGET -hashes :$samples[$i]"
            end
        end

        if test "$use" = relay
            echo
            echo "    ntlmrelayx.py -tf targets.txt -smb2support"
            echo "  $D""relaying needs SMB signing disabled on the target$N"
        end

        if test "$use" = decode
            set -l c7 "import sys;k='dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87';h=sys.argv[1];s=int(h[:2]);print(''.join(chr(int(h[i:i+2],16)^ord(k[(s+(i-2)//2)%53])) for i in range(2,len(h),2)))"
            echo
            if command -q python3
                set -l plain (python3 -c "$c7" $samples[$i] 2>/dev/null)
                test -n "$plain"; and echo "    $G$plain$N"
            end
            echo "    python3 -c \"$c7\" $samples[$i]"
        end

        # hashcat cannot read a pwdump line, john can. Cut the column out
        # first and point only the hashcat line at the result.
        set -l hctgt $tgt
        if test $from_file -eq 1 -a $saw_pwdump -eq 1
            if test "$keys[$i]" = nt
                set hctgt nt.txt
                echo
                echo "  $D""hashcat cannot read pwdump lines, john can. For hashcat:$N"
                echo "    cut -d: -f4 $tgt | sort -u > nt.txt"
            else if test "$keys[$i]" = lm
                set hctgt lm.txt
                echo
                echo "  $D""hashcat cannot read pwdump lines, john can. For hashcat:$N"
                echo "    cut -d: -f3 $tgt | sort -u > lm.txt"
            end
        end

        # the commands. Always both tools, hashcat first, and always an
        # explicit --format= so john does not autodetect its way into
        # cracking the wrong interpretation for an hour.
        if test "$use" = asis
            echo
            echo "  $D""crack it only if you need the cleartext somewhere that refuses a"
            echo "  hash, like RDP or a web login:$N"
        end

        set -l shown 0
        if test "$hc" != -
            set -l line "hashcat -m $hc $hctgt $wl"
            contains -- $hard trivial fast moderate; and set line "$line -r $rules"
            echo
            echo "    $line"
            set shown 1
            set want_save 1
            set want_potfile 1
            contains -- $hard slow futile; and set want_backend 1
        end
        if test "$jf" != -
            set -l line "john --format=$jf --wordlist=$wl"
            contains -- $hard trivial fast moderate; and set line "$line --rules=best64"
            test $shown -eq 1; or echo
            echo "    $line $tgt"
            set want_save 1
        end

        # the second plausible reading, when the string alone cannot settle it
        if test -n "$alt" -a $from_file -eq 0
            set -l a (string split -m2 ',' -- $alt)
            echo
            echo "  Ambiguous. $a[3]:" | fold -s -w 76 | sed 's/^/  /;1s/^  //'
            if test "$a[1]" != -
                echo
                echo "    hashcat -m $a[1] $tgt $wl"
                echo "    john --format=$a[2] --wordlist=$wl $tgt"
                set want_save 1
                set want_potfile 1
            end
        end
    end

    # ---- what did not match ------------------------------------------------
    if test (count $unrec) -gt 0
        echo
        for u in $unrec
            set -l p (string split -m1 '~' -- $u)
            set -l txt $p[2]
            test (string length -- $txt) -gt 60; and set txt (string sub -l 60 -- $txt)"..."
            if test $from_file -eq 1
                printf "  %sunrecognised: line %-5s%s \"%s\"\n" $R $p[1] $N $txt
            else if test (string length -- $p[2]) -gt 400
                echo "  $R""unrecognised, and over 400 characters.$N"
                echo "  That is usually a file path that does not exist, or a paste accident."
                echo "  \"$txt\""
            else
                printf "  %sunrecognised%s \"%s\"\n" $R $N $txt
            end
        end
        echo
        echo "  $D""nothing in the table matched. The escape hatches:$N"
        echo "    hashcat --example-hashes | grep -B2 -i FRAGMENT"
        echo "    john --list=formats | tr ',' '\\n' | grep -i FRAGMENT"
    end

    # ---- footer -------------------------------------------------------------
    echo
    if test $from_file -eq 0 -a $want_save -eq 1
        echo "  $D""the commands above read hash.txt:  echo '$lines[1]' > hash.txt$N"
    end
    if test $want_save -eq 1; and not test -r "$wl"
        if test -r "$wl.gz"
            echo "  $R$wl is still gzipped.$N  gunzip $wl.gz"
        else
            echo "  $R$wl is not readable.$N"
        end
    end
    if test $want_backend -eq 1
        echo "  $D""hashcat dying at startup on this VM? -D 1 for CPU only, or --force,"
        echo "  or just use the john line, which needs no backend at all.$N"
    end
    if test $want_potfile -eq 1
        echo "  $D""empty hashcat output is usually the potfile, not a failure."
        echo "  --show to print what it already has, --potfile-disable to redo it.$N"
    end
    echo
end
