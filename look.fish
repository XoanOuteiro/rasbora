function look --description "full TCP SYN sweep, then deep scan the open ports"
    set -l table 0
    set -l targets

    set -l i 1
    while test $i -le (count $argv)
        switch $argv[$i]
            case -h
                set table 1
            case -iL
                set i (math $i + 1)
                set -l lf $argv[$i]
                if test -z "$lf" -o ! -r "$lf"
                    echo "[!] cannot read host list: $lf"; return 1
                end
                while read -l l
                    set l (string trim -- $l)
                    test -z "$l"; and continue          # nmap skips blanks
                    string match -q '#*' -- $l; and continue   # and comments
                    set -a targets $l
                end <$lf
            case '-*'
                echo "[!] unknown option: $argv[$i]"; return 1
            case '*'
                set -a targets $argv[$i]
        end
        set i (math $i + 1)
    end

    if test (count $targets) -eq 0
        echo "usage: look [-h] TARGET [TARGET...]"
        echo "       look [-h] -iL FILE"
        echo "  -h   print the deep scan as a readable table when everything finishes"
        echo "  ranges are smell's job, give this one hosts"
        return 1
    end

    # scanning the same box twice because it appeared twice in a file is a waste
    set -l uniq
    for t in $targets
        contains -- $t $uniq; or set -a uniq $t
    end
    set targets $uniq

    set -l done_hosts
    set -l failed

    for target in $targets
        set -l tag (string replace -a '/' '_' -- $target)
        set -l outdir "look-$tag"
        mkdir -p $outdir

        if test (count $targets) -gt 1
            echo
            echo "[*] "$target" ("(math (contains -i -- $target $targets))" of "(count $targets)")"
        end

        # one dead host must not kill the rest of the list
        if not __run sudo nmap -sS -Pn -p- --min-rate 3000 -T4 -oN $outdir/sweep.nmap $target
            echo "[!] $target: sweep failed"
            set -a failed $target
            continue
        end

        set -l ports (string replace -rf '^(\d+)/tcp\s+open\s.*' '$1' <$outdir/sweep.nmap | string join ',')

        if test -z "$ports"
            echo "[!] $target: no open TCP ports"
            set -a failed $target
            continue
        end

        if __run sudo nmap -sS -Pn -p 1,$ports -sC -sV -O -oN $outdir/deep.nmap $target
            set -a done_hosts $target
        else
            echo "[!] $target: deep scan failed"
            set -a failed $target
        end
    end

    if test $table -eq 1
        echo
        for h in $done_hosts
            __look_table "look-"(string replace -a '/' '_' -- $h)"/deep.nmap" $h
        end
    end

    if test (count $failed) -gt 0
        echo "[!] nothing usable from: "(string join ', ' $failed)
    end

    test (count $done_hosts) -gt 0
end
