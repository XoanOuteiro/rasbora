function __look_table --description "render one deep nmap scan as a grouped table"
    set -l f $argv[1]
    set -l host $argv[2]

    if not test -f $f
        echo "[!] $host: no deep scan to show"
        return 1
    end

    set -l meta          # "label|value"
    set -l ports         # "port/proto|state|service|version"
    set -l scripts       # "port/proto|text"   (leading indent kept)
    set -l warns
    set -l cur ""

    while read -l line
        # 22/tcp   open  ssh   OpenSSH 7.4 (protocol 2.0)
        set -l pm (string match -r '^(\d+/(?:tcp|udp))\s+(\S+)\s+(\S+)\s*(.*)$' -- $line)
        if test (count $pm) -gt 0
            set cur $pm[2]
            set -a ports "$pm[2]|$pm[3]|$pm[4]|"(string trim -- $pm[5])
            continue
        end

        # | script output, possibly several lines, indent is meaningful
        if string match -qr '^\|' -- $line
            if test -n "$cur"
                # '|_' marks a script's last line; swap the _ for a space so it
                # lines up with the '| ' lines above it instead of shifting left
                set -l txt (string replace -r '^\|_' ' ' -- $line)
                set -a scripts "$cur|"(string trim -r -- (string replace -r '^\|' '' -- $txt))
            end
            continue
        end

        set -l mm (string match -r '^(Host is up|Not shown|Device type|Running|OS details|OS CPE|Aggressive OS guesses|Service Info|MAC Address|Network Distance)\s*:?\s*(.*)$' -- $line)
        if test (count $mm) -gt 0
            set -a meta "$mm[2]|"(string trim -- $mm[3])
            set cur ""      # metadata ends the port's script block
            continue
        end

        if string match -qr '^Warning:|may be unreliable|fingerprint' -- $line
            set -a warns (string trim -- $line)
            set cur ""
        end
    end <$f

    # ---- draw -------------------------------------------------------------
    set -l C (set_color -o cyan)
    set -l N (set_color normal)
    set -l B (set_color -o)
    set -l G (set_color green)
    set -l Y (set_color yellow)
    set -l D (set_color brblack)

    set -l w (math "max(8, 75 - "(string length -- $host)")")
    echo "$C┌─ $host "(string repeat -n $w '─')"$N"

    for m in $meta
        set -l p (string split -m1 '|' $m)
        printf "%s│%s %s%-16s%s %s\n" $C $N $D $p[1] $N $p[2]
    end
    for wrn in $warns
        printf "%s│%s %s%-16s%s %s\n" $C $N $Y "warning" $N $wrn
    end

    test (count $meta) -gt 0 -o (count $warns) -gt 0
    and echo "$C├"(string repeat -n 78 '─')"$N"

    printf "%s│%s %s%-11s %-9s %-16s %s%s\n" $C $N $D PORT STATE SERVICE VERSION $N

    set -l n_open 0
    set -l n_filt 0
    set -l n_other 0
    for p in $ports
        set -l q (string split -m3 '|' $p)
        set -l col $D
        switch $q[2]
            case 'open'
                set col $G; set n_open (math $n_open + 1)
            case '*filtered*'
                set col $Y; set n_filt (math $n_filt + 1)
            case '*'
                set n_other (math $n_other + 1)
        end
        set -l row (printf "%s│%s %s%-11s%s %s%-9s%s %-16s %s" \
            $C $N $B $q[1] $N $col $q[2] $N $q[3] $q[4])
        echo (string trim -r -- $row)

        for s in $scripts
            set -l t (string split -m1 '|' $s)
            test "$t[1]" = "$q[1]"; or continue
            printf "%s│%s   %s%s%s\n" $C $N $D $t[2] $N
        end
    end

    echo "$C└"(string repeat -n 78 '─')"$N"
    printf "   %s%d open%s · %d filtered · %d other · %s\n" \
        $G $n_open $N $n_filt $n_other (string replace ~ '~' -- $f)
    echo
end
