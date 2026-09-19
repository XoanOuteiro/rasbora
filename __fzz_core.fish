function __fzz_core --description "shared feroxbuster runner"
    set -l scheme $argv[1]
    set -l host $argv[2]
    set -l ext $argv[3]        # may be empty
    set -l wl $argv[4]
    set -l rate $argv[5]       # may be empty, requests per second

    set -l url "$scheme://$host"
    set -l tag (string replace -a ':' '-' $host)

    set -l xargs
    test -n "$ext"; and set xargs -x $ext

    set -l pace --auto-tune -t 50
    set -l out "ferox-$scheme-$tag.txt"

    if test -n "$rate"
        # --rate-limit is per directory scan, and feroxbuster recurses, so
        # without -L 1 the number is a per-branch figure and the real rate is
        # a multiple of it. --auto-tune has to come off too: it walks the rate
        # back up on its own and climbs straight past the ceiling you asked
        # for. 5 threads because 50 of them queueing for 5 slots is pointless.
        set pace --rate-limit $rate -L 1 -t 5
        set out "ferox-$scheme-$tag-slow.txt"
    end

    __run feroxbuster -u $url -w $wl $xargs $pace \
        -d 3 -C 404,400 --insecure \
        -o $out
end
