function __fzz_core --description "shared feroxbuster runner"
    set -l scheme $argv[1]
    set -l host $argv[2]
    set -l ext $argv[3]        # may be empty
    set -l wl $argv[4]

    set -l url "$scheme://$host"
    set -l tag (string replace -a ':' '-' $host)

    set -l xargs
    test -n "$ext"; and set xargs -x $ext

    feroxbuster -u $url -w $wl $xargs \
        -t 50 -d 3 -C 404,400 --auto-tune --insecure \
        -o "ferox-$scheme-$tag.txt"
end
