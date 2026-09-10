function __winpwn_get --description "curl a url to a path, tolerate failure"
    set -l url $argv[1]
    set -l dest $argv[2]

    rm -f $dest          # clear any dangling symlink first, curl would ELOOP on it
    if curl -sSL --fail --max-time 180 $url -o $dest 2>/dev/null
        test -s $dest; and return 0
    end
    rm -f $dest          # never leave a half file behind, it would look staged
    return 1
end
