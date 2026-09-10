function __winpwn_member --description "pull one member out of a cached zip or tarball"
    set -l cache $argv[1]
    set -l url $argv[2]
    set -l member $argv[3]
    set -l dest $argv[4]

    set -l arch $cache/(string split -r -m1 / $url)[-1]
    if not test -f $arch
        __winpwn_get $url $arch; or return 1
    end

    switch $arch
        case '*.tar.gz' '*.tgz'
            tar -xzOf $arch $member >$dest 2>/dev/null
        case '*.gz'
            gunzip -c $arch >$dest 2>/dev/null
        case '*'
            unzip -p $arch $member >$dest 2>/dev/null
    end

    test -s $dest; and return 0
    rm -f $dest
    return 1
end
