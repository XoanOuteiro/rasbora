function wpsr --description "wpscan with sane defaults"
    if test (count $argv) -eq 0
        echo "usage: wpsr URL"; return 1
    end
    __run wpscan --url $argv[1] \
        --enumerate vp,vt,u,cb \
        --plugins-detection aggressive \
        --random-user-agent \
        --disable-tls-checks
end
