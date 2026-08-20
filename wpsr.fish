function wpsr --description "wpscan with sane defaults"
    wpscan --url $argv[1] \
        --enumerate vp,vt,u,cb \
        --plugins-detection aggressive \
        --random-user-agent \
        --disable-tls-checks
end
