function smbr --description "enumerate shares, anonymous first"
    echo "=== anonymous shares"
    smbclient -L //$argv[1] -N 2>/dev/null
    echo "=== null session enum"
    enum4linux-ng -A $argv[1] 2>/dev/null | head -60
end
