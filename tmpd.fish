function tmpd --description "cd to a fresh temp dir"
    cd (mktemp -d)
    echo "[*] "(pwd)
end
