function target --description "set the current box"
    if test (count $argv) -eq 0
        echo "usage: target IP"; return 1
    end

    # One box, every name a cheatsheet might reach for, so a pasted command
    # works whichever one it happens to use. No port here on purpose: that
    # changes per service, and a stale RPORT is worse than no RPORT.
    for v in RHOST RHOSTS TARGET IP
        set -gx $v $argv[1]
    end

    set -gx LHOST (ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+')

    echo "[*] RHOST RHOSTS TARGET IP = $argv[1]"
    if test -z "$LHOST"
        echo "[!] no tun0, so LHOST is empty. Start the VPN before you build a payload."
    else
        echo "[*] LHOST = $LHOST"
    end
end
