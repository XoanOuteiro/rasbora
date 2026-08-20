function target --description "set the current box"
    set -gx RHOST $argv[1]
    set -gx LHOST (ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+')
    echo "[*] RHOST=$RHOST  LHOST=$LHOST"
end
