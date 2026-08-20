function smell --description "ARP-sweep every locally attached IPv4 subnet"
    set -l found 0

    for line in (ip -o -4 addr show scope global)
        set -l f (string split -n ' ' (string trim $line))
        set -l iface $f[2]
        set -l cidr $f[4]
        set -l prefix (string split '/' $cidr)[2]

        if not ip -o link show $iface | string match -qr 'link/ether'
            echo "[-] $iface ($cidr) — no ethernet layer, ARP N/A"; continue
        end
        if test $prefix -ge 31 -o $prefix -lt 16
            echo "[-] $iface ($cidr) — skipping"; continue
        end

        set found 1
        __run sudo nmap -sn -PR -n -oN "smell-$iface.nmap" $cidr
    end

    test $found -eq 0; and echo "[!] no ARP-capable interfaces"; and return 1
end
