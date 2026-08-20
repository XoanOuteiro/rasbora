function scudp --description "top UDP ports"
    sudo nmap -sU --top-ports 20 -oN "udp-$argv[1].nmap" $argv[1]
end
