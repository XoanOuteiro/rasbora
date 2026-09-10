function scudp --description "top UDP ports"
    if test (count $argv) -eq 0
        echo "usage: scudp TARGET"; return 1
    end
    set -l target $argv[1]
    __run sudo nmap -sU --top-ports 20 -oN "udp-$target.nmap" $target
end
