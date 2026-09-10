function ketch --description "plain listener"
    set -l port (test (count $argv) -gt 0; and echo $argv[1]; or echo 443)
    __run nc -lvnp $port
end
