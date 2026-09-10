function rketch --description "listener with readline"
    set -l port (test (count $argv) -gt 0; and echo $argv[1]; or echo 443)
    __run rlwrap nc -lvnp $port
end
