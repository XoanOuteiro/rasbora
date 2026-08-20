function rketch --description "listener with readline"
    rlwrap nc -lvnp (test (count $argv) -gt 0; and echo $argv[1]; or echo 443)
end
