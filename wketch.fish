function wketch --description "listener that passes terminal size"
    stty raw -echo
    begin; stty size; cat; end | nc -lvnp (test (count $argv) -gt 0; and echo $argv[1]; or echo 443)
    stty sane
end
