function wketch --description "listener that passes terminal size"
    set -l port (test (count $argv) -gt 0; and echo $argv[1]; or echo 443)

    # raw mode is set inside sh -c so the banner still prints on a sane terminal,
    # and dropped again before __run prints the footer
    __run sh -c "stty raw -echo; { stty size; cat; } | nc -lvnp $port; stty sane"
    set -l rc $status

    stty sane   # safety net: the inner one never runs if the listener is killed
    return $rc
end
