function sufzz --description "content discovery over http, 5 requests per second"
    if test (count $argv) -eq 0
        echo "usage: sufzz HOST[:PORT] [wordlist]"; return 1
    end
    set -l wl (test (count $argv) -gt 1; and echo $argv[2]; \
        or echo /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt)
    __fzz_core http $argv[1] "php,html,txt,bak,old,zip" $wl 5
end
