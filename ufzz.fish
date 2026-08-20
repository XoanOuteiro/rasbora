function ufzz --description "content discovery over http"
    if test (count $argv) -eq 0
        echo "usage: ufzz HOST[:PORT] [wordlist]"; return 1
    end
    set -l wl (test (count $argv) -gt 1; and echo $argv[2]; \
        or echo /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt)
    __fzz_core http $argv[1] "php,html,txt,bak,old,zip" $wl
end
