function ufzzx --description "content discovery over http, explicit extensions"
    if test (count $argv) -lt 2
        echo "usage: ufzzx HOST[:PORT] EXTENSIONS"; return 1
    end
    __fzz_core http $argv[1] $argv[2] \
        /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
end
