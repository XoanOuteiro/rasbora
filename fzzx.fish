function fzzx --description "content discovery over https, explicit extensions"
    if test (count $argv) -lt 2
        echo "usage: fzzx HOST[:PORT] EXTENSIONS"; return 1
    end
    __fzz_core https $argv[1] $argv[2] \
        /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
end
