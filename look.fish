function look --description "full TCP SYN sweep, then deep scan the open ports"
    if test (count $argv) -eq 0
        echo "usage: look TARGET"; return 1
    end

    set -l target $argv[1]
    set -l outdir "look-$target"
    mkdir -p $outdir

    __run sudo nmap -sS -Pn -p- --min-rate 3000 -T4 -oN $outdir/sweep.nmap $target
    or return 1

    set -l ports (string replace -rf '^(\d+)/tcp\s+open\s.*' '$1' <$outdir/sweep.nmap | string join ',')

    if test -z "$ports"
        echo "[!] no open TCP ports found"
        return 1
    end

    __run sudo nmap -sS -Pn -p 1,$ports -sC -sV -O -oN $outdir/deep.nmap $target
end
