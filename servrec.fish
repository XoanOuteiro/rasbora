function servrec --description 'per-service enum menu for a port/service (rasbora)'
    set -l db (dirname (status filename))/servrec.db
    test -f ~/.rasbora/servrec.db; and set db ~/.rasbora/servrec.db
    set -l verbose 0; set -l q ''
    for a in $argv
        switch $a
            case -v --verbose; set verbose 1
            case '*'; set q $a
        end
    end
    if test -z "$q"
        echo "usage: servrec <port|service> [-v]   e.g. servrec 445   |   servrec smb -v"; return 1
    end
    test -z "$RHOST"; and echo "⚠  \$RHOST unset — run `target <ip>` first"
    awk -F'\t' -v q="$q" '!/^#/ && ($1==q || index($2,q))' $db | while read -l row
        set -l f (string split \t -- $row)
        set -l port $f[1]; set -l tag $f[3]; set -l src $f[4]; set -l cmd $f[5]
        set -q PORT; and set port $PORT
        set cmd (string replace -a '$RHOST' -- "$RHOST" $cmd)
        set cmd (string replace -a '$PORT' -- "$port" $cmd)
        set_color cyan; printf '%-16s' $tag
        set_color normal; printf ' %s\n' $cmd
        test $verbose -eq 1; and begin; set_color brblack; printf '%18s%s\n' '' $src; set_color normal; end
    end
end
