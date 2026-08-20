function fns --description "list your custom functions with descriptions"
    for f in ~/.config/fish/functions/*.fish
        set -l name (basename $f .fish)
        set -l desc (functions -D -v $name 2>/dev/null)[5]
        printf "%-12s %s\n" $name "$desc"
    end
end
