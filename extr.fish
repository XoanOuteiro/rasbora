function extr --description "extract any archive"
    for f in $argv
        if not test -f $f
            echo "[!] $f not found"; continue
        end
        switch $f
            case '*.tar.bz2' '*.tbz2'; tar xjf $f
            case '*.tar.gz' '*.tgz';   tar xzf $f
            case '*.tar.xz';           tar xJf $f
            case '*.tar';              tar xf $f
            case '*.zip';              unzip -q $f
            case '*.7z';               7z x $f
            case '*.rar';              unrar x $f
            case '*.gz';               gunzip $f
            case '*.bz2';              bunzip2 $f
            case '*';                  echo "[!] don't know how to extract $f"
        end
    end
end
