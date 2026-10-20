function seasons --description "the standard AD spray wordlist: seasons and months plus years, with and without !"
    if test (count $argv) -lt 1
        echo "usage: seasons YEAR [YEAR...]  > seasons.txt"
        echo "  the year is the one the environment was built, not today's: certificate dates, copyright line, PwdLastSet"
        echo "  example: seasons 2023 2024 > seasons.txt ; spray IP -U users.txt -P seasons.txt -x smb"
        return 1
    end
    set -l words Spring Summer Autumn Fall Winter \
        January February March April May June July August September October November December \
        Password Welcome Changeme
    for y in $argv
        set -l yy (string sub -s 3 -- $y)
        for w in $words
            for base in "$w$y" "$w$yy"
                echo $base
                echo "$base!"
            end
            echo (string lower $w)$y
        end
        echo "Password1" "Password123" "Welcome1" "Welcome123" "P@ssw0rd" "Passw0rd!" | string split ' '
    end | awk '!seen[$0]++'
end
