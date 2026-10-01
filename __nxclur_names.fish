function __nxclur_names --description "pull usernames out of an nxc ldap enum, do not call directly"
    set -l f $argv[1]
    test -r "$f"; or return 1

    # tee saved the coloured stream, so strip ANSI first. Then keep the LDAP
    # data rows, drop the [*]/[+]/[-] status lines and the -Username- header,
    # cut the "LDAP ip port host" prefix off the front, and the username is
    # field one. Works for --users, --active-users and --admin-count alike:
    # in the first two the name leads the row, in --admin-count it IS the row.
    # ^LDAPS? so a scan over 636 parses the same as one over 389.
    sed -r 's/\x1b\[[0-9;]*m//g' $f \
        | grep -E '^LDAP' \
        | grep -vE '\[[-*+]\]' \
        | grep -vE -- '-Username-' \
        | sed -E 's/^LDAPS?[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]+[^[:space:]]+[[:space:]]+//' \
        | awk 'NF {print $1}'
end