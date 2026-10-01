function creduse --description "how to use a credential on a service: the next-step commands"
    if test (count $argv) -eq 0
        echo "usage: creduse PROTO [IP USER SECRET]        (PROTO, or 'all')"
        echo "  with no cred it prints templates; give IP USER SECRET to fill them in"
        echo "  USER may be domain\\\\user or domain/user; SECRET may be a password or an NTLM hash"
        echo "  protocols: smb ldap winrm wmi mssql ssh ftp rdp vnc"
        return 1
    end

    set -l proto $argv[1]
    set -l ip IP;    test (count $argv) -ge 2; and set ip $argv[2]
    set -l rawuser USER; test (count $argv) -ge 3; and set rawuser $argv[3]
    set -l sec PASS; test (count $argv) -ge 4; and set sec $argv[4]

    # split domain out of USER if it came as domain\user or domain/user
    set -l dom DOMAIN
    set -l user $rawuser
    set -l norm (string replace -a '\\' '/' -- $rawuser)
    if string match -q '*/*' -- $norm
        set dom (string split -r -m1 / -- $norm)[1]
        set user (string split -r -m1 / -- $norm)[2]
    end

    # detect hash vs password (same rule nxclur uses)
    set -l sflag -p
    string match -rq '^[0-9a-fA-F]{32}(:[0-9a-fA-F]{32})?$' -- $sec; and set sflag -H

    set -l protos $proto
    test "$proto" = all; and set protos smb ldap winrm wmi mssql ssh ftp rdp vnc

    set -l C (set_color -o cyan); set -l N (set_color normal); set -l D (set_color brblack)
    for p in $protos
        echo "$C── "(string upper $p)" ──$N"
        for line in (__cred_guide $p $ip $dom $user $sec $sflag)
            echo "  $line"
        end
        echo
    end
    echo "  $D"$sflag" chosen: "(test "$sflag" = -H; and echo "pass-the-hash"; or echo "password")". Templates, adapt freely.$N"
end