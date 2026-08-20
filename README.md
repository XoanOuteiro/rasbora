# rasbora

My fish shell functions. 
Pentesting and OSCP prep plus some other trash.

I started this because im lazy and i dont't like typing stuff.

## Install

```fish
git clone https://github.com/YOU/rasbora.git ~/rasbora
```
Then you can either symlink these or copypaste em into ~/.config/fish/functions/

## Logging

Every wrapped command prints a banner with the exact command line, start time with timezone offset, UTC alongside it, and elapsed time on finish. Same thing goes to `~/.cmdlog` with user, host and cwd.

```
┌─[2026-08-20T18:31:07+02:00]  (2026-08-20T16:31:07Z)
│ sudo nmap -sS -Pn -p- --min-rate 3000 -T4 -oN look-10.129.168.191/sweep.nmap 10.129.168.191
└──────────────────────────────────────────────────────────────────────
Starting Nmap 7.99 ...
└─[2026-08-20T18:32:41+02:00]  elapsed 94s  exit 0
```

`grep 10.129.168.191 ~/.cmdlog` gets you everything you did to a host. (Very good thing)

Check your clock or these won't count for forensics stuff.

---

## Scanning

| | |
|---|---|
| `look TARGET` | Two stage nmap. Full 65535 port SYN sweep, pulls the open ports out of the output, then reruns with `-sC -sV -O` on just those. Saves both to `look-TARGET/`. `-Pn` on both so it works on hosts that drop ICMP. |
| `smell` | ARP sweeps every interface you have a global IPv4 on. Skips tun/wireguard (no ethernet layer, ARP is impossible there) and anything wider than /16. No arguments. |
| `scudp TARGET` | Top 20 UDP ports. Everyone forgets UDP. SNMP and TFTP show up more than they should. |

## Content discovery

Feroxbuster underneath, because it recurses on its own. All four share `__fzz_core`.

| | |
|---|---|
| `fzz HOST[:PORT]` | Directory discovery over https. Default wordlist is raft-medium-directories, pass a second arg to override. Extensions: php, html, txt, bak, old, zip. |
| `ufzz HOST[:PORT]` | Same but http. |
| `fzzx HOST EXTS` | https, explicit extensions, raft-medium-files. `fzzx 10.10.10.5 asp,aspx,config` when you know the stack. |
| `ufzzx HOST EXTS` | Same but http. |

Output goes to `ferox-SCHEME-HOST.txt` so scanning the same IP on 80, 443 and 8080 does not overwrite itself.

## Service enumeration

| | |
|---|---|
| `smbr IP` | Anonymous share list. Quick first look. |
| `smbrd IP` | The full version. Shares, then rpcclient null session (`querydominfo`, `enumdomusers`, `enumdomgroups`, `enumprinters`), then enum4linux-ng. If null session works you have usernames, which is usually half the box. |
| `snmpr IP` | onesixtyone against the default community string list, then snmpwalk. |
| `wpsr URL` | wpscan with aggressive plugin detection and user enumeration. There is always a WordPress. |

## OSCP plumbing

| | |
|---|---|
| `target IP` | Sets `RHOST`, `RHOSTS`, `IP` and grabs `LHOST` off tun0 automatically. Putting your ethernet IP in a payload instead of your VPN IP is a twenty minute debugging session, this stops that. |
| `ketch [PORT]` | netcat listener, defaults to 443. Not 4444, because boxes that filter egress usually still let 443 out. |
| `rketch [PORT]` | Same but wrapped in rlwrap. Kills the `^[[A^[[B` arrow key garbage and gives you history in a raw shell. Use this when you cannot upgrade to a TTY. |
| `wketch [PORT]` | Passes your terminal dimensions through so long commands do not wrap wrong. Runs `stty sane` on exit so your terminal is not left in raw mode. |
| `pwncat` | Downloads linpeas, winPEAS, pspy, LinEnum into `~/tools` (cached, only fetches once), then serves the directory on port 80. Prints ready to paste `curl \| sh`, `certutil` and `iwr` one liners with your tun0 IP already in them. |

## Everything else

| | |
|---|---|
| `sinst PKG...` | `apt update && apt install -y`. |
| `extr FILE...` | Extracts anything. tar.gz, tar.bz2, tar.xz, zip, 7z, rar, gz, bz2. Extracts into a directory named after the archive so bare archives do not explode into your cwd. |
| `mkcd DIR` | mkdir plus cd. |
| `tmpd` | cd to a fresh temp dir. For trying something destructive. |
| `fns` | Lists every function here with its description. You will forget what you named things. |
| `decrypt CMD` | Pipes a command through `nms` for the Sneakers decryption effect. Completely pointless. `decrypt cat look-10.10.10.5/deep.nmap` looks incredible. |

## Aliases

| | |
|---|---|
| `ls` `ll` `la` `lt` | lsd. `lt` is a two level tree. |
| `peep` | `batcat -l java`, forces java syntax highlighting. |

## Internals

`__run` wraps a command with the logging banner. `__fzz_core` is the shared feroxbuster runner behind the four fuzz functions. Do not call them directly.

`__run` executes an argument list, so no pipes, redirects or `&&` inside it. Anything needing those has to go through `sh -c`.

## Gotchas

Editing a function file does not reload it in your current shell. Fish autoloads once and caches. Use `funced NAME` to edit and reload in one go, or `functions -e NAME` to drop the cached copy if you edited the file directly.

An unset variable expands to nothing in fish. `ufzz $RHOSTS` with `RHOSTS` unset becomes bare `ufzz` and you get a usage line that looks like you typed it wrong.

`--min-rate 3000` in `look` trades accuracy for speed. Against rate limiting, a slow VPN hop or an IPS, packets get dropped and ports wont seem open even they are. If a target looks suspiciously empty, rerun without it before you believe the result.

Port 1 in `look` stage two only helps `-O` if it comes back closed. Nmap wants one open and one closed port to fingerprint properly. On a default drop host it reads as filtered and you get the incomplete fingerprint warning anyway.

If a target's 404 page returns 200, every content discovery function lights up with thousands of false positives. Check what a garbage URL returns before you trust any scan output, and filter on size instead of status code.

## License

MIT. Only point these at things you are allowed to point them at.
