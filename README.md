# rasbora

My fish shell functions. 
Pentesting and OSCP prep plus some other trash.

I started this because im lazy and i dont't like typing stuff.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/XoanOuteiro/rasbora/main/install.sh | bash
```

Copies everything into `~/.config/fish/functions/` and stomps whatever was there under the same name. Run it again to update.

If you already cloned it, it uses those files instead of downloading:

```fish
git clone https://github.com/XoanOuteiro/rasbora.git ~/rasbora
~/rasbora/install.sh
```

Not with sudo. These are user functions and you would be installing them for root.

`RASBORA_REPO`, `RASBORA_REF` and `RASBORA_DEST` if you need to point it somewhere else.

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

`__run` prints the banner directly above the tool's own output, so when you copy the terminal you copy the command with it.

Wrapped: `look`, `smell`, `scudp`, the four fuzz functions, `smbr`, `smbrd`, `snmpr`, `wpsr`, `ketch`, `rketch`, `wketch`, and the servers in `pwncat` and `winpwn`.

Not wrapped: `sinst`, `extr`, `mkcd`, `tmpd`, `fns`, `decrypt`, `ls` and friends, `peep`. None of them touch a target. Same for the downloads in `pwncat` and `winpwn`, that is my box not theirs.

---

## Scanning

| | |
|---|---|
| `look TARGET...` | Two stage nmap. Full 65535 port SYN sweep, pulls the open ports out of the output, then reruns with `-sC -sV -O` on just those. Saves both to `look-TARGET/`. `-Pn` on both so it works on hosts that drop ICMP. Give it as many hosts as you want, one directory each. |
| `look -iL FILE` | Reads the hosts out of a file the way nmap does. Blank lines and `#` comments skipped, duplicates scanned once. Ranges are `smell`'s job. |
| `look -h ...` | Prints the deep scan as a table when it finishes. One block per host, OS junk at the top, then the ports lined up with each one's NSE output underneath. |
| `smell` | ARP sweeps every interface you have a global IPv4 on. Skips tun/wireguard (no ethernet layer, ARP is impossible there) and anything wider than /16. No arguments. |
| `scudp TARGET` | Top 20 UDP ports. Everyone forgets UDP. SNMP and TFTP show up more than they should. |

One dead host does not take the rest of the list with it. You get a warning, it moves to the next one, and it tells you which ones gave nothing at the end.

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
| `smbr IP` | Anonymous share list, then the first 60 lines of enum4linux-ng. Quick first look. |
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

## Windows staging

`winpwn` is `pwncat` for Windows boxes. Pulls about 59 tools into `~/tools/win` and serves them on 7331 in the foreground. `--port N` if you want it elsewhere. Four digits so it never asks for sudo, and nowhere near 443, 1337, 4444 and 9001 where I keep the handlers.

Every filename carries the architecture and the framework. `PrintSpoofer-x64.exe`, `Rubeus-net47-x64.exe`, `GodPotato-net35-x64.exe`. Never a bare `tool.exe` when two builds exist. Uploading the wrong build to a 2008 box is half an hour gone, because wrong architecture and unsupported Windows throw the same error.

Nobody wants to type those into a target shell, so there is a short name for each one and the printed commands use that instead. `jp64.exe`, `ps64.exe`, `mk64.exe`. You get the whole table every run.

| | |
|---|---|
| `winpwn` | Stage everything, print the tables and a certutil line per tool, then serve. |
| `winpwn --port 8080` | Same somewhere else. |
| `winpwn --cmd jp64` | Every way to pull one tool down. certutil, WebClient, iwr, curl, bitsadmin, .NET reflection where it applies. Prints and quits, no server. |

The potato table is the bit I actually use. Windows build on the left, the potato that works on it next to it, worked command underneath with your tun0 address in it.

Already staged means already skipped. A failed fetch is a warning and not an abort, and you get told what is missing at the end. Four are always missing because nobody ships a binary for them: JuicyPotato x86, SharpEfsPotato, RottenPotatoNG, SeRestoreAbuse.

`EXAM-BANNED.txt` lands in the tool dir every run. sqlmap, Nessus, Metasploit past the one machine you get, anything that exploits for you, and every flavour of spoofing and poisoning. No ADCS stuff either, OffSec never put it in the body of knowledge.

CLSID lists for 2008 R2, 2012, 2016, 7 and 10 go in `~/tools/win/clsid/` with `tcb.bat` to brute them. 366 entries in the 2008 R2 one. Have fun.

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

`__run` wraps a command with the logging banner. `__fzz_core` is the shared feroxbuster runner behind the four fuzz functions. `__look_table` draws the `look -h` table out of a `deep.nmap`. `__winpwn_get`, `__winpwn_ghurl` and `__winpwn_member` do the downloading and unpacking for `winpwn`. Do not call them directly.

`__run` executes an argument list, so no pipes, redirects or `&&` inside it. Anything needing those has to go through `sh -c`. Use `bash -c "set -o pipefail; ..."` when there is a pipe, or you read back the status of whatever ran last instead of the tool you cared about.

`__run` single quotes the command instead of backslash escaping it, so an `sh -c` line comes out as `sh -c 'enum4linux-ng -A 10.10.10.5 2>/dev/null | head -60'` and pastes into a report as is. Put a single quote inside one of those strings and fish drops back to backslashes and you get soup. That is why it is `rpcclient -U ""` and not `rpcclient -U ''`, sh reads them the same.

## Gotchas

Editing a function file does not reload it in your current shell. Fish autoloads once and caches. Use `funced NAME` to edit and reload in one go, or `functions -e NAME` to drop the cached copy if you edited the file directly.

An unset variable expands to nothing in fish. `ufzz $RHOSTS` with `RHOSTS` unset becomes bare `ufzz` and you get a usage line that looks like you typed it wrong.

`--min-rate 3000` in `look` trades accuracy for speed. Against rate limiting, a slow VPN hop or an IPS, packets get dropped and ports wont seem open even they are. If a target looks suspiciously empty, rerun without it before you believe the result.

Port 1 in `look` stage two only helps `-O` if it comes back closed. Nmap wants one open and one closed port to fingerprint properly. On a default drop host it reads as filtered and you get the incomplete fingerprint warning anyway.

`look -h` draws to 79 columns. A long NSE line or an OS warning runs past 120 and wraps, and on a narrow terminal the left edge falls apart. Everything is still there, it just stops being a table.

If a target's 404 page returns 200, every content discovery function lights up with thousands of false positives. Check what a garbage URL returns before you trust any scan output, and filter on size instead of status code.

`smbr`, `smbrd` and `snmpr` still cut their output with `head`. 60 lines of enum4linux-ng, 80 in `smbrd`, 100 of snmpwalk. You get no marker where it cut, so a transcript can look finished when it is not. They bin stderr too, so you never find out why something half failed.

Trust the exit code in the footer. Anything with a pipe runs under pipefail, otherwise you read `head`'s status back and a tool you never installed comes up green. `wketch` is the exception, the `stty sane` on the end always works so you always get 0 out of it. It is a listener, ignore it.

## License

MIT. Only point these at things you are allowed to point them at.
