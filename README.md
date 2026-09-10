# rasbora

My fish shell functions. 
Pentesting and OSCP prep plus some other trash.

I started this because im lazy and i dont't like typing stuff.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/XoanOuteiro/rasbora/main/install.sh | bash
```

Drops every function into `~/.config/fish/functions/`, overwriting whatever is already there under
the same name. Run it again to update.

From a clone it uses the files next to it instead of downloading:

```fish
git clone https://github.com/XoanOuteiro/rasbora.git ~/rasbora
~/rasbora/install.sh
```

Do not run it with sudo, these are user functions and you would be installing them for root.

`RASBORA_REPO`, `RASBORA_REF` and `RASBORA_DEST` override the repo, the branch and where it installs.

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

The banner sits right above the tool's own output, so a copied terminal transcript carries the
command that made it. `~/.cmdlog` is the index, the scrollback is the evidence.

Wrapped: `look`, `smell`, `scudp`, the four fuzz functions, `smbr`, `smbrd`, `snmpr`, `wpsr`,
`ketch`, `rketch`, `wketch`, and the server in `pwncat` and `winpwn`. Anything that touches a target
or catches a shell.

Not wrapped: `sinst`, `extr`, `mkcd`, `tmpd`, `fns`, `decrypt`, the `ls` family and `peep`. None of
them touch a target so they would just be noise between the real entries. Same for the tool
downloads in `pwncat` and `winpwn`, that is my box not theirs.

---

## Scanning

| | |
|---|---|
| `look TARGET...` | Two stage nmap. Full 65535 port SYN sweep, pulls the open ports out of the output, then reruns with `-sC -sV -O` on just those. Saves both to `look-TARGET/`. `-Pn` on both so it works on hosts that drop ICMP. Takes any number of hosts, one directory each. |
| `look -iL FILE` | Same but reads hosts from a file like nmap does. Blank lines and `#` comments skipped, duplicates scanned once. Ranges are `smell`'s job. |
| `look -h ...` | Prints the deep scan as a table once everything finishes. One block per host, OS and metadata up top, then aligned port rows with each port's NSE output underneath. Same data, just laid out. |
| `smell` | ARP sweeps every interface you have a global IPv4 on. Skips tun/wireguard (no ethernet layer, ARP is impossible there) and anything wider than /16. No arguments. |
| `scudp TARGET` | Top 20 UDP ports. Everyone forgets UDP. SNMP and TFTP show up more than they should. |

A dead host does not kill the rest of the list. It warns and moves on, and anything that gave
nothing gets named at the end.

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

`winpwn` is `pwncat` for Windows boxes. Stages around 59 tools into `~/tools/win` and serves them on
7331 in the foreground. `--port N` moves it. Four digits so it never needs sudo, and nowhere near
443, 1337, 4444 or 9001 where the handlers live.

Every file keeps its architecture and framework in the name. `PrintSpoofer-x64.exe`,
`Rubeus-net47-x64.exe`, `GodPotato-net35-x64.exe`. Never a bare `tool.exe` when variants exist.
Wrong architecture and unsupported Windows version are the same error message and cost the same
twenty minutes to tell apart.

Those names are miserable to type into a target shell, so everything gets a short name next to it
and every printed command uses the short one. `jp64.exe`, `ps64.exe`, `mk64.exe`, `rub64.exe`. The
table prints on every run.

| | |
|---|---|
| `winpwn` | Stage, print the alias table, the potato table and a certutil line per tool, then serve. |
| `winpwn --port 8080` | Same on another port. |
| `winpwn --cmd jp64` | Every transfer method for one tool. certutil, WebClient, iwr, curl, bitsadmin, and .NET reflection where it applies. Prints and exits, does not serve. |

The potato table is the useful part. Windows build to the potato that actually works on it, with a
worked command for each and your tun0 address already in it.

Staging skips anything already there and keeps going when a fetch fails. Whatever did not land gets
named at the end. Four never land because nobody ships a binary: JuicyPotato x86, SharpEfsPotato,
RottenPotatoNG, SeRestoreAbuse.

`EXAM-BANNED.txt` gets written every run. sqlmap, Nessus, Metasploit past the one permitted machine,
automatic exploitation, and every kind of spoofing and poisoning. No ADCS tooling either, it is not
in the published body of knowledge.

CLSID lists for 2008 R2, 2012, 2016, 7 and 10 land in `~/tools/win/clsid/` with `tcb.bat` to brute
them. The 2008 R2 list really is 366 entries.

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

`__run` wraps a command with the logging banner. `__fzz_core` is the shared feroxbuster runner behind the four fuzz functions. `__look_table` draws the `look -h` table out of a `deep.nmap`. `__winpwn_get`, `__winpwn_ghurl` and `__winpwn_member` do the fetching and unpacking for `winpwn`. Do not call them directly.

`__run` executes an argument list, so no pipes, redirects or `&&` inside it. Anything needing those
has to go through `sh -c`, or `bash -c "set -o pipefail; ..."` when there is a pipe so the exit code
stays honest.

The banner single quotes instead of backslash escaping, so an `sh -c` line comes out as
`sh -c 'enum4linux-ng -A 10.10.10.5 2>/dev/null | head -60'` and pastes straight into a report. Keep
single quotes out of those strings or fish falls back to backslashes and the banner turns into soup.
`rpcclient -U ""` instead of `rpcclient -U ''` for that reason, `sh` reads both the same.

## Gotchas

Editing a function file does not reload it in your current shell. Fish autoloads once and caches. Use `funced NAME` to edit and reload in one go, or `functions -e NAME` to drop the cached copy if you edited the file directly.

An unset variable expands to nothing in fish. `ufzz $RHOSTS` with `RHOSTS` unset becomes bare `ufzz` and you get a usage line that looks like you typed it wrong.

`--min-rate 3000` in `look` trades accuracy for speed. Against rate limiting, a slow VPN hop or an IPS, packets get dropped and ports wont seem open even they are. If a target looks suspiciously empty, rerun without it before you believe the result.

Port 1 in `look` stage two only helps `-O` if it comes back closed. Nmap wants one open and one closed port to fingerprint properly. On a default drop host it reads as filtered and you get the incomplete fingerprint warning anyway.

`look -h` draws to 79 columns. A long NSE line or an OS warning can run past 120 and wrap, which breaks the left edge. Nothing is lost, it just stops looking like a table.

If a target's 404 page returns 200, every content discovery function lights up with thousands of false positives. Check what a garbage URL returns before you trust any scan output, and filter on size instead of status code.

`smbr`, `smbrd` and `snmpr` still `head` their output. enum4linux-ng at 60 lines, 80 in `smbrd`, snmpwalk at 100. Truncation leaves no marker, so a pasted transcript looks complete when it is not. They throw stderr away too, so a tool that half failed does not say why.

Exit codes in the footer are honest. Anything with a pipe runs under `bash -c "set -o pipefail; ..."`, otherwise the footer reports `head`'s status and a tool that is not even installed logs a green `exit 0`. `wketch` is the exception, its trailing `stty sane` always succeeds so it always logs 0. Fine for a listener, do not read into it.

## License

MIT. Only point these at things you are allowed to point them at.
