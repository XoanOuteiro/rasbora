# servrec

Per-service enumeration menu for rasbora. `servrec <port|service>` prints the
commands worth running against that service, each tagged with what it's for.

## use
```
target 10.1.1.5          # sets $RHOST
servrec 445              # commands for port 445
servrec smb              # same, by service name
servrec snmp -v          # -v also shows the source of each line
```
Left column = purpose. $RHOST/$PORT are filled from your env.

## install
```
mkdir -p ~/.rasbora
cp servrec.db ~/.rasbora/
cp servrec.fish ~/.config/fish/functions/
```

## what's in it
231 commands across 45 services. Nothing hand-written: every line is
extracted verbatim from source, only placeholders normalized ($RHOST/$PORT)
and output-file plumbing stripped.

- AutoRecon  — github.com/Tib3rius/AutoRecon (default-plugins)
- HackTricks — github.com/HackTricks-wiki/hacktricks (network-services-pentesting)

Each row's origin is in column 4 (autorecon:<plugin> or hacktricks:<page>:<line>),
shown with `-v`. Credential-bruteforce plugins excluded on purpose.

## regenerate (when the sources update)
```
python3 extract_autorecon.py     # -> autorecon_rows.tsv
python3 extract_hacktricks.py    # -> hacktricks_rows.tsv
# then merge + tag (see build notes)
```

## not
A runner. It prints commands, it doesn't execute them. Read it, pick, run.
