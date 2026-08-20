function __run --description "echo a command in a banner, then execute it"
    set -l pretty (string escape -n -- $argv)
    set -l start_iso (date '+%Y-%m-%dT%H:%M:%S%:z')   # 2026-08-20T18:31:07+02:00
    set -l start_utc (date -u '+%Y-%m-%dT%H:%M:%SZ')
    set -l start_epoch (date +%s)

    # log line: ISO local | UTC | user@host | cwd | command
    echo "$start_iso | $start_utc | "(id -un)"@"(hostname)" | "(pwd)" | $pretty" >> ~/.cmdlog

    set_color -o cyan
    echo "┌─[$start_iso]  ($start_utc)"
    echo "│ $pretty"
    echo "└"(string repeat -n 70 '─')
    set_color normal

    command $argv
    set -l rc $status

    set -l end_iso (date '+%Y-%m-%dT%H:%M:%S%:z')
    set -l elapsed (math (date +%s) - $start_epoch)

    set_color -o (test $rc -eq 0; and echo cyan; or echo red)
    echo "└─[$end_iso]  elapsed "$elapsed"s  exit $rc"
    set_color normal

    echo "$end_iso | finished in "$elapsed"s, exit $rc" >> ~/.cmdlog
    return $rc
end
