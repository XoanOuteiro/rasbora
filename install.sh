#!/usr/bin/env bash
#
# rasbora installer
#
#   curl -fsSL https://raw.githubusercontent.com/XoanOuteiro/rasbora/main/install.sh | bash
#
# Copies every rasbora function into your fish functions directory, overwriting
# anything already there under the same name. Safe to run as many times as you
# like: it only touches files whose contents actually differ.
#
# Everything lives inside main() and main runs on the last line, so a download
# that gets cut off halfway can never execute half an install.

set -euo pipefail

RB_TMP=""
REPO="${RASBORA_REPO:-XoanOuteiro/rasbora}"
REF="${RASBORA_REF:-main}"

msg()  { printf '%s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[!] %s\n' "$*" >&2; exit 1; }

fetch_repo() {
    # prints the directory holding the .fish files
    local tmp url dir
    tmp="$1"
    url="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${REF}"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" | tar -xz -C "$tmp"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$url" | tar -xz -C "$tmp"
    else
        die "need curl or wget to download ${REPO}"
    fi

    dir="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    [ -n "$dir" ] || die "downloaded archive looked empty"
    printf '%s\n' "$dir"
}

main() {
    local dest src script_dir
    local new=0 upd=0 total=0

    case "${1:-}" in
        -h|--help)
            msg "usage: install.sh"
            msg "  RASBORA_REPO=user/repo   install from a different repo"
            msg "  RASBORA_REF=branch       install from a different branch"
            msg "  RASBORA_DEST=path        install somewhere other than the fish functions dir"
            return 0
            ;;
    esac

    dest="${RASBORA_DEST:-${XDG_CONFIG_HOME:-$HOME/.config}/fish/functions}"

    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        warn "running under sudo, so this installs for root, not ${SUDO_USER}"
        warn "these are user functions, they do not need root. ctrl-c and rerun without sudo."
    fi

    # Run from a clone? use the files sitting next to this script. Piped from
    # curl there is no such directory, so fall back to downloading.
    src=""
    if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if compgen -G "$script_dir/*.fish" >/dev/null 2>&1; then
            src="$script_dir"
            msg "[*] installing from $src"
        fi
    fi
    if [ -z "$src" ]; then
        msg "[*] fetching ${REPO}@${REF}"
        RB_TMP="$(mktemp -d)"
        # EXIT alone misses signals, which leaves the download dir behind
        trap 'if [ -n "${RB_TMP:-}" ]; then rm -rf "$RB_TMP"; fi' EXIT HUP INT TERM
        src="$(fetch_repo "$RB_TMP")"
    fi

    compgen -G "$src/*.fish" >/dev/null 2>&1 || die "no .fish files found in $src"

    mkdir -p "$dest"

    for f in "$src"/*.fish; do
        local base target
        base="$(basename "$f")"
        target="$dest/$base"
        total=$((total + 1))

        if [ -e "$target" ] || [ -L "$target" ]; then
            upd=$((upd + 1))
        else
            new=$((new + 1))
        fi

        rm -f "$target"
        cp "$f" "$target"
    done

    msg ""
    msg "[*] $total functions -> $dest"
    msg "    $new new, $upd overwritten"

    command -v fish >/dev/null 2>&1 || warn "fish is not on your PATH, so none of this will load yet"

    if [ "$upd" -gt 0 ]; then
        msg ""
        msg "    fish caches autoloaded functions. Open a new shell, or drop the old"
        msg "    copy with:  functions -e NAME"
    fi
}

main "$@"
