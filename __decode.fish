function __decode --description "peel layered base64/hex off a string, print each readable layer, do not call directly"
    # usage: __decode STRING
    # Prints the decoded result if the string is reversible obfuscation, nothing
    # if it is not. Walks at most 6 layers of base64 and hex, stopping at the
    # first layer that is already plain printable text (letters/digits/punct, no
    # control bytes). This is the Snookums case: base64 of base64 of a password.
    set -l s $argv[1]
    set -l C (set_color -o cyan); set -l N (set_color normal); set -l D (set_color brblack); set -l G (set_color green)
    set -l cur $s
    set -l chain
    for i in (seq 6)
        set -l next ""
        # base64: length multiple of 4, only the alphabet, decodes to printable
        if string match -qr '^[A-Za-z0-9+/]+={0,2}$' -- $cur; and test (math (string length -- $cur) % 4) -eq 0
            set -l d (printf '%s' $cur | base64 -d 2>/dev/null | string collect)
            if test -n "$d"; and __printable $d
                set next $d
                set -a chain "base64"
            end
        end
        # hex: even length, only hex digits, decodes to printable
        # hex -> text, but never for strings that are exactly a known hash
        # length (32 MD5, 40 SHA1, 64 SHA256): those are digests, not encodings
        set -l hl (string length -- $cur)
        if test -z "$next"; and string match -qr '^[0-9a-fA-F]+$' -- $cur; and test (math $hl % 2) -eq 0; and test $hl -ge 8; and not contains $hl 32 40 56 64 96 128
            set -l d
            if command -q xxd
                set d (printf '%s' $cur | xxd -r -p 2>/dev/null | string collect)
            else
                set d (printf '%s' $cur | perl -ne 's/([0-9a-fA-F]{2})/print chr hex $1/gie' 2>/dev/null | string collect)
            end
            if test -n "$d"; and __printable $d
                set next $d
                set -a chain "hex"
            end
        end
        test -z "$next"; and break
        set cur $next
        # stop if the decoded layer is plain text that would not decode further
        if not string match -qr '^[A-Za-z0-9+/]+={0,2}$' -- $cur
            break
        end
    end
    if test (count $chain) -gt 0; and test "$cur" != "$s"
        echo "$C── decodes ──$N"
        echo "  "(string join ' -> ' $chain)" ->  $G$cur$N"
        echo "  $D reversible obfuscation, not a hash. If it is a password, use it directly.$N"
        echo
        return 0
    end
    return 1
end

function __printable --description "true if the string is all printable text, do not call directly"
    # no control bytes except tab/newline, at least 2 chars
    set -l s $argv[1]
    test (string length -- $s) -ge 2; or return 1
    string match -qr '[^[:print:][:space:]]' -- $s; and return 1
    # must contain at least one letter or digit, not be pure punctuation noise
    string match -qr '[A-Za-z0-9]' -- $s; or return 1
    return 0
end
