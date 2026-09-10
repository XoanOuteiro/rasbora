function __winpwn_ghurl --description "resolve a versioned github release asset to a url"
    set -l repo $argv[1]
    set -l pat $argv[2]        # perl regex matched against the asset url

    curl -sS --fail --max-time 45 "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
        | grep -oP '"browser_download_url":\s*"\K[^"]+' \
        | grep -P -- $pat \
        | head -1
end
