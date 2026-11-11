#!/usr/bin/env bash
# Shared environment bootstrapper for local cluster runner scripts.

if [ -z "${REPO_ROOT:-}" ]; then
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

# Ensure 'go' is available in PATH, falling back to standard install directories
if ! command -v go >/dev/null 2>&1; then
    for dir in "/usr/local/go/bin" "${HOME}/go/bin"; do
        if [ -d "$dir" ] && [[ ":$PATH:" != *":$dir:"* ]]; then
            export PATH="${PATH}:${dir}"
        fi
    done
fi

if ! command -v go >/dev/null 2>&1; then
    echo "[-] Error: 'go' binary not found in PATH." >&2
    exit 1
fi

# Resolve IFRIT_CONFIG if not explicitly provided
if [ -z "${IFRIT_CONFIG:-}" ]; then
    _search_paths="${IFRIT_CONFIG_PATHS:-${REPO_ROOT}/config:${REPO_ROOT}:/var/tmp}"
    IFS=':' read -ra _dirs <<< "$_search_paths"
    for _dir in "${_dirs[@]}"; do
        [ -z "$_dir" ] && continue
        if [ -f "${_dir}/ifrit_config.yaml" ]; then
            export IFRIT_CONFIG="${_dir}/ifrit_config.yaml"
            break
        elif [ -f "${_dir}/ifrit_config.yml" ]; then
            export IFRIT_CONFIG="${_dir}/ifrit_config.yml"
            break
        fi
    done
    if [ -z "${IFRIT_CONFIG:-}" ] && [ -f "${REPO_ROOT}/config/ifrit_config.example.yaml" ]; then
        export IFRIT_CONFIG="${REPO_ROOT}/config/ifrit_config.example.yaml"
    fi
    unset _search_paths _dirs _dir
fi
