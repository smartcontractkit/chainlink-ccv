#!/usr/bin/env bash
# Refreshes the embedded EVM chain defaults in integration/pkg/accessors/evmconfig/chaindefaults:
# chainlink-evm's built-ins at the version go.mod links, and, given a chainlink branch, tag, or full
# commit SHA, CCIP's overrides from ccip/config/evm at that ref. Usage: sync-chain-defaults.sh [ref]
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
dest="$root/integration/pkg/accessors/evmconfig/chaindefaults"
readme="$dest/README.md"

# replace_dir <src> <dest>: make <dest> hold exactly the *.toml files of <src>.
replace_dir() {
    if ! compgen -G "$1/*.toml" >/dev/null; then
        echo "no *.toml files in $1" >&2
        exit 1
    fi
    rm -rf "$2"
    mkdir -p "$2"
    cp "$1"/*.toml "$2/"
    chmod 0644 "$2"/*.toml
}

# set_source <prefix> <value>: rewrite the README provenance line that starts with <prefix>.
set_source() {
    sed -i.bak "s|^$1: .*|$1: $2|" "$readme"
    rm -f "$readme.bak"
}

module="github.com/smartcontractkit/chainlink-evm"
read -r evm_dir evm_version < <(cd "$root" && go list -m -f '{{.Dir}} {{.Version}}' "$module")
replace_dir "$evm_dir/pkg/config/toml/defaults" "$dest/chainlink-evm"
set_source "chainlink-evm source" "$module@$evm_version"
echo "Synced chainlink-evm's defaults from $module@$evm_version"

if [ $# -gt 0 ] && [ -n "$1" ]; then
    repo="${CHAINLINK_REPO:-https://github.com/smartcontractkit/chainlink.git}"
    src="$(mktemp -d "${TMPDIR:-/tmp}/chain-defaults.XXXXXX")"
    trap 'rm -rf "$src"' EXIT
    git -C "$src" init -q
    git -C "$src" remote add origin "$repo"
    git -C "$src" fetch -q --depth 1 --filter=blob:none origin "$1"
    git -C "$src" sparse-checkout set --no-cone /ccip/config/evm/
    git -C "$src" checkout -q FETCH_HEAD
    commit="$(git -C "$src" rev-parse HEAD)"
    date="$(git -C "$src" show -s --format=%cs HEAD)"
    replace_dir "$src/ccip/config/evm" "$dest/ccip"
    set_source "CCIP source" "smartcontractkit/chainlink@${commit} (${date})"
    echo "Synced CCIP's defaults from smartcontractkit/chainlink@${commit}"
fi

echo "Now run: go test ./integration/pkg/accessors/evmconfig/ -run 'ChainDefaults|ChainlinkEVMDefaults'"
