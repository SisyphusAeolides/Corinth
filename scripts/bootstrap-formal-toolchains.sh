#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tools="${FORMAL_TOOLCHAIN_ROOT:-$root/target/formal/toolchains}"
downloads="$tools/downloads"
idris_root="$tools/Idris2-0.8.0"
agda_root="$tools/Agda-v2.8.0-linux"
mkdir -p "$downloads"

if command -v chezscheme >/dev/null 2>&1; then
    scheme="chezscheme"
elif command -v scheme >/dev/null 2>&1; then
    scheme="scheme"
else
    printf '%s\n' 'Idris bootstrap requires Chez Scheme.' >&2
    exit 1
fi

if [[ ! -x "$idris_root/build/exec/idris2" ]]; then
    archive="$downloads/idris2-0.8.0.tgz"
    curl --fail --location --retry 3 --output "$archive" \
        https://www.idris-lang.org/releases/idris2-0.8.0.tgz
    printf '%s  %s\n' \
        940a283cb66b0097cab0d24fe10341274fab75cb3af58dc715944d6ca7230665 \
        "$archive" | sha256sum --check --strict
    staging="$(mktemp -d "$tools/.idris.XXXXXXXX")"
    trap 'rm -rf -- "$staging"' EXIT
    tar -xzf "$archive" -C "$staging"
    make -C "$staging/Idris2-0.8.0" bootstrap SCHEME="$scheme"
    mv "$staging/Idris2-0.8.0" "$idris_root"
    rmdir "$staging"
    trap - EXIT
fi

if [[ ! -x "$agda_root/agda" ]]; then
    archive="$downloads/Agda-v2.8.0-linux.tar.xz"
    curl --fail --location --retry 3 --output "$archive" \
        https://github.com/agda/agda/releases/download/v2.8.0/Agda-v2.8.0-linux.tar.xz
    printf '%s  %s\n' \
        824081b8dcbe431289a50ac6bd83e451f390c51c3884ac7a8c4a5c0df2632faf \
        "$archive" | sha256sum --check --strict
    staging="$(mktemp -d "$tools/.agda.XXXXXXXX")"
    trap 'rm -rf -- "$staging"' EXIT
    tar -xJf "$archive" -C "$staging"
    mkdir "$agda_root"
    mv "$staging/agda" "$agda_root/agda"
    rmdir "$staging"
    trap - EXIT
fi

IDRIS2="$idris_root/build/exec/idris2" \
IDRIS2_PATH="$idris_root/libs/prelude/build/ttc:$idris_root/libs/base/build/ttc" \
AGDA="$agda_root/agda" \
    "$root/scripts/check-formal-models.sh"
