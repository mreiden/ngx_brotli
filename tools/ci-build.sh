#!/bin/bash
# Build ngx_brotli against a PGP-verified nginx source tree.
#
#   tools/ci-build.sh [mode] [version]
#     mode   : system (default) | bundled
#              system  — link the system libbrotli found via pkg-config
#                        (the filter/config system-first path)
#              bundled — cmake-build deps/brotli into deps/brotli/c/../out
#                        first, then link it (the fallback path)
#     version: nginx version, e.g. 1.31.3. Omit to resolve the current
#              mainline release from nginx.org.
#
# Built tree persists at .build/nginx-<version>/objs/ so a CI job can run
# tests against the binary after the script exits. NO_CACHE=1 forces a
# from-scratch rebuild.
#
# nginx tarballs are verified via PGP against the signer keys VENDORED in
# tools/keys/ (committed to this repo) — never fetched from nginx.org at
# build time, so an origin compromise cannot substitute tarball, signature
# and keys together. Same provenance model as nginx-zstd-module's
# tools/ci-build.sh, which this is adapted from.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"

MODE="${1:-system}"
VERSION="${2:-}"

case "$MODE" in
    system | bundled) ;;
    *)
        echo "ERROR: unsupported mode: $MODE (want: system|bundled)" >&2
        exit 2
        ;;
esac

if [ -z "$VERSION" ]; then
    # Resolve the current mainline release; nginx.org only keeps the newest
    # mainline tarball, so a hardcoded version eventually 404s.
    VERSION="$(curl -fsSL https://nginx.org/en/download.html |
        grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+(?=\.tar\.gz)' |
        sort -V | tail -1 || true)"
    if [ -z "$VERSION" ]; then
        echo "ERROR: could not resolve mainline nginx version from nginx.org" >&2
        exit 1
    fi
fi

KEYRING_DIR="$SCRIPT_DIR/keys"
ROOT="${BUILD_ROOT:-$MODULE_DIR/.build}"
NO_CACHE="${NO_CACHE:-0}"

DIR="nginx-${VERSION}"
URL="https://nginx.org/download/${DIR}.tar.gz"
SRCDIR="$ROOT/$DIR"
TARBALL="$ROOT/${DIR}.tar.gz"

echo "== ngx_brotli build: mode=$MODE nginx=$VERSION tree=$SRCDIR"

mkdir -p "$ROOT"

if [ "$NO_CACHE" = "1" ]; then
    # deps/brotli/out too (CodeRabbit on the graft): the bundled-mode
    # static lib is exactly what you are trying to rebuild when you
    # reach for NO_CACHE=1 on a bundled link failure
    rm -rf "$SRCDIR" "$TARBALL" "$MODULE_DIR/deps/brotli/out"
fi

if [ ! -f "$TARBALL" ]; then
    wget -q -O "$TARBALL" "$URL"
fi

# Verification always runs, cache hit or fresh download — a cached tarball
# is exactly as untrusted as a fresh one until re-checked.
if [ ! -f "${TARBALL}.asc" ]; then
    wget -q "${URL}.asc" -O "${TARBALL}.asc"
fi

gnupghome="$(mktemp -d)"
trap 'rm -rf "$gnupghome"' EXIT
export GNUPGHOME="$gnupghome"
chmod 700 "$gnupghome"
shopt -s nullglob
keyfiles=("$KEYRING_DIR"/*.key)
shopt -u nullglob
if [ ${#keyfiles[@]} -eq 0 ]; then
    echo "ERROR: no vendored keys found in $KEYRING_DIR" >&2
    rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
    exit 1
fi
for keyfile in "${keyfiles[@]}"; do
    # LOUD on failure (CodeRabbit on the graft): a corrupt vendored key
    # is a supply-chain trust-root problem and must not die silently
    # under set -e with its diagnostics eaten
    gpg --import "$keyfile" || {
        echo "ERROR: importing $keyfile failed" >&2
        exit 1
    }
done

if gpg --quiet --verify "${TARBALL}.asc" "$TARBALL"; then
    echo "== PGP signature verified for ${DIR}.tar.gz"
else
    echo "ERROR: PGP signature verification FAILED for ${DIR}.tar.gz" >&2
    rm -rf "$gnupghome" "$TARBALL" "${TARBALL}.asc"
    exit 1
fi
rm -rf "$gnupghome"
unset GNUPGHOME

if [ ! -d "$SRCDIR" ]; then
    tar -xzf "$TARBALL" -C "$ROOT"
fi

if [ "$MODE" = "bundled" ]; then
    # The bundled path expects prebuilt static libs in deps/brotli/c/../out
    # (filter/config links -L<out> -lbrotlienc -lbrotlicommon).
    if [ ! -f "$MODULE_DIR/deps/brotli/c/include/brotli/encode.h" ]; then
        echo "ERROR: bundled mode needs the submodule:" \
             "git submodule update --init" >&2
        exit 1
    fi
    if [ ! -f "$MODULE_DIR/deps/brotli/out/libbrotlienc.a" ]; then
        cmake -S "$MODULE_DIR/deps/brotli" -B "$MODULE_DIR/deps/brotli/out" \
            -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
            -DBROTLI_BUILD_TOOLS=OFF > /dev/null
        cmake --build "$MODULE_DIR/deps/brotli/out" -j "$(nproc)" > /dev/null
    fi
    # Hide the system pkg-config module so filter/config's system-first
    # probe cannot short-circuit the path this mode exists to exercise.
    export PKG_CONFIG_LIBDIR=/nonexistent
else
    if ! pkg-config --exists libbrotlienc; then
        echo "ERROR: system mode needs libbrotli dev files" \
             "(pkg-config libbrotlienc)" >&2
        exit 1
    fi
    echo "== system libbrotlienc $(pkg-config --modversion libbrotlienc)"
fi

cd "$SRCDIR"

# NGX_BROTLI_SANITIZE=1 (CI only): build under ASan+UBSan, everything
# fatal. The zstd siblings' round-4 lesson: chain-state code deserves a
# sanitizer pass, and their job's first run caught real (upstream-nginx)
# UB. Both suites here run at warn log level, so nginx core's own
# debug-log UB sites (the nonnull-attribute family the in-flight nginx
# PRs #1671/#1672 and #1679-#1682 address) never execute — no check
# class needs disabling.
san_cc=""
san_ld=""
if [ "${NGX_BROTLI_SANITIZE:-0}" = "1" ]; then
    san_cc="--with-cc-opt=-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
    san_ld="--with-ld-opt=-fsanitize=address,undefined"
fi

./configure \
    --with-compat \
    --with-debug \
    --with-http_gzip_static_module \
    ${san_cc:+"$san_cc"} \
    ${san_ld:+"$san_ld"} \
    --add-module="$MODULE_DIR" > /dev/null

# quiet on success, the WHOLE tail on failure (CodeRabbit on the graft):
# tail -3 kept only the make trailer, never the diagnostic -- and this
# module links two different brotli sources across two build modes, so
# link errors are the expected failure class here
build_log="$(mktemp)"
if ! make -j"$(nproc)" > "$build_log" 2>&1; then
    tail -60 "$build_log"
    rm -f "$build_log"
    exit 1
fi
tail -3 "$build_log"
rm -f "$build_log"

test -f objs/nginx
./objs/nginx -V 2>&1
echo "BUILD_OK $SRCDIR/objs/nginx"
