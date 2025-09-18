#!/bin/sh
# Disassemble the output
set -eu

cd "$(dirname -- "$0")"

if [ "$#" -ge 1 ] && [ "$1" = "-g" ] ; then
    # Compress with GZip
    TARGET_DIR=/tmp/ocinception-target/target-disasm-32-gzip
    cargo +nightly build --release \
        --target i686-unknown-none.json \
        --target-dir "$TARGET_DIR" \
        --features gzip \
        -Zbuild-std=core,alloc
else
    # Compress with Zstandard
    TARGET_DIR=/tmp/ocinception-target/target-disasm-32-zstd
    cargo +nightly build --release \
        --target i686-unknown-none.json \
        --target-dir "$TARGET_DIR" \
        -Zbuild-std=core
fi

objdump -rd -Mintel "$TARGET_DIR/i686-unknown-none/release/ocinception_3"
