#!/usr/bin/env bash
# Test several features and compute the score
set -eu

cd "$(dirname -- "$0")"

ALL_FEATURES=(
    ''
    'tar-binary-size'
    'never-use-arg-as-manifest-digest'
    'merge-config-index'
    'gz'
    'gz,tar-binary-size'
    'gz,never-use-arg-as-manifest-digest'
    'gz,merge-config-index'
    'zstd'
    'zstd,tar-binary-size'
    'zstd,never-use-arg-as-manifest-digest'
    'zstd,merge-config-index'
)

TEST_ARG=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

for FEATURES in "${ALL_FEATURES[@]}" ; do
    TARGET_DIR="target/target-${FEATURES}"
    mkdir -p "$TARGET_DIR"
    cargo run --quiet --release \
        --target x86_64-unknown-linux-musl \
        --target-dir "$TARGET_DIR" \
        --features "$FEATURES" \
        > "$TARGET_DIR/ocinception_1.tar"
    cargo run --quiet --release \
        --target x86_64-unknown-linux-musl \
        --target-dir "$TARGET_DIR" \
        --features "$FEATURES" \
        -- "$TEST_ARG" > "$TARGET_DIR/final_ocinception_1.tar"
    SCORE="$(stat --printf=%s "$TARGET_DIR/final_ocinception_1.tar")"
    printf "%6d %s\n" "$SCORE" "$FEATURES"
done
