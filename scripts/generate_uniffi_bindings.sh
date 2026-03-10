#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$ROOT_DIR/target/debug"
KOTLIN_OUT="$ROOT_DIR/bindings/kotlin"
SWIFT_OUT="$ROOT_DIR/bindings/swift"

case "$(uname -s)" in
    Darwin)
        LIB_PATH="$TARGET_DIR/liberc7730.dylib"
        ;;
    Linux)
        LIB_PATH="$TARGET_DIR/liberc7730.so"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        LIB_PATH="$TARGET_DIR/erc7730.dll"
        ;;
    *)
        echo "Unsupported host OS: $(uname -s)" >&2
        exit 1
        ;;
esac

mkdir -p "$KOTLIN_OUT" "$SWIFT_OUT"

echo "Building erc7730 with UniFFI feature..."
cargo build -p erc7730 --features uniffi,github-registry

if [[ ! -f "$LIB_PATH" ]]; then
    echo "Expected library not found at: $LIB_PATH" >&2
    echo "Available candidate files:" >&2
    find "$TARGET_DIR" -maxdepth 1 -name '*erc7730*' -print >&2 || true
    exit 1
fi

echo "Generating Kotlin bindings to $KOTLIN_OUT"
cargo run -p erc7730 --features uniffi,github-registry --bin uniffi-bindgen -- generate --library "$LIB_PATH" --language kotlin --out-dir "$KOTLIN_OUT"

echo "Generating Swift bindings to $SWIFT_OUT"
cargo run -p erc7730 --features uniffi,github-registry --bin uniffi-bindgen -- generate --library "$LIB_PATH" --language swift --out-dir "$SWIFT_OUT"

echo "Done. Bindings generated in $ROOT_DIR/bindings"
