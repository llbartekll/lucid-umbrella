# ERC-7730 v2 Clear Signing Library

Rust library for ERC-7730 v2 clear signing — decodes and formats contract calldata and EIP-712 messages for human-readable display.

## Workspace Layout

- Cargo workspace root at `/`
- Single crate: `crates/erc7730/`

## Build & Test

```sh
cargo build          # Build
cargo test           # Run all tests (26 unit tests)
cargo clippy         # Lint
cargo fmt --check    # Format check
```

## Code Conventions

- Rust 2021 edition
- `thiserror` for error types, `serde` for serialization
- No `.unwrap()` in library code — use `Result` and `?`
- All public API re-exported from `lib.rs`
- Signature-based decoding: function signatures parsed from descriptor format keys, no ABI JSON needed

## Key Modules

| Module | Purpose |
|--------|---------|
| `engine.rs` | Main formatting pipeline |
| `decoder.rs` | Calldata decoding from function signatures |
| `eip712.rs` | EIP-712 typed data support |
| `resolver.rs` | Descriptor resolution (`DescriptorSource` trait) |
| `token.rs` | Token metadata (`TokenSource` trait) |
| `types/` | Descriptor, display, context, metadata types |

## Pending

- UniFFI bindings (Kotlin/Swift)
- Embedded descriptors
- GitHub API descriptor source
- CI pipeline
