# ERC-7730 v2 Clear Signing Library

Rust library for ERC-7730 v2 clear signing — decodes and formats contract calldata and EIP-712 messages for human-readable display.
UniFFI bindings (Kotlin + Swift) are implemented in the same crate via a stateless FFI wrapper.

## Workspace Layout

- Cargo workspace root at `/`
- Single crate: `crates/erc7730/`

## Build & Test

```sh
cargo build          # Build
cargo test           # Run default tests (27 unit tests)
cargo clippy         # Lint
cargo fmt --check    # Format check
```

UniFFI checks and binding generation:

```sh
cargo check -p erc7730 --features uniffi
cargo test -p erc7730 --features uniffi     # 34 unit tests
cargo clippy -p erc7730 --all-targets --features uniffi -- -D warnings
./scripts/generate_uniffi_bindings.sh
```

Generated binding outputs:
- `bindings/kotlin/uniffi/erc7730/erc7730.kt`
- `bindings/swift/erc7730.swift`
- `bindings/swift/erc7730FFI.h`
- `bindings/swift/erc7730FFI.modulemap`

Repository policy:
- `bindings/swift/` is kept in-repo for SPM consumption.
- `bindings/kotlin/` is generated locally and gitignored.

## Code Conventions

- Rust 2021 edition
- `thiserror` for error types, `serde` for serialization
- No `.unwrap()` in library code — use `Result` and `?`
- All public API re-exported from `lib.rs`
- Signature-based decoding: function signatures parsed from descriptor format keys, no ABI JSON needed

## Public API

Three entry points, all in `lib.rs`:
- `format(chain_id, to, calldata, value, source, tokens)` — high-level: resolves descriptor then formats
- `format_calldata(descriptor, chain_id, to, calldata, value, tokens)` — low-level: format with pre-resolved descriptor
- `format_typed_data(descriptor, data, tokens)` — EIP-712 typed data formatting

UniFFI FFI exports in `src/uniffi_compat/mod.rs`:
- `erc7730_format_calldata(descriptor_json, chain_id, to, calldata_hex, value_hex, tokens)`
- `erc7730_format_typed_data(descriptor_json, typed_data_json, tokens)`

## Key Modules

| Module | Key Types | Purpose |
|--------|-----------|---------|
| `engine.rs` | `DisplayModel`, `DisplayEntry`, `DisplayItem` | Main formatting pipeline |
| `decoder.rs` | `FunctionSignature`, `ParamType`, `ArgumentValue` | Calldata decoding from function signatures |
| `eip712.rs` | `TypedData`, `TypedDataDomain` | EIP-712 typed data support |
| `resolver.rs` | `DescriptorSource` (trait), `ResolvedDescriptor`, `StaticSource` | Descriptor resolution |
| `token.rs` | `TokenSource` (trait), `TokenMeta`, `TokenLookupKey` | Token metadata (CAIP-19 keys) |
| `address_book.rs` | `AddressBook` | Address → label resolution from descriptor metadata |
| `uniffi_compat/` | `TokenMetaInput`, `FfiError`, exported FFI functions | Stateless UniFFI wrapper layer |
| `types/` | `Descriptor`, `DescriptorContext`, `DescriptorDisplay`, `DisplayField`, `FieldFormat`, `VisibleRule` | Descriptor, display, context, metadata types |
| `error.rs` | `Error`, `DecodeError`, `ResolveError` | Unified error hierarchy |

## Pending

- **Phase 2**: `format_multi()` + `FieldFormat::Calldata` (nested calldata, Safe wallet support)
- **Phase 3**: `GitHubRegistrySource` + `EmbeddedSource` + descriptor validation
- **Phase 4**: Packaging/distribution for existing UniFFI bindings (Swift XCFramework/SPM + Kotlin AAR/Maven)
- **Phase 5**: Missing formatters (`nftName`, `duration`, `unit`), graceful degradation, CI pipeline
