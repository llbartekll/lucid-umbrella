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

## Public API

Three entry points, all in `lib.rs`:
- `format(chain_id, to, calldata, value, source, tokens)` — high-level: resolves descriptor then formats
- `format_calldata(descriptor, chain_id, to, calldata, value, tokens)` — low-level: format with pre-resolved descriptor
- `format_typed_data(descriptor, data, tokens)` — EIP-712 typed data formatting

## Key Modules

| Module | Key Types | Purpose |
|--------|-----------|---------|
| `engine.rs` | `DisplayModel`, `DisplayEntry`, `DisplayItem` | Main formatting pipeline |
| `decoder.rs` | `FunctionSignature`, `ParamType`, `ArgumentValue` | Calldata decoding from function signatures |
| `eip712.rs` | `TypedData`, `TypedDataDomain` | EIP-712 typed data support |
| `resolver.rs` | `DescriptorSource` (trait), `ResolvedDescriptor`, `StaticSource` | Descriptor resolution |
| `token.rs` | `TokenSource` (trait), `TokenMeta`, `TokenLookupKey` | Token metadata (CAIP-19 keys) |
| `address_book.rs` | `AddressBook` | Address → label resolution from descriptor metadata |
| `types/` | `Descriptor`, `DescriptorContext`, `DescriptorDisplay`, `DisplayField`, `FieldFormat`, `VisibleRule` | Descriptor, display, context, metadata types |
| `error.rs` | `Error`, `DecodeError`, `ResolveError` | Unified error hierarchy |

## Pending

- **Phase 2**: `format_multi()` + `FieldFormat::Calldata` (nested calldata, Safe wallet support)
- **Phase 3**: `GitHubRegistrySource` + `EmbeddedSource` + descriptor validation
- **Phase 4**: UniFFI bindings — Swift XCFramework/SPM + Kotlin AAR/Maven
- **Phase 5**: Missing formatters (`nftName`, `duration`, `unit`), graceful degradation, CI pipeline
