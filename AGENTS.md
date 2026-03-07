# ERC-7730 v2 Clear Signing Library

Guidance for GPT/Codex-style agents working in this repository.

## Project Summary

Rust library for ERC-7730 v2 clear signing. It decodes and formats contract calldata and EIP-712 messages for human-readable display.
The crate also provides UniFFI bindings (Kotlin + Swift) through a stateless FFI surface.

## Workspace Layout

- Cargo workspace root at `/`
- Single crate: `crates/erc7730/`

## Build And Test

Run these from the workspace root:

```sh
cargo build
cargo test
cargo clippy
cargo fmt --check
```

UniFFI-specific checks:

```sh
cargo check -p erc7730 --features uniffi
cargo test -p erc7730 --features uniffi
cargo clippy -p erc7730 --all-targets --features uniffi -- -D warnings
./scripts/generate_uniffi_bindings.sh
```

Current baseline from `CLAUDE.md`:
- 27 unit tests (default build)
- 34 unit tests (`--features uniffi`)

## Code Conventions

- Rust 2021 edition
- Use `thiserror` for error types and `serde` for serialization
- Do not use `.unwrap()` in library code; propagate errors with `Result` and `?`
- Re-export all public API from `lib.rs`
- Decoding is signature-based: parse function signatures from descriptor format keys, without ABI JSON

## Public API

The three main entry points are re-exported from `lib.rs`:

- `format(chain_id, to, calldata, value, source, tokens)` for high-level formatting with descriptor resolution
- `format_calldata(descriptor, chain_id, to, calldata, value, tokens)` for formatting with a pre-resolved descriptor
- `format_typed_data(descriptor, data, tokens)` for EIP-712 typed data formatting

UniFFI FFI exports (feature-gated module `uniffi_compat`):

- `erc7730_format_calldata(descriptor_json, chain_id, to, calldata_hex, value_hex, tokens)`
- `erc7730_format_typed_data(descriptor_json, typed_data_json, tokens)`

FFI API is intentionally stateless and JSON/hex-based.

## Key Modules

| Module | Key Types | Purpose |
|--------|-----------|---------|
| `engine.rs` | `DisplayModel`, `DisplayEntry`, `DisplayItem` | Main formatting pipeline |
| `decoder.rs` | `FunctionSignature`, `ParamType`, `ArgumentValue` | Calldata decoding from function signatures |
| `eip712.rs` | `TypedData`, `TypedDataDomain` | EIP-712 typed data support |
| `resolver.rs` | `DescriptorSource`, `ResolvedDescriptor`, `StaticSource` | Descriptor resolution |
| `token.rs` | `TokenSource`, `TokenMeta`, `TokenLookupKey` | Token metadata using CAIP-19 keys |
| `address_book.rs` | `AddressBook` | Address-to-label resolution from descriptor metadata |
| `uniffi_compat/` | `TokenMetaInput`, `FfiError`, UniFFI exports | Stateless FFI wrapper for Kotlin/Swift |
| `types/` | `Descriptor`, `DescriptorContext`, `DescriptorDisplay`, `DisplayField`, `FieldFormat`, `VisibleRule` | Descriptor, display, context, and metadata types |
| `error.rs` | `Error`, `DecodeError`, `ResolveError` | Unified error hierarchy |

## UniFFI Artifacts

Generated bindings are written to:

- `bindings/kotlin/`
- `bindings/swift/`

## Working Expectations For Agents

- Prefer minimal, targeted changes over broad refactors
- Preserve existing public API unless the task explicitly requires API changes
- Add or update tests when changing formatting, decoding, or resolution behavior
- Run relevant Rust checks after changes when possible
- Keep docs and module exports aligned with implementation changes

## Pending Roadmap

- Phase 2: `format_multi()` plus `FieldFormat::Calldata` for nested calldata and Safe wallet support
- Phase 3: `GitHubRegistrySource`, `EmbeddedSource`, and descriptor validation
- Phase 4: Packaging and distribution for existing UniFFI bindings (Swift XCFramework/SPM and Kotlin AAR/Maven)
- Phase 5: Missing formatters (`nftName`, `duration`, `unit`), graceful degradation, and CI pipeline
