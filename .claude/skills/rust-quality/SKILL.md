---
name: rust-quality
description: Write idiomatic Rust following this project's patterns and conventions
user_invocable: false
autoactivate_when: editing or creating Rust (.rs) files in this workspace
---

# Rust Quality Skill

## Goal

Write idiomatic Rust code that follows this project's established patterns. This library (ERC-7730 v2 clear signing) is the standalone version of yttrium's clear signing module, adapted for Rust 2021 edition with a sync-only, single-crate architecture.

## When to Activate

- Writing or modifying `.rs` files
- Adding new modules, error types, traits, or tests
- Implementing format renderers, decoders, or resolvers

## Code Style

### Imports

Standard `use` per item (not block `use { }` style). Group by:

1. External crates (`use serde::...`, `use num_bigint::...`)
2. Crate-internal (`use crate::...`)
3. Standard library (`use std::...`) — only when needed explicitly

```rust
use tiny_keccak::{Hasher, Keccak};

use crate::error::DecodeError;
```

### Error Handling

- Use `thiserror` with `#[derive(Debug, Error)]`
- Descriptive `#[error("...")]` messages with context
- Structured error variants with named fields for multi-value errors
- Use `#[from]` for automatic conversion from sub-errors
- **Never** use `.unwrap()` in library code — use `Result` + `?`
- Convert external errors with `.map_err(|e| ...)`

```rust
#[derive(Debug, Error)]
pub enum MyError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("not found: key={key}, context={context}")]
    NotFound { key: String, context: String },

    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),
}
```

### Traits & Pluggability

- Define traits for extensible behavior (`DescriptorSource`, `TokenSource`)
- Provide static/in-memory test implementations (`StaticSource`, `StaticTokenSource`)
- Implement `Default` for test sources via `new()` delegation
- Use `&dyn Trait` for trait object parameters (no async, no `Send + Sync` bounds needed)

```rust
pub trait MySource {
    fn lookup(&self, key: &str) -> Option<MyResult>;
}

pub struct StaticMySource {
    data: HashMap<String, MyResult>,
}

impl Default for StaticMySource {
    fn default() -> Self { Self::new() }
}
```

### Types & Data Structures

- `#[derive(Debug, Clone)]` on all public types
- `#[derive(Debug, Clone, Serialize, Deserialize)]` for types that roundtrip through JSON
- Use `#[serde(untagged)]` for flexible enums (like `DisplayField`, `VisibleRule`)
- Use `#[serde(rename_all = "camelCase")]` for JSON field mapping
- Recursive enums with `Box` for tree structures (`ParamType::Array(Box<ParamType>)`)
- Lifetime-bound context structs for pipeline state (`RenderContext<'a>`)

### Pipeline Pattern

Pass a mutable `RenderContext<'a>` through rendering pipelines to accumulate warnings and carry shared state:

```rust
struct RenderContext<'a> {
    descriptor: &'a Descriptor,
    decoded: &'a DecodedArguments,
    chain_id: u64,
    token_source: &'a dyn TokenSource,
    warnings: Vec<String>,
}
```

### Module Structure

- One module per concern (`decoder.rs`, `engine.rs`, `resolver.rs`)
- Types in `types/` subdirectory with submodules
- Public API re-exported from `lib.rs`
- Use `pub(crate)` for internal helpers shared between modules

### Tests

- Inline `#[cfg(test)] mod tests { ... }` at bottom of each module
- `use super::*;` in test modules
- Helper functions for building test data (JSON descriptors, calldata)
- Pattern matching in assertions with `if let ... { } else { panic!(...) }`
- Test both success and error paths

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_descriptor_json() -> &'static str {
        r#"{ ... }"#
    }

    #[test]
    fn test_my_feature() {
        let descriptor = Descriptor::from_json(test_descriptor_json()).unwrap();
        // ... build calldata ...
        let result = my_function(&descriptor).unwrap();
        assert_eq!(result.field, "expected");
    }
}
```

## Formatting & Linting

```sh
cargo fmt          # Stable rustfmt, default width (100)
cargo clippy -- -D warnings
cargo test
```

No `rustfmt.toml` overrides — use default settings.

## Validation Checklist

Before considering Rust code complete:

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes (all 26+ tests)
- [ ] No `.unwrap()` in library code (tests are fine)
- [ ] Error types use `thiserror`
- [ ] Public types have `Debug` and `Clone`
- [ ] New modules re-exported from `lib.rs` if public
- [ ] Tests cover both success and error paths

## Anti-Patterns

**Do NOT:**
- Use `.unwrap()` or `.expect()` in library code
- Use `eyre`, `anyhow`, or `Box<dyn Error>` — only `thiserror`
- Add `async` / `tokio` — this is a sync library
- Use block import style `use { foo, bar }` — use one `use` per item
- Add `Send + Sync` bounds on trait objects — not needed in sync code
- Create `rustfmt.toml` — use defaults
- Use `cargo +nightly fmt` — use stable `cargo fmt`
- Skip `#[derive(Debug, Clone)]` on public types
- Add UniFFI attributes yet — planned but not implemented

## Examples

See `REFERENCE.md` for advanced patterns specific to this project.
