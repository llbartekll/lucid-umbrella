# Evaluations

Test prompts to verify the rust-quality skill activates and guides correctly.

## Test 1: New Error Type

**Prompt:** "Add a `ValidationError` enum to `error.rs` with variants for missing fields and invalid ranges."

**Expected behavior:**
- Uses `thiserror` with `#[derive(Debug, Error)]`
- Descriptive `#[error("...")]` messages
- Structured variants with named fields where appropriate
- Adds `#[from]` conversion in the parent `Error` enum
- Does NOT use `eyre`, `anyhow`, or `Box<dyn Error>`
- Does NOT add UniFFI derives

## Test 2: New Trait + Implementation

**Prompt:** "Add a `ChainSource` trait that looks up chain metadata by chain ID, with a static test implementation."

**Expected behavior:**
- Defines `pub trait ChainSource` with sync methods
- Creates `StaticChainSource` with `HashMap` storage
- Implements `new()` + `Default` delegation
- Uses `&dyn ChainSource` in function signatures (no `Send + Sync`)
- Follows the `DescriptorSource` / `TokenSource` pattern exactly
- Inline `#[cfg(test)]` tests

## Test 3: New Format Renderer

**Prompt:** "Implement the `Duration` format renderer in `engine.rs` that converts seconds to human-readable duration."

**Expected behavior:**
- Adds match arm in `format_value()` dispatch
- Implements `format_duration()` function
- Extracts `BigUint` from `ArgumentValue::Uint`
- Returns `Result<String, Error>` (not `String`)
- Falls back to `format_raw()` for non-uint values
- Adds test in `engine::tests`
- Removes `Duration` from the "not yet implemented" catch-all

## Test 4: Modify Existing Module

**Prompt:** "Add a `resolve_by_name` method to `StaticSource` that looks up descriptors by contract name."

**Expected behavior:**
- Preserves existing import style (one `use` per item)
- Follows existing method patterns in `StaticSource`
- Returns `Result<ResolvedDescriptor, ResolveError>`
- Adds test in existing `mod tests`
- Does NOT reorganize imports or add unrelated changes

## Test 5: Non-Activation (Documentation)

**Prompt:** "Update the README with installation instructions."

**Expected behavior:**
- Skill does NOT activate (not editing Rust code)
- No Rust-specific guidance applied

## Test 6: Non-Activation (Non-Rust File)

**Prompt:** "Add a GitHub Actions CI workflow."

**Expected behavior:**
- Skill does NOT activate for YAML files
- May reference `cargo fmt`, `cargo clippy`, `cargo test` commands but doesn't apply Rust code style rules

## Test 7: Test Writing

**Prompt:** "Add a test for decoding calldata with a tuple parameter."

**Expected behavior:**
- Uses `#[test]` in existing `mod tests`
- Uses `super::*` imports
- Builds test data with helper functions
- Pattern matches on `ArgumentValue::Tuple`
- Uses `if let ... { assert!(...) } else { panic!(...) }` pattern
- `.unwrap()` is fine in tests
