---
name: rust-check
description: Run the full Rust quality gate (fmt, clippy, test) and report results
user_invocable: true
---

# Rust Quality Gate

Run the following checks in sequence and report a summary:

1. **Format**: `cargo fmt --check`
2. **Lint**: `cargo clippy -- -D warnings`
3. **Test**: `cargo test`

For each step, report pass/fail. If a step fails, include the relevant error output. Summarize with an overall pass/fail status.
