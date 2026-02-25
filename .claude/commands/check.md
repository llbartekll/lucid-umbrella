Run the full quality gate for the workspace:

1. `cargo fmt --check` — verify formatting
2. `cargo clippy -- -D warnings` — lint with warnings as errors
3. `cargo test` — run all tests

Report results for each step. If any step fails, stop and report the failure with details.
