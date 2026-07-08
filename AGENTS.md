# AGENTS.md

## Project: TarLens

TarLens is a tar archive analysis toolkit written in Rust. It parses tar binary formats from scratch (no external tar crate).

## Build & Test

```bash
cargo build          # Debug build
cargo build --release  # Release build
cargo test           # Run all tests
cargo fmt            # Format code
cargo clippy         # Lint
```

## Architecture

- `src/header.rs` — 512-byte tar header parsing (V7, USTAR, PAX, GNU formats)
- `src/reader.rs` — Streaming archive reader, PAX/GNU long name support
- `src/inspect.rs` — Raw header inspection with field breakdown table
- `src/verify.rs` — Checksum validation, path traversal, permission checks
- `src/diff.rs` — Archive comparison engine
- `src/stats.rs` — Archive statistics
- `src/output.rs` — Text and JSON output formatting
- `src/main.rs` — CLI (clap derive)

## Key Design Decisions

- No external tar crate — all binary parsing is hand-written
- Supports V7, USTAR, PAX (POSIX.1-2001), and GNU tar variants
- Base-256 size encoding for files >8GB (GNU extension)
- PAX extended headers for long file names and other metadata
- Both text and JSON output for all commands
- Read-only tool — no extraction, no path traversal risk

## Conventions

- Commit messages follow conventional commits (feat:, fix:, test:, etc.)
- All code is formatted with `cargo fmt`
- Tests cover happy path and error cases
- No hardcoded secrets or tokens
