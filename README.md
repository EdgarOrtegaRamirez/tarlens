# TarLens

**Tar archive analysis toolkit — inspect, verify, diff, and analyze tar archives with hand-written binary format parsing.**

TarLens is a standalone CLI tool for analyzing tar archives without extracting them. It parses the tar binary format from scratch (no external tar library), supporting all major variants: V7 (original), USTAR (POSIX), PAX (POSIX.1-2001), and GNU.

## Features

- **List** — View archive contents in short or long (ls-style) format
- **Inspect** — Detailed raw header breakdown with field offsets, byte counts, and hex dump
- **Verify** — Checksum validation, path traversal detection, suspicious permission flags, symlink safety
- **Diff** — Compare two archives and show added, removed, modified, and type-changed entries
- **Stats** — Archive statistics: file counts, size distribution, format detection, top largest files
- **Info** — Quick format detection and entry summary
- **JSON output** — All commands support `--format json` for machine-readable output

## Supported Tar Formats

| Format | Magic Field | Description |
|--------|-------------|-------------|
| V7 | (none) | Original Unix V7 tar |
| USTAR | `ustar\0` | POSIX.1-1988 (POSIX.1-1988) |
| GNU | `ustar \0` | GNU tar extensions (long names, base-256 sizes) |
| PAX | `ustar\0` + PAX headers | POSIX.1-2001 extended headers |

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
git clone https://github.com/EdgarOrtegaRamirez/tarlens.git
cd tarlens
cargo build --release
# Binary at target/release/tarlens
```

## Quick Start

```bash
# List archive contents
tarlens list archive.tar

# Long format (ls-style)
tarlens list archive.tar --long

# Filter by type
tarlens list archive.tar --type file
tarlens list archive.tar --type dir
tarlens list archive.tar --type link

# JSON output
tarlens list archive.tar --format json

# Inspect raw header of first entry
tarlens inspect archive.tar

# Inspect specific entry (0-indexed) with hex dump
tarlens inspect archive.tar --entry 2 --hex

# Verify archive integrity
tarlens verify archive.tar

# Diff two archives
tarlens diff old.tar new.tar

# Show statistics
tarlens stats archive.tar

# Quick format detection
tarlens info archive.tar
```

## Verification Checks

The `verify` command performs the following integrity and security checks:

- **Checksum validation** — Verifies each entry's stored checksum matches the computed checksum
- **Path traversal** — Flags entries containing `..` (potential directory escape)
- **Absolute paths** — Warns about entries with absolute paths (starting with `/`)
- **World-writable** — Flags entries with mode 0777
- **Setuid/setgid** — Reports entries with special permission bits
- **Symlink safety** — Checks symlinks for absolute targets or parent traversal
- **Content size** — Verifies content length matches header size field
- **Duplicate entries** — Warns about duplicate entry names

## Architecture

TarLens is built with a modular architecture:

```
src/
├── main.rs     — CLI entry point (clap derive)
├── header.rs   — 512-byte tar header parsing (V7/USTAR/PAX/GNU)
├── reader.rs   — Streaming archive reader with PAX/GNU extension support
├── inspect.rs  — Raw header inspection with field breakdown
├── verify.rs   — Integrity and security verification
├── diff.rs     — Archive comparison engine
├── stats.rs    — Archive statistics computation
└── output.rs   — Text and JSON output formatting
```

### Binary Format Parsing

The tar header is a 512-byte block with the following layout:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 100 | File name (null-terminated) |
| 100 | 8 | File mode (octal) |
| 108 | 8 | Owner UID (octal) |
| 116 | 8 | Group GID (octal) |
| 124 | 12 | File size (octal or base-256) |
| 136 | 12 | Modification time (octal) |
| 148 | 8 | Header checksum (octal) |
| 156 | 1 | Type flag |
| 157 | 100 | Link name (for symlinks/hardlinks) |
| 257 | 6 | Magic field ("ustar\0" or "ustar ") |
| 263 | 2 | Version ("00") |
| 265 | 32 | Owner name |
| 297 | 32 | Group name |
| 329 | 8 | Device major |
| 337 | 8 | Device minor |
| 345 | 155 | Prefix (for long paths in USTAR) |

All parsing is done from raw bytes — no external tar crate is used.

## Security

- No extraction functionality — TarLens is read-only, so no path traversal during extraction
- Verification command flags potential security issues in archives
- No network access required
- No external dependencies beyond clap (CLI) and tempfile (dev only)

See [SECURITY.md](SECURITY.md) for more details.

## License

MIT
