# Security Policy

## Overview

TarLens is a read-only tar archive analysis tool. It does **not** extract files, write to disk, or make network connections. This significantly reduces the attack surface.

## Security Features

### Verification Command

The `tarlens verify` command checks for:

- **Path traversal** — Entries containing `..` sequences that could escape the archive root during extraction
- **Absolute paths** — Entries with absolute paths (starting with `/`)
- **World-writable files** — Entries with mode 0777
- **Setuid/setgid bits** — Entries with special permission bits
- **Symlink safety** — Symlinks pointing to absolute paths or containing `..`
- **Checksum validation** — Verifies header integrity

### Safe by Design

- **No extraction** — TarLens only reads and analyzes, never writes files
- **No network access** — Fully offline tool
- **No shell execution** — No subprocess calls
- **Input validation** — All parsed fields are validated

## Reporting Issues

If you discover a security issue, please do NOT open a public issue. Instead, report it privately.

## Supported Versions

Only the latest release is supported with security updates.
