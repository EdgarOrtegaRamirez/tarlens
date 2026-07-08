//! Header inspection — detailed raw header analysis.

use crate::header::{self, TarHeader, BLOCK_SIZE};
use crate::reader::RawBlock;

/// Inspect a specific entry's raw header block.
pub fn inspect_entry(
    blocks: &[RawBlock],
    entry_index: usize,
    show_hex: bool,
) -> Result<(), InspectError> {
    if entry_index >= blocks.len() {
        return Err(InspectError::EntryNotFound {
            index: entry_index,
            total: blocks.len(),
        });
    }

    let block = &blocks[entry_index];
    let parsed =
        TarHeader::parse(&block.block).map_err(|e| InspectError::HeaderParse(e.to_string()))?;

    print_header_details(&parsed, &block.block, block.offset);

    if show_hex {
        println!();
        print_hex_dump(&block.block);
    }

    Ok(())
}

fn print_header_details(header: &TarHeader, block: &[u8; BLOCK_SIZE], offset: u64) {
    println!("=== Header Inspection (entry at offset {offset}) ===");
    println!();
    println!("Field Breakdown:");
    println!("  Offset  | Field      | Bytes | Value");
    println!("  ------- | ---------- | ----- | -----");
    println!(
        "  {:>7} | name       |   100 | {}",
        0,
        truncate(&header.name, 60)
    );
    println!("  {:>7} | mode       |     8 | {:06o}", 100, header.mode);
    println!("  {:>7} | uid        |     8 | {}", 108, header.uid);
    println!("  {:>7} | gid        |     8 | {}", 116, header.gid);
    println!(
        "  {:>7} | size       |    12 | {} ({} bytes)",
        124,
        header.size,
        header.size_string()
    );
    println!(
        "  {:>7} | mtime      |    12 | {} ({})",
        136,
        header.mtime,
        header.mtime_string()
    );
    println!(
        "  {:>7} | checksum   |     8 | {} ({})",
        148,
        header.checksum,
        if header.checksum_valid {
            "VALID"
        } else {
            "INVALID"
        }
    );
    println!(
        "  {:>7} | typeflag   |     1 | '{}' ({})",
        156,
        header.entry_type.as_flag() as char,
        header.entry_type.description()
    );
    println!(
        "  {:>7} | linkname   |   100 | {}",
        157,
        if header.linkname.is_empty() {
            "(none)"
        } else {
            &header.linkname
        }
    );
    println!(
        "  {:>7} | magic      |     6 | {:?}",
        257,
        String::from_utf8_lossy(&block[257..263])
    );
    println!(
        "  {:>7} | version    |     2 | {:?}",
        263,
        String::from_utf8_lossy(&block[263..265])
    );
    println!(
        "  {:>7} | uname      |    32 | {}",
        265,
        if header.uname.is_empty() {
            "(none)"
        } else {
            &header.uname
        }
    );
    println!(
        "  {:>7} | gname      |    32 | {}",
        297,
        if header.gname.is_empty() {
            "(none)"
        } else {
            &header.gname
        }
    );
    println!("  {:>7} | devmajor   |     8 | {}", 329, header.devmajor);
    println!("  {:>7} | devminor   |     8 | {}", 337, header.devminor);
    println!(
        "  {:>7} | prefix     |   155 | {}",
        345,
        if header.prefix.is_empty() {
            "(none)"
        } else {
            &header.prefix
        }
    );

    println!();
    println!("Computed Values:");
    let computed = header::compute_checksum(block);
    println!("  Computed checksum: {computed}");
    println!("  Stored checksum:   {}", header.checksum);
    println!(
        "  Match: {}",
        if header.checksum_valid { "YES" } else { "NO" }
    );

    println!();
    println!("Format: {}", header.format);
    println!("Permissions: {}", header.permissions());

    if !header.pax_records.is_empty() {
        println!();
        println!("PAX Extended Records:");
        for record in &header.pax_records {
            println!("  {} = {}", record.key, truncate(&record.value, 60));
        }
    }
}

fn print_hex_dump(block: &[u8; BLOCK_SIZE]) {
    println!("Hex Dump (512 bytes):");
    println!();
    for (i, chunk) in block.chunks(16).enumerate() {
        let offset = i * 16;
        print!("  {:04x}  ", offset);
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{byte:02x} ");
        }
        // Pad if last row is short.
        for _ in chunk.len()..16 {
            print!("   ");
        }
        print!(" |");
        for byte in chunk {
            let c = if (32..=126).contains(byte) {
                *byte as char
            } else {
                '.'
            };
            print!("{c}");
        }
        println!("|");
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

/// Errors during inspection.
#[derive(Debug)]
pub enum InspectError {
    EntryNotFound { index: usize, total: usize },
    HeaderParse(String),
}

impl std::fmt::Display for InspectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InspectError::EntryNotFound { index, total } => {
                write!(
                    f,
                    "entry index {index} not found (archive has {total} entries)"
                )
            }
            InspectError::HeaderParse(msg) => write!(f, "header parse error: {msg}"),
        }
    }
}

impl std::error::Error for InspectError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::BLOCK_SIZE;

    fn make_test_block() -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block[..8].copy_from_slice(b"test.txt");
        let mode = format!("{:07o}", 0o644);
        block[100..100 + mode.len()].copy_from_slice(mode.as_bytes());
        let size = format!("{:011o}", 42u64);
        block[124..124 + size.len()].copy_from_slice(size.as_bytes());
        block[156] = b'0';
        block[257..262].copy_from_slice(b"ustar");
        block[262] = 0;
        block[263] = b'0';
        block[264] = b'0';
        let checksum = header::compute_checksum(&block);
        let cs = format!("{:07o}", checksum);
        block[148..148 + cs.len()].copy_from_slice(cs.as_bytes());
        block
    }

    #[test]
    fn test_inspect_entry_not_found() {
        let blocks = vec![];
        let result = inspect_entry(&blocks, 0, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_inspect_valid_entry() {
        let block = make_test_block();
        let blocks = vec![RawBlock {
            block,
            offset: 0,
            is_header: true,
        }];
        let result = inspect_entry(&blocks, 0, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inspect_with_hex() {
        let block = make_test_block();
        let blocks = vec![RawBlock {
            block,
            offset: 0,
            is_header: true,
        }];
        let result = inspect_entry(&blocks, 0, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 8), "hello...");
    }
}
