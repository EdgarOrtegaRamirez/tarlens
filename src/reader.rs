//! Archive reader — streaming tar archive parsing.
//!
//! Reads tar archives entry by entry, handling PAX extended headers,
//! GNU long name/long link extensions, and content extraction.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::header::{self, EntryType, PaxRecord, TarFormat, TarHeader, BLOCK_SIZE};

/// An entry from a tar archive.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TarEntry {
    pub header: TarHeader,
    /// Raw content data (for regular files).
    pub content: Vec<u8>,
    /// Raw 512-byte header block (for inspection).
    pub raw_block: [u8; BLOCK_SIZE],
    /// Offset of the header block in the file.
    pub offset: u64,
}

/// Read a tar archive and return all entries.
pub fn read_archive(path: &Path) -> Result<Vec<TarEntry>, ReaderError> {
    let file = File::open(path).map_err(|e| ReaderError::Io(e.to_string()))?;
    let mut reader = BufReader::new(file);
    read_archive_from(&mut reader)
}

/// Read a tar archive from any Read+Seek source.
pub fn read_archive_from<R: Read + Seek>(reader: &mut R) -> Result<Vec<TarEntry>, ReaderError> {
    let mut entries = Vec::new();
    let mut pax_records: Vec<PaxRecord> = Vec::new();
    let mut gnu_long_name: Option<String> = None;
    let mut gnu_long_link: Option<String> = None;

    loop {
        // Read the 512-byte header block.
        let offset = reader
            .stream_position()
            .map_err(|e| ReaderError::Io(e.to_string()))?;
        let mut block = [0u8; BLOCK_SIZE];
        let n = reader
            .read(&mut block)
            .map_err(|e| ReaderError::Io(e.to_string()))?;

        if n == 0 {
            // End of file.
            break;
        }

        if n < BLOCK_SIZE {
            return Err(ReaderError::TruncatedHeader);
        }

        // Parse the header.
        let header_result = header::TarHeader::parse(&block);
        let parsed = match header_result {
            Ok(h) => h,
            Err(header::HeaderError::EndOfArchive) => {
                // Check for second zero block (end of archive marker).
                let mut block2 = [0u8; BLOCK_SIZE];
                let n2 = reader
                    .read(&mut block2)
                    .map_err(|e| ReaderError::Io(e.to_string()))?;
                if n2 == 0 || block2.iter().all(|&b| b == 0) {
                    break;
                } else {
                    // Only one zero block — unusual but treat as end.
                    break;
                }
            }
            Err(e) => return Err(ReaderError::HeaderParse(e.to_string())),
        };

        // Handle metadata entries (PAX headers, GNU long name/link).
        match parsed.entry_type {
            EntryType::PaxHeader | EntryType::PaxGlobal => {
                // Read PAX data.
                let pax_data = read_content(reader, parsed.size)?;
                let records = header::parse_pax_records(&pax_data)
                    .map_err(|e| ReaderError::PaxParse(e.to_string()))?;
                if parsed.entry_type == EntryType::PaxGlobal {
                    // Global PAX records apply to all subsequent entries.
                    pax_records.extend(records);
                } else {
                    // Per-entry PAX records apply to the next entry.
                    pax_records.extend(records);
                }
                // Store as a metadata entry (no content in the output).
                entries.push(TarEntry {
                    header: parsed,
                    content: pax_data,
                    raw_block: block,
                    offset,
                });
            }
            EntryType::GnuLongName => {
                let data = read_content(reader, parsed.size)?;
                gnu_long_name = Some(
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string(),
                );
                entries.push(TarEntry {
                    header: parsed,
                    content: data,
                    raw_block: block,
                    offset,
                });
            }
            EntryType::GnuLongLink => {
                let data = read_content(reader, parsed.size)?;
                gnu_long_link = Some(
                    String::from_utf8_lossy(&data)
                        .trim_end_matches('\0')
                        .to_string(),
                );
                entries.push(TarEntry {
                    header: parsed,
                    content: data,
                    raw_block: block,
                    offset,
                });
            }
            _ => {
                // Regular entry — apply PAX records and GNU long name/link.
                let mut header = parsed;

                if !pax_records.is_empty() {
                    header.apply_pax(&pax_records);
                    pax_records.clear();
                }

                if let Some(name) = gnu_long_name.take() {
                    header.name = name;
                    header.format = TarFormat::Gnu;
                }

                if let Some(link) = gnu_long_link.take() {
                    header.linkname = link;
                    header.format = TarFormat::Gnu;
                }

                // Read content for regular files.
                let content = if header.entry_type.is_regular() && header.size > 0 {
                    read_content(reader, header.size)?
                } else {
                    Vec::new()
                };

                entries.push(TarEntry {
                    header,
                    content,
                    raw_block: block,
                    offset,
                });
            }
        }
    }

    Ok(entries)
}

/// Read content data from the reader, skipping padding to the next block boundary.
fn read_content<R: Read + Seek>(reader: &mut R, size: u64) -> Result<Vec<u8>, ReaderError> {
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; size as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|_| ReaderError::TruncatedContent { expected: size })?;

    // Skip padding to next block boundary.
    let padding = (BLOCK_SIZE - (size as usize % BLOCK_SIZE)) % BLOCK_SIZE;
    if padding > 0 {
        let mut pad_buf = vec![0u8; padding];
        reader
            .read_exact(&mut pad_buf)
            .map_err(|_| ReaderError::TruncatedContent { expected: size })?;
    }

    Ok(buf)
}

/// Read raw 512-byte blocks from the archive (for header inspection).
pub fn read_raw_blocks(path: &Path) -> Result<Vec<RawBlock>, ReaderError> {
    let file = File::open(path).map_err(|e| ReaderError::Io(e.to_string()))?;
    let mut reader = BufReader::new(file);
    let mut blocks = Vec::new();

    loop {
        let offset = reader
            .stream_position()
            .map_err(|e| ReaderError::Io(e.to_string()))?;
        let mut block = [0u8; BLOCK_SIZE];
        let n = reader
            .read(&mut block)
            .map_err(|e| ReaderError::Io(e.to_string()))?;

        if n == 0 {
            break;
        }
        if n < BLOCK_SIZE {
            break;
        }

        // Check for end of archive.
        if block.iter().all(|&b| b == 0) {
            break;
        }

        // Try to parse the header to get the size for skipping content.
        let raw_block = RawBlock {
            block,
            offset,
            is_header: true,
        };

        if let Ok(h) = header::TarHeader::parse(&block) {
            blocks.push(raw_block);

            // Skip content data + padding.
            if h.size > 0 && !h.entry_type.is_metadata() {
                let total = h.size
                    + ((BLOCK_SIZE as u64 - (h.size % BLOCK_SIZE as u64)) % BLOCK_SIZE as u64);
                reader
                    .seek(SeekFrom::Current(total as i64))
                    .map_err(|e| ReaderError::Io(e.to_string()))?;
            } else if h.entry_type.is_metadata() {
                // For metadata entries, skip their content too.
                let total = h.size
                    + ((BLOCK_SIZE as u64 - (h.size % BLOCK_SIZE as u64)) % BLOCK_SIZE as u64);
                if total > 0 {
                    reader
                        .seek(SeekFrom::Current(total as i64))
                        .map_err(|e| ReaderError::Io(e.to_string()))?;
                }
            }
        } else {
            break;
        }
    }

    Ok(blocks)
}

/// A raw 512-byte block from the archive.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RawBlock {
    pub block: [u8; BLOCK_SIZE],
    pub offset: u64,
    pub is_header: bool,
}

/// Errors that can occur during archive reading.
#[derive(Debug)]
pub enum ReaderError {
    Io(String),
    TruncatedHeader,
    TruncatedContent { expected: u64 },
    HeaderParse(String),
    PaxParse(String),
}

impl std::fmt::Display for ReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReaderError::Io(msg) => write!(f, "I/O error: {msg}"),
            ReaderError::TruncatedHeader => write!(f, "truncated header (less than 512 bytes)"),
            ReaderError::TruncatedContent { expected } => {
                write!(f, "truncated content (expected {expected} bytes)")
            }
            ReaderError::HeaderParse(msg) => write!(f, "header parse error: {msg}"),
            ReaderError::PaxParse(msg) => write!(f, "PAX parse error: {msg}"),
        }
    }
}

impl std::error::Error for ReaderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::BLOCK_SIZE;
    use std::io::Cursor;

    fn make_header_block(name: &str, size: u64, typeflag: u8) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(100);
        block[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // Mode
        let mode = format!("{:07o}", 0o644);
        block[100..100 + mode.len()].copy_from_slice(mode.as_bytes());
        block[100 + mode.len()] = 0;

        // UID
        let uid = format!("{:07o}", 1000);
        block[108..108 + uid.len()].copy_from_slice(uid.as_bytes());
        block[108 + uid.len()] = 0;

        // GID
        let gid = format!("{:07o}", 1000);
        block[116..116 + gid.len()].copy_from_slice(gid.as_bytes());
        block[116 + gid.len()] = 0;

        // Size
        let size_s = format!("{:011o}", size);
        block[124..124 + size_s.len()].copy_from_slice(size_s.as_bytes());
        block[124 + size_s.len()] = 0;

        // Mtime
        let mtime = format!("{:011o}", 1718000000u64);
        block[136..136 + mtime.len()].copy_from_slice(mtime.as_bytes());
        block[136 + mtime.len()] = 0;

        // Type flag
        block[156] = typeflag;

        // Magic — USTAR
        block[257..262].copy_from_slice(b"ustar");
        block[262] = 0;
        block[263] = b'0';
        block[264] = b'0';

        // Checksum
        let checksum = header::compute_checksum(&block);
        let cs = format!("{:07o}", checksum);
        block[148..148 + cs.len()].copy_from_slice(cs.as_bytes());
        block[148 + cs.len()] = 0;

        block
    }

    fn make_archive(entries: &[(&str, &[u8], u8)]) -> Vec<u8> {
        let mut data = Vec::new();
        for (name, content, typeflag) in entries {
            let block = make_header_block(name, content.len() as u64, *typeflag);
            data.extend_from_slice(&block);
            if !content.is_empty() {
                data.extend_from_slice(content);
                let padding = (BLOCK_SIZE - (content.len() % BLOCK_SIZE)) % BLOCK_SIZE;
                data.extend(std::iter::repeat_n(0u8, padding));
            }
        }
        // End of archive: two zero blocks.
        data.extend(std::iter::repeat_n(0u8, BLOCK_SIZE * 2));
        data
    }

    #[test]
    fn test_read_empty_archive() {
        let data = vec![0u8; BLOCK_SIZE * 2];
        let mut cursor = Cursor::new(data);
        let entries = read_archive_from(&mut cursor).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_read_single_file() {
        let content = b"Hello, World!";
        let data = make_archive(&[("test.txt", content, b'0')]);
        let mut cursor = Cursor::new(data);
        let entries = read_archive_from(&mut cursor).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "test.txt");
        assert_eq!(entries[0].header.size, 13);
        assert_eq!(entries[0].content, content);
        assert!(entries[0].header.entry_type.is_regular());
    }

    #[test]
    fn test_read_multiple_files() {
        let data = make_archive(&[
            ("file1.txt", b"content1", b'0'),
            ("file2.txt", b"content2 is longer", b'0'),
            ("dir/", b"", b'5'),
        ]);
        let mut cursor = Cursor::new(data);
        let entries = read_archive_from(&mut cursor).unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].header.name, "file1.txt");
        assert_eq!(entries[1].header.name, "file2.txt");
        assert_eq!(entries[2].header.name, "dir/");
        assert!(entries[2].header.entry_type.is_directory());
    }

    #[test]
    fn test_read_large_file() {
        // File larger than one block.
        let content = vec![b'A'; 600];
        let data = make_archive(&[("large.bin", &content, b'0')]);
        let mut cursor = Cursor::new(data);
        let entries = read_archive_from(&mut cursor).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.size, 600);
        assert_eq!(entries[0].content.len(), 600);
        assert!(entries[0].content.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn test_read_symlink() {
        let data = make_archive(&[("link.txt", b"", b'2')]);
        let mut cursor = Cursor::new(data);
        let entries = read_archive_from(&mut cursor).unwrap();

        assert_eq!(entries[0].header.entry_type, EntryType::Symlink);
        assert_eq!(entries[0].content.len(), 0);
    }

    #[test]
    fn test_read_raw_blocks() {
        let content = b"test content";
        let data = make_archive(&[("test.txt", content, b'0')]);
        let mut cursor = Cursor::new(data);
        let blocks = read_raw_blocks_from(&mut cursor).unwrap();

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].offset, 0);
    }

    fn read_raw_blocks_from<R: Read + Seek>(reader: &mut R) -> Result<Vec<RawBlock>, ReaderError> {
        // Reuse the same logic as read_raw_blocks but from a reader.
        let mut blocks = Vec::new();
        loop {
            let offset = reader
                .stream_position()
                .map_err(|e| ReaderError::Io(e.to_string()))?;
            let mut block = [0u8; BLOCK_SIZE];
            let n = reader
                .read(&mut block)
                .map_err(|e| ReaderError::Io(e.to_string()))?;
            if n == 0 || n < BLOCK_SIZE {
                break;
            }
            if block.iter().all(|&b| b == 0) {
                break;
            }
            if let Ok(h) = header::TarHeader::parse(&block) {
                blocks.push(RawBlock {
                    block,
                    offset,
                    is_header: true,
                });
                if h.size > 0 {
                    let total = h.size
                        + ((BLOCK_SIZE as u64 - (h.size % BLOCK_SIZE as u64)) % BLOCK_SIZE as u64);
                    reader
                        .seek(SeekFrom::Current(total as i64))
                        .map_err(|e| ReaderError::Io(e.to_string()))?;
                }
            } else {
                break;
            }
        }
        Ok(blocks)
    }
}
