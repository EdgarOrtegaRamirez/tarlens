//! Tar header parsing — 512-byte block format (V7, USTAR, PAX, GNU).
//!
//! The tar header is a 512-byte block with fields stored as null-terminated
//! octal strings. This module implements parsing, checksum verification,
//! and format detection for all major tar variants.

use std::fmt;
use std::str;

/// Size of a tar header block in bytes.
pub const BLOCK_SIZE: usize = 512;

/// Tar entry type flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryType {
    Regular,
    HardLink,
    Symlink,
    CharDevice,
    BlockDevice,
    Directory,
    Fifo,
    Contiguous,
    PaxHeader,
    PaxGlobal,
    GnuLongName,
    GnuLongLink,
    GnuSparse,
    Other(char),
}

impl EntryType {
    pub fn from_flag(flag: u8) -> Self {
        match flag {
            b'0' | 0 => EntryType::Regular,
            b'1' => EntryType::HardLink,
            b'2' => EntryType::Symlink,
            b'3' => EntryType::CharDevice,
            b'4' => EntryType::BlockDevice,
            b'5' => EntryType::Directory,
            b'6' => EntryType::Fifo,
            b'7' => EntryType::Contiguous,
            b'x' => EntryType::PaxHeader,
            b'g' => EntryType::PaxGlobal,
            b'L' => EntryType::GnuLongName,
            b'K' => EntryType::GnuLongLink,
            b'S' => EntryType::GnuSparse,
            other => EntryType::Other(other as char),
        }
    }

    pub fn as_flag(&self) -> u8 {
        match self {
            EntryType::Regular => b'0',
            EntryType::HardLink => b'1',
            EntryType::Symlink => b'2',
            EntryType::CharDevice => b'3',
            EntryType::BlockDevice => b'4',
            EntryType::Directory => b'5',
            EntryType::Fifo => b'6',
            EntryType::Contiguous => b'7',
            EntryType::PaxHeader => b'x',
            EntryType::PaxGlobal => b'g',
            EntryType::GnuLongName => b'L',
            EntryType::GnuLongLink => b'K',
            EntryType::GnuSparse => b'S',
            EntryType::Other(c) => *c as u8,
        }
    }

    pub fn is_regular(&self) -> bool {
        matches!(self, EntryType::Regular | EntryType::Contiguous)
    }

    pub fn is_directory(&self) -> bool {
        matches!(self, EntryType::Directory)
    }

    pub fn is_link(&self) -> bool {
        matches!(self, EntryType::HardLink | EntryType::Symlink)
    }

    pub fn is_metadata(&self) -> bool {
        matches!(
            self,
            EntryType::PaxHeader
                | EntryType::PaxGlobal
                | EntryType::GnuLongName
                | EntryType::GnuLongLink
                | EntryType::GnuSparse
        )
    }

    pub fn description(&self) -> &'static str {
        match self {
            EntryType::Regular => "regular file",
            EntryType::HardLink => "hard link",
            EntryType::Symlink => "symbolic link",
            EntryType::CharDevice => "character device",
            EntryType::BlockDevice => "block device",
            EntryType::Directory => "directory",
            EntryType::Fifo => "FIFO",
            EntryType::Contiguous => "contiguous file",
            EntryType::PaxHeader => "PAX extended header",
            EntryType::PaxGlobal => "PAX global header",
            EntryType::GnuLongName => "GNU long name",
            EntryType::GnuLongLink => "GNU long link",
            EntryType::GnuSparse => "GNU sparse file",
            EntryType::Other(_) => "unknown",
        }
    }
}

/// Tar format variant detected from header magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarFormat {
    /// Original Unix V7 tar (no magic field).
    V7,
    /// POSIX.1-1988 USTAR format (magic = "ustar\0").
    Ustar,
    /// GNU tar format (magic = "ustar " with space).
    Gnu,
    /// PAX POSIX.1-2001 format (USTAR header + PAX extended headers).
    Pax,
}

impl fmt::Display for TarFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TarFormat::V7 => write!(f, "V7"),
            TarFormat::Ustar => write!(f, "Ustar"),
            TarFormat::Gnu => write!(f, "GNU"),
            TarFormat::Pax => write!(f, "PAX"),
        }
    }
}

/// PAX extended header record (key-value pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaxRecord {
    pub key: String,
    pub value: String,
}

/// A parsed tar header with all fields decoded.
#[derive(Debug, Clone)]
pub struct TarHeader {
    /// File name (may be overridden by PAX or GNU long name).
    pub name: String,
    /// File mode (permission bits) as octal string.
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Modification time (Unix timestamp).
    pub mtime: u64,
    /// Computed checksum (sum of all bytes with checksum field as spaces).
    pub checksum: u32,
    /// Entry type flag.
    pub entry_type: EntryType,
    /// Link target name (for symlinks/hardlinks).
    pub linkname: String,
    /// Detected format variant.
    pub format: TarFormat,
    /// Owner user name.
    pub uname: String,
    /// Owner group name.
    pub gname: String,
    /// Device major number.
    pub devmajor: u32,
    /// Device minor number.
    pub devminor: u32,
    /// Prefix (for long paths in USTAR format).
    pub prefix: String,
    /// PAX extended records (if any were applied).
    pub pax_records: Vec<PaxRecord>,
    /// Whether the checksum was valid.
    pub checksum_valid: bool,
}

impl TarHeader {
    /// Parse a 512-byte block into a TarHeader.
    ///
    /// Returns an error if the block is empty (all zeros) or too small.
    pub fn parse(block: &[u8; BLOCK_SIZE]) -> Result<Self, HeaderError> {
        // Check for end-of-archive marker (two consecutive zero blocks).
        let is_zero = block.iter().all(|&b| b == 0);
        if is_zero {
            return Err(HeaderError::EndOfArchive);
        }

        // Parse name (100 bytes, null-terminated).
        let name = parse_cstr(&block[0..100])?;

        // Parse mode (8 bytes, octal, null or space terminated).
        let mode = parse_octal(&block[100..108])?;

        // Parse uid (8 bytes, octal).
        let uid = parse_octal(&block[108..116])?;

        // Parse gid (8 bytes, octal).
        let gid = parse_octal(&block[116..124])?;

        // Parse size (12 bytes, octal). GNU uses base-256 for large files.
        let size = parse_size(&block[124..136])?;

        // Parse mtime (12 bytes, octal).
        let mtime = parse_size(&block[136..148])?;

        // Parse checksum (8 bytes, octal, followed by NUL and space).
        let stored_checksum = parse_octal(&block[148..156]).unwrap_or(0);

        // Parse type flag (1 byte).
        let typeflag = block[156];
        let entry_type = EntryType::from_flag(typeflag);

        // Parse linkname (100 bytes).
        let linkname = parse_cstr(&block[157..257])?;

        // Detect format from magic field (bytes 257..263).
        let (format, _magic) = detect_format(&block[257..265]);

        // Parse uname (32 bytes, USTAR/GNU only).
        let uname = if format != TarFormat::V7 {
            parse_cstr(&block[265..297]).unwrap_or_default()
        } else {
            String::new()
        };

        // Parse gname (32 bytes, USTAR/GNU only).
        let gname = if format != TarFormat::V7 {
            parse_cstr(&block[297..329]).unwrap_or_default()
        } else {
            String::new()
        };

        // Parse devmajor (8 bytes, octal).
        let devmajor = if format != TarFormat::V7 {
            parse_octal(&block[329..337]).unwrap_or(0)
        } else {
            0
        };

        // Parse devminor (8 bytes, octal).
        let devminor = if format != TarFormat::V7 {
            parse_octal(&block[337..345]).unwrap_or(0)
        } else {
            0
        };

        // Parse prefix (155 bytes, USTAR/GNU only).
        let prefix = if format != TarFormat::V7 {
            parse_cstr(&block[345..500]).unwrap_or_default()
        } else {
            String::new()
        };

        // Compute and verify checksum.
        let computed_checksum = compute_checksum(block);
        let checksum_valid = computed_checksum == stored_checksum;

        // Build full path from prefix + name (USTAR long path support).
        let full_name = if !prefix.is_empty() && !name.is_empty() {
            format!("{prefix}/{name}")
        } else {
            name
        };

        Ok(TarHeader {
            name: full_name,
            mode,
            uid,
            gid,
            size,
            mtime,
            checksum: stored_checksum,
            entry_type,
            linkname,
            format,
            uname,
            gname,
            devmajor,
            devminor,
            prefix,
            pax_records: Vec::new(),
            checksum_valid,
        })
    }

    /// Apply PAX records to override header fields.
    pub fn apply_pax(&mut self, records: &[PaxRecord]) {
        for record in records {
            match record.key.as_str() {
                "path" => self.name = record.value.clone(),
                "linkpath" => self.linkname = record.value.clone(),
                "size" => {
                    if let Ok(size) = record.value.parse::<u64>() {
                        self.size = size;
                    }
                }
                "uid" => {
                    if let Ok(uid) = record.value.parse::<u32>() {
                        self.uid = uid;
                    }
                }
                "gid" => {
                    if let Ok(gid) = record.value.parse::<u32>() {
                        self.gid = gid;
                    }
                }
                "uname" => self.uname = record.value.clone(),
                "gname" => self.gname = record.value.clone(),
                "mtime" => {
                    if let Ok(mtime) = record.value.parse::<u64>() {
                        self.mtime = mtime;
                    }
                }
                _ => {}
            }
        }
        self.pax_records = records.to_vec();
        if !records.is_empty() {
            self.format = TarFormat::Pax;
        }
    }

    /// Get the permission bits as a string (e.g., "rwxr-xr-x").
    pub fn permissions(&self) -> String {
        let mode = self.mode & 0o7777;
        let mut perms = String::with_capacity(10);

        // File type indicator
        perms.push(match self.entry_type {
            EntryType::Regular => '-',
            EntryType::Directory => 'd',
            EntryType::Symlink => 'l',
            EntryType::HardLink => 'h',
            EntryType::CharDevice => 'c',
            EntryType::BlockDevice => 'b',
            EntryType::Fifo => 'p',
            _ => '?',
        });

        // Owner permissions
        perms.push(if mode & 0o400 != 0 { 'r' } else { '-' });
        perms.push(if mode & 0o200 != 0 { 'w' } else { '-' });
        perms.push(if mode & 0o100 != 0 {
            if mode & 0o4000 != 0 {
                's'
            } else {
                'x'
            }
        } else if mode & 0o4000 != 0 {
            'S'
        } else {
            '-'
        });

        // Group permissions
        perms.push(if mode & 0o040 != 0 { 'r' } else { '-' });
        perms.push(if mode & 0o020 != 0 { 'w' } else { '-' });
        perms.push(if mode & 0o010 != 0 {
            if mode & 0o2000 != 0 {
                's'
            } else {
                'x'
            }
        } else if mode & 0o2000 != 0 {
            'S'
        } else {
            '-'
        });

        // Other permissions
        perms.push(if mode & 0o004 != 0 { 'r' } else { '-' });
        perms.push(if mode & 0o002 != 0 { 'w' } else { '-' });
        perms.push(if mode & 0o001 != 0 {
            if mode & 0o1000 != 0 {
                't'
            } else {
                'x'
            }
        } else if mode & 0o1000 != 0 {
            'T'
        } else {
            '-'
        });

        perms
    }

    /// Format the modification time as a human-readable string.
    pub fn mtime_string(&self) -> String {
        if self.mtime == 0 {
            return "1970-01-01 00:00:00 UTC".to_string();
        }
        // Simple formatting without external date library.
        let days_since_epoch = self.mtime / 86400;
        let secs_in_day = self.mtime % 86400;
        let hour = secs_in_day / 3600;
        let min = (secs_in_day % 3600) / 60;
        let sec = secs_in_day % 60;

        // Calculate date from days since epoch.
        let (year, month, day) = days_to_ymd(days_since_epoch as i64);
        format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} UTC")
    }

    /// Format the size as a human-readable string.
    pub fn size_string(&self) -> String {
        let size = self.size;
        if size < 1024 {
            format!("{size}B")
        } else if size < 1024 * 1024 {
            format!("{:.1}K", size as f64 / 1024.0)
        } else if size < 1024 * 1024 * 1024 {
            format!("{:.1}M", size as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.1}G", size as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }
}

/// Errors that can occur during header parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// End of archive (zero block encountered).
    EndOfArchive,
    /// Invalid octal number in a numeric field.
    InvalidOctal { field: &'static str, value: String },
    /// Invalid UTF-8 in a string field.
    InvalidUtf8 { field: &'static str },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::EndOfArchive => write!(f, "end of archive"),
            HeaderError::InvalidOctal { field, value } => {
                write!(f, "invalid octal in {field}: {value:?}")
            }
            HeaderError::InvalidUtf8 { field } => {
                write!(f, "invalid UTF-8 in {field}")
            }
        }
    }
}

impl std::error::Error for HeaderError {}

/// Parse a null-terminated string from a byte slice.
fn parse_cstr(data: &[u8]) -> Result<String, HeaderError> {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let trimmed = &data[..end];
    str::from_utf8(trimmed)
        .map(|s| s.trim_end().to_string())
        .map_err(|_| HeaderError::InvalidUtf8 { field: "string" })
}

/// Parse an octal number from a tar field.
fn parse_octal(data: &[u8]) -> Result<u32, HeaderError> {
    let end = data
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(data.len());
    let trimmed = &data[..end];
    let s = str::from_utf8(trimmed).map_err(|_| HeaderError::InvalidOctal {
        field: "octal",
        value: format!("{trimmed:?}"),
    })?;
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u32::from_str_radix(s, 8).map_err(|_| HeaderError::InvalidOctal {
        field: "octal",
        value: s.to_string(),
    })
}

/// Parse a size field (12 bytes). Supports octal and GNU base-256 encoding.
fn parse_size(data: &[u8]) -> Result<u64, HeaderError> {
    // GNU base-256 encoding: first byte has high bit set.
    if !data.is_empty() && data[0] & 0x80 != 0 {
        // Base-256: first byte is 0x80, remaining 11 bytes are big-endian.
        let mut result: u64 = (data[0] & 0x7f) as u64;
        for &b in &data[1..12] {
            result = (result << 8) | b as u64;
        }
        Ok(result)
    } else {
        let end = data
            .iter()
            .position(|&b| b == 0 || b == b' ')
            .unwrap_or(data.len());
        let trimmed = &data[..end];
        let s = str::from_utf8(trimmed).map_err(|_| HeaderError::InvalidOctal {
            field: "size",
            value: format!("{trimmed:?}"),
        })?;
        let s = s.trim();
        if s.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(s, 8).map_err(|_| HeaderError::InvalidOctal {
            field: "size",
            value: s.to_string(),
        })
    }
}

/// Detect the tar format from the magic field.
fn detect_format(magic: &[u8]) -> (TarFormat, &'static str) {
    // USTAR: magic = "ustar\0", version = "00"
    if magic.len() >= 6 && &magic[..5] == b"ustar" && magic[5] == 0 {
        return (TarFormat::Ustar, "ustar\\0");
    }
    // GNU: magic = "ustar ", version = " \0"
    if magic.len() >= 8 && &magic[..6] == b"ustar " && magic[6] == b' ' {
        return (TarFormat::Gnu, "ustar  ");
    }
    // V7: no magic field
    (TarFormat::V7, "(none)")
}

/// Compute the tar checksum: sum of all bytes with the checksum field
/// treated as 8 spaces (0x20).
pub fn compute_checksum(block: &[u8; BLOCK_SIZE]) -> u32 {
    let mut sum: u32 = 0;
    for (i, &byte) in block.iter().enumerate() {
        // Checksum field is bytes 148..156 (8 bytes).
        if (148..156).contains(&i) {
            sum += 0x20; // Treat checksum field as spaces.
        } else {
            sum += byte as u32;
        }
    }
    sum
}

/// Parse PAX extended header records from a data block.
///
/// PAX records are in the format: "%d %s=%s\n" where %d is the length
/// of the entire record (including the length field itself).
pub fn parse_pax_records(data: &[u8]) -> Result<Vec<PaxRecord>, HeaderError> {
    let mut records = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Skip trailing NUL or newline.
        if data[pos] == 0 || data[pos] == b'\n' {
            break;
        }

        // Find the space that separates length from key.
        let space_pos =
            data[pos..]
                .iter()
                .position(|&b| b == b' ')
                .ok_or(HeaderError::InvalidUtf8 {
                    field: "pax length",
                })?;

        let length_str =
            str::from_utf8(&data[pos..pos + space_pos]).map_err(|_| HeaderError::InvalidUtf8 {
                field: "pax length",
            })?;
        let total_len: usize = length_str.parse().map_err(|_| HeaderError::InvalidOctal {
            field: "pax length",
            value: length_str.to_string(),
        })?;

        if pos + total_len > data.len() {
            break;
        }

        let record_data = &data[pos + space_pos + 1..pos + total_len];

        // Find the = that separates key from value.
        let eq_pos = record_data
            .iter()
            .position(|&b| b == b'=')
            .ok_or(HeaderError::InvalidUtf8 { field: "pax key" })?;

        let key = str::from_utf8(&record_data[..eq_pos])
            .map_err(|_| HeaderError::InvalidUtf8 { field: "pax key" })?
            .to_string();

        // Value is everything after = up to the trailing newline.
        let value_end = if record_data.ends_with(b"\n") {
            record_data.len() - 1
        } else {
            record_data.len()
        };
        let value = str::from_utf8(&record_data[eq_pos + 1..value_end])
            .map_err(|_| HeaderError::InvalidUtf8 { field: "pax value" })?
            .to_string();

        records.push(PaxRecord { key, value });
        pos += total_len;
    }

    Ok(records)
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    // Algorithm from "Calendrical Calculations" by Nachum Dershowitz.
    // Days since 1970-01-01.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_zero_block() -> [u8; BLOCK_SIZE] {
        [0u8; BLOCK_SIZE]
    }

    fn make_simple_header(name: &str, size: u64, typeflag: u8) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];

        // Name (100 bytes)
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(100);
        block[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // Mode (8 bytes, octal) — 0o644
        write_octal(&mut block[100..108], 0o644);

        // UID (8 bytes)
        write_octal(&mut block[108..116], 1000);

        // GID (8 bytes)
        write_octal(&mut block[116..124], 1000);

        // Size (12 bytes)
        write_octal(&mut block[124..136], size);

        // Mtime (12 bytes)
        write_octal(&mut block[136..148], 1718000000);

        // Type flag (1 byte)
        block[156] = typeflag;

        // Magic (6 bytes) — USTAR
        block[257..262].copy_from_slice(b"ustar");
        block[262] = 0;

        // Version (2 bytes) — "00"
        block[263] = b'0';
        block[264] = b'0';

        // Compute and write checksum.
        let checksum = compute_checksum(&block);
        write_octal(&mut block[148..155], checksum as u64);
        block[155] = 0;

        block
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let s = format!("{:0width$o}", value, width = width);
        let len = s.len().min(width);
        field[..len].copy_from_slice(&s.as_bytes()[..len]);
        field[len] = 0;
    }

    #[test]
    fn test_end_of_archive() {
        let block = make_zero_block();
        let result = TarHeader::parse(&block);
        assert_eq!(result.unwrap_err(), HeaderError::EndOfArchive);
    }

    #[test]
    fn test_simple_regular_file() {
        let block = make_simple_header("test.txt", 42, b'0');
        let header = TarHeader::parse(&block).unwrap();

        assert_eq!(header.name, "test.txt");
        assert_eq!(header.mode, 0o644);
        assert_eq!(header.uid, 1000);
        assert_eq!(header.gid, 1000);
        assert_eq!(header.size, 42);
        assert_eq!(header.entry_type, EntryType::Regular);
        assert!(header.entry_type.is_regular());
        assert!(header.checksum_valid);
        assert_eq!(header.format, TarFormat::Ustar);
    }

    #[test]
    fn test_directory() {
        let block = make_simple_header("mydir/", 0, b'5');
        let header = TarHeader::parse(&block).unwrap();

        assert_eq!(header.name, "mydir/");
        assert_eq!(header.entry_type, EntryType::Directory);
        assert!(header.entry_type.is_directory());
        assert_eq!(header.size, 0);
    }

    #[test]
    fn test_symlink() {
        let mut block = make_simple_header("link.txt", 0, b'2');
        let linkname = b"target.txt";
        block[157..157 + linkname.len()].copy_from_slice(linkname);

        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.entry_type, EntryType::Symlink);
        assert!(header.entry_type.is_link());
        assert_eq!(header.linkname, "target.txt");
    }

    #[test]
    fn test_v7_format() {
        let mut block = make_simple_header("old.txt", 10, b'0');
        // Clear magic field to simulate V7 format.
        for b in &mut block[257..265] {
            *b = 0;
        }
        // Recompute checksum.
        let checksum = compute_checksum(&block);
        write_octal(&mut block[148..155], checksum as u64);
        block[155] = 0;

        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.format, TarFormat::V7);
        assert!(header.uname.is_empty());
        assert!(header.gname.is_empty());
    }

    #[test]
    fn test_gnu_format() {
        let mut block = make_simple_header("gnu.txt", 10, b'0');
        // GNU magic: "ustar " (with trailing space).
        block[257..263].copy_from_slice(b"ustar ");
        block[263] = b' ';
        block[264] = 0;
        // Recompute checksum.
        let checksum = compute_checksum(&block);
        write_octal(&mut block[148..155], checksum as u64);
        block[155] = 0;

        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.format, TarFormat::Gnu);
    }

    #[test]
    fn test_base256_size() {
        let mut block = make_simple_header("big.bin", 0, b'0');
        // Clear the size field (make_simple_header writes octal zeros = 0x30).
        for b in &mut block[124..136] {
            *b = 0;
        }
        // Write base-256 encoded size > 8GB.
        // Size field is bytes 124..136 (12 bytes). Base-256: first byte has
        // high bit set, remaining bytes are big-endian value.
        // 8GB = 0x200000000, which in 12-byte big-endian (after indicator) is:
        // [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]
        block[124] = 0x80; // Base-256 indicator.
        block[131] = 0x02; // Byte 7 of size field (bits 32-39, value 2^33 = 8GB).
                           // Recompute checksum.
        let checksum = compute_checksum(&block);
        write_octal(&mut block[148..155], checksum as u64);
        block[155] = 0;

        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.size, 0x200000000); // 8GB
    }

    #[test]
    fn test_checksum_verification() {
        let block = make_simple_header("test.txt", 42, b'0');
        let header = TarHeader::parse(&block).unwrap();
        assert!(header.checksum_valid);
    }

    #[test]
    fn test_invalid_checksum() {
        let mut block = make_simple_header("test.txt", 42, b'0');
        // Corrupt the checksum.
        block[148] = b'7';
        block[149] = b'7';
        block[150] = b'7';

        let header = TarHeader::parse(&block).unwrap();
        assert!(!header.checksum_valid);
    }

    #[test]
    fn test_permissions() {
        let block = make_simple_header("test.txt", 0, b'0');
        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.permissions(), "-rw-r--r--");
    }

    #[test]
    fn test_permissions_directory() {
        let block = make_simple_header("dir/", 0, b'5');
        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.permissions(), "drw-r--r--");
    }

    #[test]
    fn test_pax_records_parsing() {
        // Format: "len key=value\n"
        let data = b"12 path=foo\n10 uid=42\n";
        let records = parse_pax_records(data).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].key, "path");
        assert_eq!(records[0].value, "foo");
        assert_eq!(records[1].key, "uid");
        assert_eq!(records[1].value, "42");
    }

    #[test]
    fn test_apply_pax_path() {
        let block = make_simple_header("short.txt", 10, b'0');
        let mut header = TarHeader::parse(&block).unwrap();
        let records = vec![PaxRecord {
            key: "path".to_string(),
            value: "very/long/path/that/exceeds/100/characters/and/needs/pax/extension/to/be/stored.txt"
                .to_string(),
        }];
        header.apply_pax(&records);
        assert_eq!(header.format, TarFormat::Pax);
        assert!(header.name.starts_with("very/long/path/"));
    }

    #[test]
    fn test_size_string() {
        let block = make_simple_header("test.txt", 0, b'0');
        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.size_string(), "0B");
    }

    #[test]
    fn test_entry_type_description() {
        assert_eq!(EntryType::Regular.description(), "regular file");
        assert_eq!(EntryType::Directory.description(), "directory");
        assert_eq!(EntryType::Symlink.description(), "symbolic link");
        assert_eq!(EntryType::PaxHeader.description(), "PAX extended header");
    }

    #[test]
    fn test_days_to_ymd() {
        // 1970-01-01 = day 0
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 2024-01-01 = day 19723
        assert_eq!(days_to_ymd(19723), (2024, 1, 1));
        // 2026-04-28 ≈ day 20572
        let (y, m, d) = days_to_ymd(20572);
        assert_eq!(y, 2026);
        assert_eq!(m, 4);
        assert!((27..=29).contains(&d));
    }
}
