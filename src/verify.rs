//! Archive verification — checksum validation and structural integrity checks.

use crate::header::EntryType;
use crate::reader::TarEntry;

/// Verification report for an archive.
#[derive(Debug)]
pub struct VerifyReport {
    pub total_entries: usize,
    pub valid_checksums: usize,
    pub invalid_checksums: usize,
    pub issues: Vec<VerifyIssue>,
    pub overall_status: VerifyStatus,
}

/// A single verification issue.
#[derive(Debug, Clone)]
pub struct VerifyIssue {
    pub severity: IssueSeverity,
    pub entry_name: String,
    pub message: String,
}

/// Issue severity levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueSeverity {
    Error,
    Warning,
    Info,
}

/// Overall verification status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    Pass,
    Fail,
    Warning,
}

/// Verify an archive's integrity.
pub fn verify_archive(entries: &[TarEntry]) -> VerifyReport {
    let mut issues = Vec::new();
    let mut valid_checksums = 0;
    let mut invalid_checksums = 0;
    let mut seen_names = std::collections::HashSet::new();

    let total_entries = entries
        .iter()
        .filter(|e| !e.header.entry_type.is_metadata())
        .count();

    for entry in entries {
        // Check checksum validity.
        if entry.header.checksum_valid {
            valid_checksums += 1;
        } else {
            invalid_checksums += 1;
            issues.push(VerifyIssue {
                severity: IssueSeverity::Error,
                entry_name: entry.header.name.clone(),
                message: format!(
                    "checksum mismatch: stored={}, computed (not shown)",
                    entry.header.checksum
                ),
            });
        }

        // Skip metadata entries for further checks.
        if entry.header.entry_type.is_metadata() {
            continue;
        }

        // Check for duplicate entry names.
        if !seen_names.insert(entry.header.name.clone()) {
            issues.push(VerifyIssue {
                severity: IssueSeverity::Warning,
                entry_name: entry.header.name.clone(),
                message: "duplicate entry name in archive".to_string(),
            });
        }

        // Check for path traversal in entry names.
        if entry.header.name.contains("..") {
            issues.push(VerifyIssue {
                severity: IssueSeverity::Error,
                entry_name: entry.header.name.clone(),
                message: "path traversal detected (contains '..')".to_string(),
            });
        }

        // Check for absolute paths.
        if entry.header.name.starts_with('/') {
            issues.push(VerifyIssue {
                severity: IssueSeverity::Warning,
                entry_name: entry.header.name.clone(),
                message: "absolute path in entry name".to_string(),
            });
        }

        // Check for suspicious permissions.
        let mode = entry.header.mode & 0o7777;
        if mode & 0o777 == 0o777 {
            issues.push(VerifyIssue {
                severity: IssueSeverity::Warning,
                entry_name: entry.header.name.clone(),
                message: "world-writable, readable, and executable (0777)".to_string(),
            });
        }

        // Check for setuid/setgid bits.
        if mode & 0o6000 != 0 {
            let bits = if mode & 0o4000 != 0 { "setuid" } else { "" };
            let bits2 = if mode & 0o2000 != 0 { "setgid" } else { "" };
            let combined = [bits, bits2]
                .iter()
                .filter(|s| !s.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join("+");
            issues.push(VerifyIssue {
                severity: IssueSeverity::Info,
                entry_name: entry.header.name.clone(),
                message: format!("special permission bits set: {combined}"),
            });
        }

        // Check for empty regular files with non-zero size header.
        if entry.header.entry_type.is_regular()
            && entry.header.size > 0
            && entry.content.len() != entry.header.size as usize
        {
            issues.push(VerifyIssue {
                severity: IssueSeverity::Error,
                entry_name: entry.header.name.clone(),
                message: format!(
                    "content size mismatch: header={}, actual={}",
                    entry.header.size,
                    entry.content.len()
                ),
            });
        }

        // Check for symlinks pointing outside the archive.
        if entry.header.entry_type == EntryType::Symlink {
            if entry.header.linkname.starts_with('/') {
                issues.push(VerifyIssue {
                    severity: IssueSeverity::Warning,
                    entry_name: entry.header.name.clone(),
                    message: format!("symlink points to absolute path: {}", entry.header.linkname),
                });
            }
            if entry.header.linkname.contains("..") {
                issues.push(VerifyIssue {
                    severity: IssueSeverity::Warning,
                    entry_name: entry.header.name.clone(),
                    message: format!(
                        "symlink may traverse parent directory: {}",
                        entry.header.linkname
                    ),
                });
            }
        }
    }

    // Determine overall status.
    let has_errors = issues.iter().any(|i| i.severity == IssueSeverity::Error);
    let has_warnings = issues.iter().any(|i| i.severity == IssueSeverity::Warning);

    let overall_status = if has_errors || invalid_checksums > 0 {
        VerifyStatus::Fail
    } else if has_warnings {
        VerifyStatus::Warning
    } else {
        VerifyStatus::Pass
    };

    VerifyReport {
        total_entries,
        valid_checksums,
        invalid_checksums,
        issues,
        overall_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{EntryType, TarFormat, TarHeader};
    use crate::reader::TarEntry;

    fn make_entry(
        name: &str,
        size: u64,
        content: &[u8],
        checksum_valid: bool,
        entry_type: EntryType,
    ) -> TarEntry {
        TarEntry {
            header: TarHeader {
                name: name.to_string(),
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                size,
                mtime: 1000,
                checksum: 12345,
                entry_type,
                linkname: String::new(),
                format: TarFormat::Ustar,
                uname: String::new(),
                gname: String::new(),
                devmajor: 0,
                devminor: 0,
                prefix: String::new(),
                pax_records: Vec::new(),
                checksum_valid,
            },
            content: content.to_vec(),
            raw_block: [0u8; 512],
            offset: 0,
        }
    }

    #[test]
    fn test_verify_clean_archive() {
        let entries = vec![
            make_entry("file1.txt", 5, b"hello", true, EntryType::Regular),
            make_entry("file2.txt", 5, b"world", true, EntryType::Regular),
        ];
        let report = verify_archive(&entries);

        assert_eq!(report.overall_status, VerifyStatus::Pass);
        assert_eq!(report.valid_checksums, 2);
        assert_eq!(report.invalid_checksums, 0);
        assert!(report.issues.is_empty());
    }

    #[test]
    fn test_verify_invalid_checksum() {
        let entries = vec![make_entry(
            "bad.txt",
            5,
            b"hello",
            false,
            EntryType::Regular,
        )];
        let report = verify_archive(&entries);

        assert_eq!(report.overall_status, VerifyStatus::Fail);
        assert_eq!(report.invalid_checksums, 1);
        assert!(report
            .issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Error));
    }

    #[test]
    fn test_verify_path_traversal() {
        let entries = vec![make_entry(
            "../etc/passwd",
            0,
            b"",
            true,
            EntryType::Regular,
        )];
        let report = verify_archive(&entries);

        assert_eq!(report.overall_status, VerifyStatus::Fail);
        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("path traversal")));
    }

    #[test]
    fn test_verify_absolute_path() {
        let entries = vec![make_entry("/etc/passwd", 0, b"", true, EntryType::Regular)];
        let report = verify_archive(&entries);

        assert_eq!(report.overall_status, VerifyStatus::Warning);
        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("absolute path")));
    }

    #[test]
    fn test_verify_world_writable() {
        let mut entry = make_entry("dangerous.sh", 0, b"", true, EntryType::Regular);
        entry.header.mode = 0o777;
        let report = verify_archive(&[entry]);

        assert!(report.issues.iter().any(|i| i.message.contains("0777")));
    }

    #[test]
    fn test_verify_symlink_traversal() {
        let mut entry = make_entry("link.txt", 0, b"", true, EntryType::Symlink);
        entry.header.linkname = "../../../etc/passwd".to_string();
        let report = verify_archive(&[entry]);

        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("traverse parent")));
    }

    #[test]
    fn test_verify_content_size_mismatch() {
        let entries = vec![make_entry(
            "bad.txt",
            100,
            b"short",
            true,
            EntryType::Regular,
        )];
        let report = verify_archive(&entries);

        assert_eq!(report.overall_status, VerifyStatus::Fail);
        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("size mismatch")));
    }

    #[test]
    fn test_verify_duplicate_entries() {
        let entries = vec![
            make_entry("file.txt", 5, b"hello", true, EntryType::Regular),
            make_entry("file.txt", 5, b"world", true, EntryType::Regular),
        ];
        let report = verify_archive(&entries);

        assert!(report
            .issues
            .iter()
            .any(|i| i.message.contains("duplicate")));
    }
}
