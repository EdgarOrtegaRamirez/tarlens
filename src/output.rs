//! Output formatting — text and JSON output for all tarlens commands.

use std::io::Write;
use std::path::Path;

use crate::diff::{Change, DiffResult};
use crate::reader::TarEntry;
use crate::stats::{format_size, ArchiveStats};
use crate::verify::{IssueSeverity, VerifyReport, VerifyStatus};

// ===========================================================================
// Text output
// ===========================================================================

/// Print a list of entries in text format.
pub fn print_list<W: Write>(w: &mut W, entries: &[TarEntry], long: bool) -> std::io::Result<()> {
    for entry in entries {
        if entry.header.entry_type.is_metadata() {
            continue;
        }
        if long {
            writeln!(
                w,
                "{} {:>8} {} {} {} {}",
                format_mode(entry.header.mode),
                format_size(entry.header.size),
                entry.header.uname_or_uid(),
                entry.header.gname_or_gid(),
                format_mtime(entry.header.mtime),
                entry.header.name,
            )?;
        } else {
            writeln!(w, "{}", entry.header.name)?;
        }
    }
    Ok(())
}

/// Print verify report in text format.
pub fn print_verify<W: Write>(w: &mut W, report: &VerifyReport) -> std::io::Result<()> {
    writeln!(w, "Archive Verification Report")?;
    writeln!(w, "============================")?;
    writeln!(w, "Total entries:     {}", report.total_entries)?;
    writeln!(w, "Valid checksums:   {}", report.valid_checksums)?;
    writeln!(w, "Invalid checksums: {}", report.invalid_checksums)?;
    writeln!(w, "Issues found:      {}", report.issues.len())?;
    writeln!(w)?;

    match report.overall_status {
        VerifyStatus::Pass => writeln!(w, "Status: PASS")?,
        VerifyStatus::Fail => writeln!(w, "Status: FAIL")?,
        VerifyStatus::Warning => writeln!(w, "Status: WARNING")?,
    }
    writeln!(w)?;

    if !report.issues.is_empty() {
        writeln!(w, "Issues:")?;
        for issue in &report.issues {
            let icon = match issue.severity {
                IssueSeverity::Error => "ERROR",
                IssueSeverity::Warning => "WARN",
                IssueSeverity::Info => "INFO",
            };
            writeln!(w, "  [{icon}] {}: {}", issue.entry_name, issue.message)?;
        }
    }
    Ok(())
}

/// Print statistics in text format.
pub fn print_stats<W: Write>(w: &mut W, stats: &ArchiveStats) -> std::io::Result<()> {
    writeln!(w, "Archive Statistics")?;
    writeln!(w, "==================")?;
    writeln!(w, "Total entries:      {}", stats.total_entries)?;
    writeln!(w, "Files:              {}", stats.file_count)?;
    writeln!(w, "Directories:        {}", stats.directory_count)?;
    writeln!(w, "Links:              {}", stats.link_count)?;
    writeln!(w, "Other:              {}", stats.other_count)?;
    writeln!(w, "Metadata entries:   {}", stats.metadata_count)?;
    writeln!(w)?;
    writeln!(
        w,
        "Total uncompressed:  {}",
        format_size(stats.total_uncompressed_size)
    )?;
    if let Some((name, size)) = &stats.largest_file {
        writeln!(w, "Largest file:        {} ({})", name, format_size(*size))?;
    }
    if let Some((name, size)) = &stats.smallest_file {
        writeln!(w, "Smallest file:       {} ({})", name, format_size(*size))?;
    }
    writeln!(
        w,
        "Average file size:   {:.2} bytes",
        stats.average_file_size
    )?;
    writeln!(w)?;

    if let Some(fmt) = stats.format {
        writeln!(w, "Detected format:     {}", fmt)?;
    }
    if stats.formats_detected.len() > 1 {
        writeln!(
            w,
            "All formats:         {}",
            stats
                .formats_detected
                .iter()
                .map(|f| format!("{f}"))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }
    writeln!(w)?;

    if !stats.entry_types.is_empty() {
        writeln!(w, "Entry type breakdown:")?;
        let mut types: Vec<_> = stats.entry_types.iter().collect();
        types.sort_by(|a, b| b.1.cmp(a.1));
        for (etype, count) in types {
            writeln!(w, "  {etype}: {count}")?;
        }
    }
    writeln!(w)?;

    if !stats.top_largest_files.is_empty() {
        writeln!(w, "Top largest files:")?;
        for (name, size) in &stats.top_largest_files {
            writeln!(w, "  {}: {}", name, format_size(*size))?;
        }
    }
    Ok(())
}

/// Print diff results in text format.
pub fn print_diff<W: Write>(
    w: &mut W,
    diff: &DiffResult,
    path1: &Path,
    path2: &Path,
) -> std::io::Result<()> {
    writeln!(
        w,
        "Archive Diff: {} vs {}",
        path1.display(),
        path2.display()
    )?;
    writeln!(w, "==========================================")?;
    writeln!(w, "Added entries:      {}", diff.added_count)?;
    writeln!(w, "Removed entries:    {}", diff.removed_count)?;
    writeln!(w, "Modified entries:   {}", diff.modified_count)?;
    writeln!(w, "Type changes:       {}", diff.type_changed_count)?;
    writeln!(w, "Unchanged entries:  {}", diff.unchanged_count)?;
    writeln!(w)?;

    if !diff.changes.is_empty() {
        writeln!(w, "Changes:")?;
        for change in &diff.changes {
            match change {
                Change::Added {
                    name,
                    entry_type,
                    size,
                } => {
                    writeln!(
                        w,
                        "  + {name}  ({}, {})",
                        entry_type.description(),
                        format_size(*size)
                    )?;
                }
                Change::Removed {
                    name,
                    entry_type,
                    size,
                } => {
                    writeln!(
                        w,
                        "  - {name}  ({}, {})",
                        entry_type.description(),
                        format_size(*size)
                    )?;
                }
                Change::Modified {
                    name,
                    old_size,
                    new_size,
                    old_mtime,
                    new_mtime,
                    content_changed,
                    ..
                } => {
                    writeln!(w, "  M {name}")?;
                    if old_size != new_size {
                        writeln!(
                            w,
                            "      size: {} -> {}",
                            format_size(*old_size),
                            format_size(*new_size)
                        )?;
                    }
                    if old_mtime != new_mtime {
                        writeln!(
                            w,
                            "      mtime: {} -> {}",
                            format_mtime(*old_mtime),
                            format_mtime(*new_mtime)
                        )?;
                    }
                    if *content_changed {
                        writeln!(w, "      content changed")?;
                    }
                }
                Change::TypeChanged {
                    name,
                    old_type,
                    new_type,
                } => {
                    writeln!(
                        w,
                        "  T {name}: {} -> {}",
                        old_type.description(),
                        new_type.description()
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Print archive info (format detection summary).
pub fn print_info<W: Write>(w: &mut W, entries: &[TarEntry], path: &Path) -> std::io::Result<()> {
    writeln!(w, "Archive: {}", path.display())?;
    writeln!(w, "================")?;

    let total = entries.len();
    let metadata = entries
        .iter()
        .filter(|e| e.header.entry_type.is_metadata())
        .count();
    let data_entries = total - metadata;

    writeln!(w, "Total blocks:       {total}")?;
    writeln!(w, "Data entries:       {data_entries}")?;
    writeln!(w, "Metadata entries:   {metadata}")?;
    writeln!(w)?;

    // Detect formats.
    let mut formats = Vec::new();
    for entry in entries {
        if !formats.contains(&entry.header.format) {
            formats.push(entry.header.format);
        }
    }

    if formats.len() == 1 {
        writeln!(w, "Format: {}", formats[0])?;
    } else if formats.is_empty() {
        writeln!(w, "Format: (empty archive)")?;
    } else {
        writeln!(w, "Formats detected:")?;
        for fmt in &formats {
            writeln!(w, "  - {fmt}")?;
        }
    }

    // Entry type summary.
    let mut file_count = 0;
    let mut dir_count = 0;
    let mut link_count = 0;
    let mut other_count = 0;
    for entry in entries
        .iter()
        .filter(|e| !e.header.entry_type.is_metadata())
    {
        let et = &entry.header.entry_type;
        if et.is_regular() {
            file_count += 1;
        } else if et.is_directory() {
            dir_count += 1;
        } else if et.is_link() {
            link_count += 1;
        } else {
            other_count += 1;
        }
    }

    writeln!(w)?;
    writeln!(w, "Entry summary:")?;
    writeln!(w, "  Files:       {file_count}")?;
    writeln!(w, "  Directories: {dir_count}")?;
    writeln!(w, "  Links:       {link_count}")?;
    writeln!(w, "  Other:       {other_count}")?;

    Ok(())
}

// ===========================================================================
// JSON output
// ===========================================================================

/// Print a list of entries in JSON format.
pub fn print_list_json<W: Write>(w: &mut W, entries: &[TarEntry]) -> std::io::Result<()> {
    let mut first = true;
    write!(w, "[")?;
    for entry in entries {
        if entry.header.entry_type.is_metadata() {
            continue;
        }
        if !first {
            write!(w, ",")?;
        }
        first = false;
        write!(
            w,
            r#"{{"name":"{}","type":"{}","size":{},"mode":"{:06o}","uid":{},"gid":{},"mtime":{}}}"#,
            json_escape(&entry.header.name),
            entry.header.entry_type.description(),
            entry.header.size,
            entry.header.mode,
            entry.header.uid,
            entry.header.gid,
            entry.header.mtime,
        )?;
    }
    writeln!(w, "]")?;
    Ok(())
}

/// Print verify report in JSON format.
pub fn print_verify_json<W: Write>(w: &mut W, report: &VerifyReport) -> std::io::Result<()> {
    let status = match report.overall_status {
        VerifyStatus::Pass => "pass",
        VerifyStatus::Fail => "fail",
        VerifyStatus::Warning => "warning",
    };
    write!(
        w,
        r#"{{"total_entries":{},"valid_checksums":{},"invalid_checksums":{},"status":"{}","issues":["#,
        report.total_entries, report.valid_checksums, report.invalid_checksums, status,
    )?;
    let mut first = true;
    for issue in &report.issues {
        if !first {
            write!(w, ",")?;
        }
        first = false;
        let severity = match issue.severity {
            IssueSeverity::Error => "error",
            IssueSeverity::Warning => "warning",
            IssueSeverity::Info => "info",
        };
        write!(
            w,
            r#"{{"severity":"{}","entry":"{}","message":"{}"}}"#,
            severity,
            json_escape(&issue.entry_name),
            json_escape(&issue.message),
        )?;
    }
    writeln!(w, "]}}")?;
    Ok(())
}

/// Print statistics in JSON format.
pub fn print_stats_json<W: Write>(w: &mut W, stats: &ArchiveStats) -> std::io::Result<()> {
    let largest = stats
        .largest_file
        .as_ref()
        .map(|(n, s)| format!(r#"{{"name":"{}","size":{}}}"#, json_escape(n), s))
        .unwrap_or_else(|| "null".to_string());
    let smallest = stats
        .smallest_file
        .as_ref()
        .map(|(n, s)| format!(r#"{{"name":"{}","size":{}}}"#, json_escape(n), s))
        .unwrap_or_else(|| "null".to_string());
    let format_str = stats
        .format
        .map(|f| format!(r#""{}""#, f))
        .unwrap_or_else(|| "null".to_string());

    writeln!(
        w,
        r#"{{"total_entries":{},"file_count":{},"directory_count":{},"link_count":{},"other_count":{},"total_uncompressed_size":{},"largest_file":{},"smallest_file":{},"average_file_size":{:.2},"format":{}}}"#,
        stats.total_entries,
        stats.file_count,
        stats.directory_count,
        stats.link_count,
        stats.other_count,
        stats.total_uncompressed_size,
        largest,
        smallest,
        stats.average_file_size,
        format_str,
    )?;
    Ok(())
}

/// Print diff results in JSON format.
pub fn print_diff_json<W: Write>(w: &mut W, diff: &DiffResult) -> std::io::Result<()> {
    write!(
        w,
        r#"{{"added_count":{},"removed_count":{},"modified_count":{},"type_changed_count":{},"unchanged_count":{},"changes":["#,
        diff.added_count,
        diff.removed_count,
        diff.modified_count,
        diff.type_changed_count,
        diff.unchanged_count,
    )?;
    let mut first = true;
    for change in &diff.changes {
        if !first {
            write!(w, ",")?;
        }
        first = false;
        match change {
            Change::Added {
                name,
                entry_type,
                size,
            } => {
                write!(
                    w,
                    r#"{{"type":"added","name":"{}","entry_type":"{}","size":{}}}"#,
                    json_escape(name),
                    entry_type.description(),
                    size,
                )?;
            }
            Change::Removed {
                name,
                entry_type,
                size,
            } => {
                write!(
                    w,
                    r#"{{"type":"removed","name":"{}","entry_type":"{}","size":{}}}"#,
                    json_escape(name),
                    entry_type.description(),
                    size,
                )?;
            }
            Change::Modified {
                name,
                old_size,
                new_size,
                old_mtime,
                new_mtime,
                content_changed,
                ..
            } => {
                write!(
                    w,
                    r#"{{"type":"modified","name":"{}","old_size":{},"new_size":{},"old_mtime":{},"new_mtime":{},"content_changed":{}}}"#,
                    json_escape(name),
                    old_size,
                    new_size,
                    old_mtime,
                    new_mtime,
                    content_changed,
                )?;
            }
            Change::TypeChanged {
                name,
                old_type,
                new_type,
            } => {
                write!(
                    w,
                    r#"{{"type":"type_changed","name":"{}","old_type":"{}","new_type":"{}"}}"#,
                    json_escape(name),
                    old_type.description(),
                    new_type.description(),
                )?;
            }
        }
    }
    writeln!(w, "]}}")?;
    Ok(())
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Escape a string for JSON output.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Format a mode/permissions string (e.g., "rwxr-xr-x").
fn format_mode(mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    });
    let perms = mode & 0o777;
    let bits = [
        (perms & 0o400 != 0, perms & 0o200 != 0, perms & 0o100 != 0),
        (perms & 0o040 != 0, perms & 0o020 != 0, perms & 0o010 != 0),
        (perms & 0o004 != 0, perms & 0o002 != 0, perms & 0o001 != 0),
    ];
    for (r, w, x) in bits {
        s.push(if r { 'r' } else { '-' });
        s.push(if w { 'w' } else { '-' });
        s.push(if x { 'x' } else { '-' });
    }
    s
}

/// Format a Unix timestamp as a human-readable date.
fn format_mtime(mtime: u64) -> String {
    if mtime == 0 {
        return "epoch".to_string();
    }
    let secs = mtime as i64;
    let days = secs / 86400;
    let remainder = secs % 86400;
    let hours = remainder / 3600;
    let minutes = (remainder % 3600) / 60;
    let seconds = remainder % 60;

    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}")
}

/// Convert days since epoch to (year, month, day).
fn days_to_date(days: i64) -> (i64, u32, u32) {
    let mut year = 1970i64;
    let mut remaining_days = days;

    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let year_days = if is_leap { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [
        31,
        28 + is_leap as i64,
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &mdays in &month_days {
        if remaining_days < mdays {
            break;
        }
        remaining_days -= mdays;
        month += 1;
    }
    let day = remaining_days as u32 + 1;
    (year, month, day)
}

// Helper trait for TarHeader.
trait HeaderHelpers {
    fn uname_or_uid(&self) -> String;
    fn gname_or_gid(&self) -> String;
}

impl HeaderHelpers for crate::header::TarHeader {
    fn uname_or_uid(&self) -> String {
        if !self.uname.is_empty() {
            self.uname.clone()
        } else {
            self.uid.to_string()
        }
    }
    fn gname_or_gid(&self) -> String {
        if !self.gname.is_empty() {
            self.gname.clone()
        } else {
            self.gid.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{Change, DiffResult};
    use crate::header::{EntryType, TarFormat, TarHeader};
    use crate::reader::TarEntry;
    use crate::stats::ArchiveStats;
    use crate::verify::{IssueSeverity, VerifyIssue, VerifyReport, VerifyStatus};
    use std::collections::HashMap;

    fn make_entry(name: &str, size: u64, entry_type: EntryType) -> TarEntry {
        TarEntry {
            header: TarHeader {
                name: name.to_string(),
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                size,
                mtime: 1000,
                checksum: 0,
                entry_type,
                linkname: String::new(),
                format: TarFormat::Ustar,
                uname: "user".to_string(),
                gname: "group".to_string(),
                devmajor: 0,
                devminor: 0,
                prefix: String::new(),
                pax_records: Vec::new(),
                checksum_valid: true,
            },
            content: vec![b'x'; size as usize],
            raw_block: [0u8; 512],
            offset: 0,
        }
    }

    #[test]
    fn test_print_list_short() {
        let entries = vec![
            make_entry("file1.txt", 10, EntryType::Regular),
            make_entry("file2.txt", 20, EntryType::Regular),
        ];
        let mut buf = Vec::new();
        print_list(&mut buf, &entries, false).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("file1.txt"));
        assert!(output.contains("file2.txt"));
    }

    #[test]
    fn test_print_list_long() {
        let entries = vec![make_entry("file1.txt", 10, EntryType::Regular)];
        let mut buf = Vec::new();
        print_list(&mut buf, &entries, true).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("file1.txt"));
        assert!(output.contains("user"));
    }

    #[test]
    fn test_print_verify_pass() {
        let report = VerifyReport {
            total_entries: 5,
            valid_checksums: 5,
            invalid_checksums: 0,
            issues: vec![],
            overall_status: VerifyStatus::Pass,
        };
        let mut buf = Vec::new();
        print_verify(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("PASS"));
        assert!(output.contains("Total entries:     5"));
    }

    #[test]
    fn test_print_verify_fail() {
        let report = VerifyReport {
            total_entries: 1,
            valid_checksums: 0,
            invalid_checksums: 1,
            issues: vec![VerifyIssue {
                severity: IssueSeverity::Error,
                entry_name: "bad.txt".to_string(),
                message: "checksum mismatch".to_string(),
            }],
            overall_status: VerifyStatus::Fail,
        };
        let mut buf = Vec::new();
        print_verify(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("FAIL"));
        assert!(output.contains("bad.txt"));
    }

    #[test]
    fn test_print_stats() {
        let mut entry_types = HashMap::new();
        entry_types.insert("regular file".to_string(), 3);
        let stats = ArchiveStats {
            total_entries: 3,
            file_count: 3,
            directory_count: 0,
            link_count: 0,
            other_count: 0,
            metadata_count: 0,
            total_uncompressed_size: 600,
            largest_file: Some(("big.txt".to_string(), 300)),
            smallest_file: Some(("small.txt".to_string(), 100)),
            average_file_size: 200.0,
            format: Some(TarFormat::Ustar),
            formats_detected: vec![TarFormat::Ustar],
            entry_types,
            top_largest_files: vec![("big.txt".to_string(), 300)],
        };
        let mut buf = Vec::new();
        print_stats(&mut buf, &stats).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Files:"));
        assert!(output.contains("big.txt"));
        assert!(output.contains("Ustar"));
    }

    #[test]
    fn test_print_diff() {
        let diff = DiffResult {
            changes: vec![
                Change::Added {
                    name: "added.txt".to_string(),
                    entry_type: EntryType::Regular,
                    size: 100,
                },
                Change::Removed {
                    name: "removed.txt".to_string(),
                    entry_type: EntryType::Regular,
                    size: 50,
                },
                Change::Modified {
                    name: "mod.txt".to_string(),
                    entry_type: EntryType::Regular,
                    old_size: 100,
                    new_size: 200,
                    old_mtime: 1000,
                    new_mtime: 2000,
                    old_mode: 0o644,
                    new_mode: 0o644,
                    content_changed: true,
                },
            ],
            added_count: 1,
            removed_count: 1,
            modified_count: 1,
            type_changed_count: 0,
            unchanged_count: 0,
        };
        let mut buf = Vec::new();
        print_diff(&mut buf, &diff, Path::new("a.tar"), Path::new("b.tar")).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("removed.txt"));
        assert!(output.contains("added.txt"));
        assert!(output.contains("mod.txt"));
        assert!(output.contains("size: 100 B -> 200 B"));
    }

    #[test]
    fn test_print_info() {
        let entries = vec![
            make_entry("file1.txt", 10, EntryType::Regular),
            make_entry("dir/", 0, EntryType::Directory),
        ];
        let mut buf = Vec::new();
        print_info(&mut buf, &entries, Path::new("test.tar")).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("test.tar"));
        assert!(output.contains("Ustar"));
        assert!(output.contains("Files:       1"));
        assert!(output.contains("Directories: 1"));
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape(r#"he said "hi""#), r#"he said \"hi\""#);
        assert_eq!(json_escape("line\nbreak"), r#"line\nbreak"#);
    }

    #[test]
    fn test_print_list_json() {
        let entries = vec![make_entry("file.txt", 10, EntryType::Regular)];
        let mut buf = Vec::new();
        print_list_json(&mut buf, &entries).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("file.txt"));
        assert!(output.contains("regular file"));
        assert!(output.starts_with("["));
        assert!(output.trim().ends_with("]"));
    }

    #[test]
    fn test_days_to_date() {
        assert_eq!(days_to_date(0), (1970, 1, 1));
        assert_eq!(days_to_date(31), (1970, 2, 1));
        assert_eq!(days_to_date(365), (1971, 1, 1));
    }

    #[test]
    fn test_format_mode() {
        let mut buf = Vec::new();
        let entry = make_entry("test", 0, EntryType::Regular);
        print_list(&mut buf, &[entry], true).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("rw-r--r--"));
    }
}
