//! Archive diffing — compare two tar archives and show changes.

use std::collections::HashMap;

use crate::header::EntryType;
use crate::reader::TarEntry;

/// A single change between two archives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// File added in archive2.
    Added {
        name: String,
        entry_type: EntryType,
        size: u64,
    },
    /// File removed from archive1.
    Removed {
        name: String,
        entry_type: EntryType,
        size: u64,
    },
    /// File modified between archives.
    Modified {
        name: String,
        entry_type: EntryType,
        old_size: u64,
        new_size: u64,
        old_mtime: u64,
        new_mtime: u64,
        old_mode: u32,
        new_mode: u32,
        content_changed: bool,
    },
    /// File type changed (e.g., file became directory).
    TypeChanged {
        name: String,
        old_type: EntryType,
        new_type: EntryType,
    },
}

/// Result of diffing two archives.
#[derive(Debug)]
pub struct DiffResult {
    pub changes: Vec<Change>,
    pub added_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
    pub type_changed_count: usize,
    pub unchanged_count: usize,
}

/// Diff two archives by comparing entries by name.
pub fn diff_archives(entries1: &[TarEntry], entries2: &[TarEntry]) -> DiffResult {
    // Build maps of name -> entry, excluding metadata entries.
    let map1: HashMap<String, &TarEntry> = entries1
        .iter()
        .filter(|e| !e.header.entry_type.is_metadata())
        .map(|e| (e.header.name.clone(), e))
        .collect();

    let map2: HashMap<String, &TarEntry> = entries2
        .iter()
        .filter(|e| !e.header.entry_type.is_metadata())
        .map(|e| (e.header.name.clone(), e))
        .collect();

    let mut changes = Vec::new();
    let mut added = 0;
    let mut removed = 0;
    let mut modified = 0;
    let mut type_changed = 0;
    let mut unchanged = 0;

    // Check for added and modified entries.
    let mut all_names: Vec<String> = map2.keys().cloned().collect();
    all_names.sort();

    for name in &all_names {
        let entry2 = map2[name];
        match map1.get(name) {
            None => {
                changes.push(Change::Added {
                    name: name.clone(),
                    entry_type: entry2.header.entry_type.clone(),
                    size: entry2.header.size,
                });
                added += 1;
            }
            Some(entry1) => {
                if entry1.header.entry_type != entry2.header.entry_type {
                    changes.push(Change::TypeChanged {
                        name: name.clone(),
                        old_type: entry1.header.entry_type.clone(),
                        new_type: entry2.header.entry_type.clone(),
                    });
                    type_changed += 1;
                } else {
                    let content_changed = entry1.content != entry2.content;
                    let size_changed = entry1.header.size != entry2.header.size;
                    let mtime_changed = entry1.header.mtime != entry2.header.mtime;
                    let mode_changed = entry1.header.mode != entry2.header.mode;

                    if content_changed || size_changed || mtime_changed || mode_changed {
                        changes.push(Change::Modified {
                            name: name.clone(),
                            entry_type: entry2.header.entry_type.clone(),
                            old_size: entry1.header.size,
                            new_size: entry2.header.size,
                            old_mtime: entry1.header.mtime,
                            new_mtime: entry2.header.mtime,
                            old_mode: entry1.header.mode,
                            new_mode: entry2.header.mode,
                            content_changed,
                        });
                        modified += 1;
                    } else {
                        unchanged += 1;
                    }
                }
            }
        }
    }

    // Check for removed entries.
    let mut names1: Vec<String> = map1.keys().cloned().collect();
    names1.sort();
    for name in &names1 {
        if !map2.contains_key(name) {
            let entry1 = map1[name];
            changes.push(Change::Removed {
                name: name.clone(),
                entry_type: entry1.header.entry_type.clone(),
                size: entry1.header.size,
            });
            removed += 1;
        }
    }

    // Sort changes by name for consistent output.
    changes.sort_by_key(|c| change_name(c).cloned());

    DiffResult {
        changes,
        added_count: added,
        removed_count: removed,
        modified_count: modified,
        type_changed_count: type_changed,
        unchanged_count: unchanged,
    }
}

fn change_name(change: &Change) -> Option<&String> {
    match change {
        Change::Added { name, .. } => Some(name),
        Change::Removed { name, .. } => Some(name),
        Change::Modified { name, .. } => Some(name),
        Change::TypeChanged { name, .. } => Some(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::TarHeader;
    use crate::reader::TarEntry;

    fn make_entry(name: &str, size: u64, mtime: u64, content: &[u8]) -> TarEntry {
        TarEntry {
            header: TarHeader {
                name: name.to_string(),
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                size,
                mtime,
                checksum: 0,
                entry_type: EntryType::Regular,
                linkname: String::new(),
                format: crate::header::TarFormat::Ustar,
                uname: String::new(),
                gname: String::new(),
                devmajor: 0,
                devminor: 0,
                prefix: String::new(),
                pax_records: Vec::new(),
                checksum_valid: true,
            },
            content: content.to_vec(),
            raw_block: [0u8; 512],
            offset: 0,
        }
    }

    #[test]
    fn test_diff_identical_archives() {
        let entries1 = vec![
            make_entry("file1.txt", 10, 1000, b"content1!!!"),
            make_entry("file2.txt", 10, 2000, b"content2!!!"),
        ];
        let entries2 = vec![
            make_entry("file1.txt", 10, 1000, b"content1!!!"),
            make_entry("file2.txt", 10, 2000, b"content2!!!"),
        ];

        let result = diff_archives(&entries1, &entries2);
        assert_eq!(result.unchanged_count, 2);
        assert_eq!(result.added_count, 0);
        assert_eq!(result.removed_count, 0);
        assert_eq!(result.modified_count, 0);
    }

    #[test]
    fn test_diff_added_file() {
        let entries1 = vec![make_entry("file1.txt", 10, 1000, b"content1!!!")];
        let entries2 = vec![
            make_entry("file1.txt", 10, 1000, b"content1!!!"),
            make_entry("file2.txt", 20, 2000, b"content2_longer!!!"),
        ];

        let result = diff_archives(&entries1, &entries2);
        assert_eq!(result.added_count, 1);
        assert_eq!(result.unchanged_count, 1);
    }

    #[test]
    fn test_diff_removed_file() {
        let entries1 = vec![
            make_entry("file1.txt", 10, 1000, b"content1!!!"),
            make_entry("file2.txt", 20, 2000, b"content2_longer!!!"),
        ];
        let entries2 = vec![make_entry("file1.txt", 10, 1000, b"content1!!!")];

        let result = diff_archives(&entries1, &entries2);
        assert_eq!(result.removed_count, 1);
        assert_eq!(result.unchanged_count, 1);
    }

    #[test]
    fn test_diff_modified_file() {
        let entries1 = vec![make_entry("file1.txt", 10, 1000, b"old content")];
        let entries2 = vec![make_entry("file1.txt", 13, 2000, b"new content!")];

        let result = diff_archives(&entries1, &entries2);
        assert_eq!(result.modified_count, 1);
        assert_eq!(result.unchanged_count, 0);

        if let Some(Change::Modified {
            content_changed, ..
        }) = result.changes.first()
        {
            assert!(*content_changed);
        }
    }

    #[test]
    fn test_diff_empty_archives() {
        let result = diff_archives(&[], &[]);
        assert_eq!(result.unchanged_count, 0);
        assert!(result.changes.is_empty());
    }

    #[test]
    fn test_diff_all_added() {
        let entries2 = vec![
            make_entry("a.txt", 5, 1000, b"hello"),
            make_entry("b.txt", 5, 2000, b"world"),
        ];
        let result = diff_archives(&[], &entries2);
        assert_eq!(result.added_count, 2);
    }

    #[test]
    fn test_diff_all_removed() {
        let entries1 = vec![
            make_entry("a.txt", 5, 1000, b"hello"),
            make_entry("b.txt", 5, 2000, b"world"),
        ];
        let result = diff_archives(&entries1, &[]);
        assert_eq!(result.removed_count, 2);
    }
}
