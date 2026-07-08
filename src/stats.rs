//! Archive statistics — compute summary statistics for a tar archive.

use std::collections::HashMap;

use crate::header::{EntryType, TarFormat};
use crate::reader::TarEntry;

/// Statistics for a tar archive.
#[derive(Debug)]
pub struct ArchiveStats {
    pub total_entries: usize,
    pub file_count: usize,
    pub directory_count: usize,
    pub link_count: usize,
    pub other_count: usize,
    pub metadata_count: usize,
    pub total_uncompressed_size: u64,
    pub largest_file: Option<(String, u64)>,
    pub smallest_file: Option<(String, u64)>,
    pub average_file_size: f64,
    pub format: Option<TarFormat>,
    pub formats_detected: Vec<TarFormat>,
    pub entry_types: HashMap<String, usize>,
    pub top_largest_files: Vec<(String, u64)>,
}

/// Compute statistics for an archive.
pub fn compute_stats(entries: &[TarEntry]) -> ArchiveStats {
    let mut file_count = 0;
    let mut directory_count = 0;
    let mut link_count = 0;
    let mut other_count = 0;
    let mut metadata_count = 0;
    let mut total_size: u64 = 0;
    let mut largest: Option<(String, u64)> = None;
    let mut smallest: Option<(String, u64)> = None;
    let mut formats = Vec::new();
    let mut entry_types: HashMap<String, usize> = HashMap::new();
    let mut file_sizes: Vec<(String, u64)> = Vec::new();

    for entry in entries {
        let et = &entry.header.entry_type;
        let type_desc = et.description().to_string();
        *entry_types.entry(type_desc).or_insert(0) += 1;

        if et.is_metadata() {
            metadata_count += 1;
            continue;
        }

        if !formats.contains(&entry.header.format) {
            formats.push(entry.header.format);
        }

        match et {
            EntryType::Regular | EntryType::Contiguous => {
                file_count += 1;
                total_size += entry.header.size;
                file_sizes.push((entry.header.name.clone(), entry.header.size));

                if largest.is_none() || entry.header.size > largest.as_ref().unwrap().1 {
                    largest = Some((entry.header.name.clone(), entry.header.size));
                }
                if smallest.is_none() || entry.header.size < smallest.as_ref().unwrap().1 {
                    smallest = Some((entry.header.name.clone(), entry.header.size));
                }
            }
            EntryType::Directory => directory_count += 1,
            EntryType::HardLink | EntryType::Symlink => link_count += 1,
            _ => other_count += 1,
        }
    }

    // Sort files by size descending and take top 10.
    file_sizes.sort_by_key(|b| std::cmp::Reverse(b.1));
    let top_largest = file_sizes.into_iter().take(10).collect();

    let average = if file_count > 0 {
        total_size as f64 / file_count as f64
    } else {
        0.0
    };

    let total_entries = entries
        .iter()
        .filter(|e| !e.header.entry_type.is_metadata())
        .count();

    let format = formats.first().copied();

    ArchiveStats {
        total_entries,
        file_count,
        directory_count,
        link_count,
        other_count,
        metadata_count,
        total_uncompressed_size: total_size,
        largest_file: largest,
        smallest_file: smallest,
        average_file_size: average,
        format,
        formats_detected: formats,
        entry_types,
        top_largest_files: top_largest,
    }
}

/// Format a byte size as a human-readable string.
pub fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < 1024 * 1024 {
        format!("{:.2} KB", size as f64 / 1024.0)
    } else if size < 1024 * 1024 * 1024 {
        format!("{:.2} MB", size as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", size as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{EntryType, TarFormat, TarHeader};
    use crate::reader::TarEntry;

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
                uname: String::new(),
                gname: String::new(),
                devmajor: 0,
                devminor: 0,
                prefix: String::new(),
                pax_records: Vec::new(),
                checksum_valid: true,
            },
            content: Vec::new(),
            raw_block: [0u8; 512],
            offset: 0,
        }
    }

    #[test]
    fn test_stats_empty() {
        let stats = compute_stats(&[]);
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.file_count, 0);
    }

    #[test]
    fn test_stats_files() {
        let entries = vec![
            make_entry("a.txt", 100, EntryType::Regular),
            make_entry("b.txt", 200, EntryType::Regular),
            make_entry("c.txt", 300, EntryType::Regular),
        ];
        let stats = compute_stats(&entries);

        assert_eq!(stats.file_count, 3);
        assert_eq!(stats.total_uncompressed_size, 600);
        assert!((stats.average_file_size - 200.0).abs() < 0.01);
    }

    #[test]
    fn test_stats_largest_smallest() {
        let entries = vec![
            make_entry("small.txt", 10, EntryType::Regular),
            make_entry("large.txt", 1000, EntryType::Regular),
            make_entry("medium.txt", 100, EntryType::Regular),
        ];
        let stats = compute_stats(&entries);

        assert_eq!(stats.largest_file.as_ref().unwrap().0, "large.txt");
        assert_eq!(stats.largest_file.as_ref().unwrap().1, 1000);
        assert_eq!(stats.smallest_file.as_ref().unwrap().0, "small.txt");
        assert_eq!(stats.smallest_file.as_ref().unwrap().1, 10);
    }

    #[test]
    fn test_stats_mixed_types() {
        let entries = vec![
            make_entry("file.txt", 100, EntryType::Regular),
            make_entry("dir/", 0, EntryType::Directory),
            make_entry("link.txt", 0, EntryType::Symlink),
        ];
        let stats = compute_stats(&entries);

        assert_eq!(stats.file_count, 1);
        assert_eq!(stats.directory_count, 1);
        assert_eq!(stats.link_count, 1);
    }

    #[test]
    fn test_stats_top_largest() {
        let entries: Vec<TarEntry> = (0..15)
            .map(|i| make_entry(&format!("file{i}.txt"), (i + 1) * 100, EntryType::Regular))
            .collect();
        let stats = compute_stats(&entries);

        assert_eq!(stats.top_largest_files.len(), 10);
        // Should be sorted by size descending.
        assert_eq!(stats.top_largest_files[0].0, "file14.txt");
        assert_eq!(stats.top_largest_files[0].1, 1500);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1048576), "1.00 MB");
    }
}
