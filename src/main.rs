//! TarLens — Tar archive analysis toolkit.
//!
//! Inspect, verify, diff, and analyze tar archives with hand-written
//! binary format parsing supporting V7, USTAR, PAX, and GNU tar variants.

mod diff;
mod header;
mod inspect;
mod output;
mod reader;
mod stats;
mod verify;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "tarlens")]
#[command(version = "0.1.0")]
#[command(about = "Tar archive analysis toolkit — inspect, verify, diff, and analyze tar archives")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List archive contents with detailed metadata
    List {
        /// Archive file to read
        archive: PathBuf,
        /// Show long format with all metadata
        #[arg(short = 'l', long = "long")]
        long: bool,
        /// Output format (text, json)
        #[arg(short = 'f', long = "format", default_value = "text")]
        format: String,
        /// Filter by entry type (file, dir, link, etc.)
        #[arg(short = 't', long = "type")]
        entry_type: Option<String>,
    },
    /// Inspect raw header of the first entry or a specific entry
    Inspect {
        /// Archive file to read
        archive: PathBuf,
        /// Entry index to inspect (0-based)
        #[arg(short = 'n', long = "entry", default_value = "0")]
        entry: usize,
        /// Show hex dump of the raw header block
        #[arg(short = 'x', long = "hex")]
        hex: bool,
    },
    /// Verify archive integrity (checksums, structure)
    Verify {
        /// Archive file to verify
        archive: PathBuf,
        /// Output format (text, json)
        #[arg(short = 'f', long = "format", default_value = "text")]
        format: String,
    },
    /// Diff two archives and show changes
    Diff {
        /// First archive
        archive1: PathBuf,
        /// Second archive
        archive2: PathBuf,
        /// Output format (text, json)
        #[arg(short = 'f', long = "format", default_value = "text")]
        format: String,
    },
    /// Show archive statistics
    Stats {
        /// Archive file to analyze
        archive: PathBuf,
        /// Output format (text, json)
        #[arg(short = 'f', long = "format", default_value = "text")]
        format: String,
    },
    /// Detect the tar format variant
    Info {
        /// Archive file to analyze
        archive: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::List {
            archive,
            long,
            format,
            entry_type,
        } => list_command(&archive, long, &format, entry_type.as_deref()),
        Commands::Inspect {
            archive,
            entry,
            hex,
        } => inspect_command(&archive, entry, hex),
        Commands::Verify { archive, format } => verify_command(&archive, &format),
        Commands::Diff {
            archive1,
            archive2,
            format,
        } => diff_command(&archive1, &archive2, &format),
        Commands::Stats { archive, format } => stats_command(&archive, &format),
        Commands::Info { archive } => info_command(&archive),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn list_command(
    path: &Path,
    long: bool,
    format: &str,
    entry_type: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = reader::read_archive(path)?;
    let filtered: Vec<reader::TarEntry> = if let Some(type_filter) = entry_type {
        entries
            .into_iter()
            .filter(|e| matches_type(&e.header.entry_type, type_filter))
            .collect()
    } else {
        entries
    };
    let mut out = std::io::stdout().lock();
    if format == "json" {
        output::print_list_json(&mut out, &filtered)?;
    } else {
        output::print_list(&mut out, &filtered, long)?;
    }
    Ok(())
}

fn inspect_command(path: &Path, entry: usize, hex: bool) -> Result<(), Box<dyn std::error::Error>> {
    let raw_blocks = reader::read_raw_blocks(path)?;
    inspect::inspect_entry(&raw_blocks, entry, hex)?;
    Ok(())
}

fn verify_command(path: &Path, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entries = reader::read_archive(path)?;
    let report = verify::verify_archive(&entries);
    let mut out = std::io::stdout().lock();
    if format == "json" {
        output::print_verify_json(&mut out, &report)?;
    } else {
        output::print_verify(&mut out, &report)?;
    }
    Ok(())
}

fn diff_command(
    path1: &Path,
    path2: &Path,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries1 = reader::read_archive(path1)?;
    let entries2 = reader::read_archive(path2)?;
    let diff_result = diff::diff_archives(&entries1, &entries2);
    let mut out = std::io::stdout().lock();
    if format == "json" {
        output::print_diff_json(&mut out, &diff_result)?;
    } else {
        output::print_diff(&mut out, &diff_result, path1, path2)?;
    }
    Ok(())
}

fn stats_command(path: &Path, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entries = reader::read_archive(path)?;
    let stats = stats::compute_stats(&entries);
    let mut out = std::io::stdout().lock();
    if format == "json" {
        output::print_stats_json(&mut out, &stats)?;
    } else {
        output::print_stats(&mut out, &stats)?;
    }
    Ok(())
}

fn info_command(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let entries = reader::read_archive(path)?;
    let mut out = std::io::stdout().lock();
    output::print_info(&mut out, &entries, path)?;
    Ok(())
}

fn matches_type(entry_type: &header::EntryType, filter: &str) -> bool {
    match filter.to_lowercase().as_str() {
        "file" | "f" => entry_type.is_regular(),
        "dir" | "d" => entry_type.is_directory(),
        "link" | "l" => entry_type.is_link(),
        "symlink" => *entry_type == header::EntryType::Symlink,
        "hardlink" => *entry_type == header::EntryType::HardLink,
        "all" | "" => true,
        _ => false,
    }
}
