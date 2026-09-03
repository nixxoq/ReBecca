use crate::model::{RegHive, RegKey, RegValue, RegValueType};
use clap::{Parser, Subcommand, ValueEnum};
use log::{debug, info};
use serde::Serialize;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "rebecca")]
#[command(bin_name = "rebecca")]
#[command(
    about = "Windows NT Registry (REGF) manipulation, inspection, and verification tool",
    version,
    author
)]
pub struct Cli {
    /// Increase logging verbosity (-v for info, -vv for debug, -vvv for trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Display Base Block metadata, versions, timestamps, and checksums
    Info {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Output details in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Verify structural integrity of bins, cells, index trees, and checksums
    Validate {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Output result in JSON format
        #[arg(long)]
        json: bool,
    },

    /// List subkeys and values under a specific key path
    Ls {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path (default: root key)
        key_path: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Display a visual hierarchical ASCII key tree
    Tree {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path to start tree from (default: root key)
        key_path: Option<String>,
        /// Maximum recursion depth
        #[arg(short, long)]
        depth: Option<usize>,
        /// Also display values under each key
        #[arg(short, long)]
        values: bool,
        /// Output tree in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Read and display a value (or all values) in a key
    Get {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path
        key_path: String,
        /// Name of the value (if omitted, displays all values in the key)
        value_name: Option<String>,
        /// Output raw binary value to stdout
        #[arg(long)]
        raw: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },

    /// Create a brand-new valid empty Windows REGF hive from scratch
    New {
        /// Path to the output hive file
        output: PathBuf,
        /// Name of the root key (default: "ROOT")
        #[arg(long, default_value = "ROOT")]
        root_name: String,
    },

    /// Create a key path (automatically creating intermediate parents)
    CreateKey {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path to create
        key_path: String,
        /// Optional path to write the modified hive (default: in-place atomic commit)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Test creation without modifying file on disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Create or update a registry value
    Set {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path
        key_path: String,
        /// Value name
        value_name: String,
        /// Value data type
        #[arg(value_enum)]
        r#type: ValueTypeArg,
        /// Value data (hex string or @filename for binary, comma-separated for multi-string)
        value_data: String,
        /// Optional path to write the modified hive (default: in-place atomic commit)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Test mutation without writing to disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Shortcut to set a string value (REG_SZ)
    SetString {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path
        key_path: String,
        /// Value name
        value_name: String,
        /// String value
        value: String,
        /// Optional output path (default: in-place atomic commit)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Test mutation without writing to disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Shortcut to set a 32-bit integer value (REG_DWORD)
    SetDword {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path
        key_path: String,
        /// Value name
        value_name: String,
        /// 32-bit unsigned integer (decimal or 0x hex)
        value: String,
        /// Optional output path (default: in-place atomic commit)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Test mutation without writing to disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Shortcut to set a 64-bit integer value (REG_QWORD)
    SetQword {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path
        key_path: String,
        /// Value name
        value_name: String,
        /// 64-bit unsigned integer (decimal or 0x hex)
        value: String,
        /// Optional output path (default: in-place atomic commit)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Test mutation without writing to disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Shortcut to set binary data (REG_BINARY)
    SetBinary {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path
        key_path: String,
        /// Value name
        value_name: String,
        /// Hex string (e.g. "DEADBEEF" or "de ad be ef") or @filename to read from file
        data: String,
        /// Optional output path (default: in-place atomic commit)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Test mutation without writing to disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Shortcut to set a multi-string value (REG_MULTI_SZ)
    SetMulti {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path
        key_path: String,
        /// Value name
        value_name: String,
        /// List of strings
        values: Vec<String>,
        /// Optional output path (default: in-place atomic commit)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Test mutation without writing to disk
        #[arg(long)]
        dry_run: bool,
    },

    /// Export the registry tree and values to JSON or text format
    Export {
        /// Path to the registry hive file
        hive: PathBuf,
        /// Key path to export (default: root)
        key_path: Option<String>,
        /// Output format (json or text)
        #[arg(long, default_value = "json")]
        format: ExportFormat,
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ValueTypeArg {
    String,
    Sz,
    ExpandString,
    Dword,
    Qword,
    Binary,
    Hex,
    MultiString,
    Multi,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Text,
}

#[derive(Serialize)]
struct InfoJson {
    signature: String,
    major_version: u32,
    minor_version: u32,
    file_type: u32,
    sequence1: u32,
    sequence2: u32,
    last_written_filetime: u64,
    last_written_iso: String,
    root_cell_offset: u32,
    hive_bins_data_size: u32,
    file_size: usize,
    checksum_stored: u32,
    checksum_calculated: u32,
    checksum_valid: bool,
}

#[derive(Serialize)]
struct ValidateJson {
    valid: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct ValueJson {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    size_bytes: usize,
    value: serde_json::Value,
}

#[derive(Serialize)]
struct KeyListJson {
    key_path: String,
    subkeys: Vec<String>,
    values: Vec<ValueJson>,
}

#[derive(Serialize)]
struct TreeNodeJson {
    name: String,
    path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    values: Vec<ValueJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subkeys: Vec<TreeNodeJson>,
}

pub fn format_reg_type(vt: &RegValueType) -> &'static str {
    match vt {
        RegValueType::None => "REG_NONE",
        RegValueType::String => "REG_SZ",
        RegValueType::ExpandString => "REG_EXPAND_SZ",
        RegValueType::Binary => "REG_BINARY",
        RegValueType::Dword => "REG_DWORD",
        RegValueType::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
        RegValueType::Link => "REG_LINK",
        RegValueType::MultiString => "REG_MULTI_SZ",
        RegValueType::ResourceList => "REG_RESOURCE_LIST",
        RegValueType::Qword => "REG_QWORD",
        RegValueType::Unknown(_) => "REG_UNKNOWN",
    }
}

pub fn run() -> io::Result<()> {
    let cli = Cli::parse();

    let default_level = match (cli.quiet, cli.verbose) {
        (true, _) => log::LevelFilter::Error,
        (_, 0) => log::LevelFilter::Warn,
        (_, 1) => log::LevelFilter::Info,
        (_, 2) => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(default_level.as_str()),
    )
    .format_target(false)
    .format_timestamp_secs()
    .init();

    match cli.command {
        Commands::Info { hive, json } => handle_info(&hive, json),
        Commands::Validate { hive, json } => handle_validate(&hive, json),
        Commands::Ls {
            hive,
            key_path,
            json,
        } => handle_ls(&hive, key_path.as_deref(), json),
        Commands::Tree {
            hive,
            key_path,
            depth,
            values,
            json,
        } => handle_tree(&hive, key_path.as_deref(), depth, values, json),
        Commands::Get {
            hive,
            key_path,
            value_name,
            raw,
            json,
        } => handle_get(&hive, &key_path, value_name.as_deref(), raw, json),
        Commands::New { output, root_name } => handle_new(&output, &root_name),
        Commands::CreateKey {
            hive,
            key_path,
            output,
            dry_run,
        } => handle_create_key(&hive, &key_path, output.as_deref(), dry_run),
        Commands::Set {
            hive,
            key_path,
            value_name,
            r#type,
            value_data,
            output,
            dry_run,
        } => handle_set(
            &hive,
            &key_path,
            &value_name,
            r#type,
            &value_data,
            output.as_deref(),
            dry_run,
        ),
        Commands::SetString {
            hive,
            key_path,
            value_name,
            value,
            output,
            dry_run,
        } => handle_set_string(
            &hive,
            &key_path,
            &value_name,
            &value,
            output.as_deref(),
            dry_run,
        ),
        Commands::SetDword {
            hive,
            key_path,
            value_name,
            value,
            output,
            dry_run,
        } => handle_set_dword(
            &hive,
            &key_path,
            &value_name,
            &value,
            output.as_deref(),
            dry_run,
        ),
        Commands::SetQword {
            hive,
            key_path,
            value_name,
            value,
            output,
            dry_run,
        } => handle_set_qword(
            &hive,
            &key_path,
            &value_name,
            &value,
            output.as_deref(),
            dry_run,
        ),
        Commands::SetBinary {
            hive,
            key_path,
            value_name,
            data,
            output,
            dry_run,
        } => handle_set_binary(
            &hive,
            &key_path,
            &value_name,
            &data,
            output.as_deref(),
            dry_run,
        ),
        Commands::SetMulti {
            hive,
            key_path,
            value_name,
            values,
            output,
            dry_run,
        } => handle_set_multi(
            &hive,
            &key_path,
            &value_name,
            &values,
            output.as_deref(),
            dry_run,
        ),
        Commands::Export {
            hive,
            key_path,
            format,
            output,
        } => handle_export(&hive, key_path.as_deref(), format, output.as_deref()),
    }
}

fn handle_info(hive_path: &Path, json: bool) -> io::Result<()> {
    info!("Reading hive header: {}", hive_path.display());
    let hive = RegHive::from(hive_path)?;
    let bb = &hive.base_block;
    let raw = hive.raw_data();

    let mut calculated_chk = 0u32;
    if raw.len() >= 508 {
        for chunk in raw[0..508].as_chunks::<4>().0 {
            calculated_chk ^= u32::from_le_bytes(*chunk);
        }
    }
    let stored_chk = if raw.len() >= 512 {
        u32::from_le_bytes(raw[508..512].try_into().unwrap_or_default())
    } else {
        0
    };
    let chk_valid = stored_chk == calculated_chk;
    let iso_time = format_filetime(bb.last_written);

    debug!(
        "Sequence: seq1={}, seq2={}, root_cell_offset=0x{:X}",
        bb.sequence1, bb.sequence2, bb.root_cell_offset
    );

    if json {
        let out = InfoJson {
            signature: String::from_utf8_lossy(&bb.signature).to_string(),
            major_version: bb.major_version,
            minor_version: bb.minor_version,
            file_type: bb.file_type,
            sequence1: bb.sequence1,
            sequence2: bb.sequence2,
            last_written_filetime: bb.last_written,
            last_written_iso: iso_time,
            root_cell_offset: bb.root_cell_offset,
            hive_bins_data_size: bb.hive_bins_data_size,
            file_size: raw.len(),
            checksum_stored: stored_chk,
            checksum_calculated: calculated_chk,
            checksum_valid: chk_valid,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("File:               {}", hive_path.display());
        println!(
            "Signature:          {}",
            String::from_utf8_lossy(&bb.signature)
        );
        println!(
            "Format Version:     {}.{}",
            bb.major_version, bb.minor_version
        );
        println!("File Type:          Primary ({})", bb.file_type);
        println!(
            "Sequence Numbers:   {} / {}{}",
            bb.sequence1,
            bb.sequence2,
            if bb.sequence1 == bb.sequence2 {
                " (Synchronized)"
            } else {
                " (Mismatch)"
            }
        );
        println!(
            "Last Written:       {} (FILETIME: {})",
            iso_time, bb.last_written
        );
        println!(
            "Root Cell Offset:   0x{:08X} (File offset: 0x{:08X})",
            bb.root_cell_offset,
            4096 + bb.root_cell_offset
        );
        println!(
            "Hive Bins Size:     {} bytes (0x{:X})",
            bb.hive_bins_data_size, bb.hive_bins_data_size
        );
        println!("Total File Size:    {} bytes", raw.len());
        println!(
            "Checksum:           0x{:08X} ({})",
            stored_chk,
            if chk_valid { "VALID" } else { "INVALID" }
        );
    }

    Ok(())
}

fn handle_validate(hive_path: &Path, json: bool) -> io::Result<()> {
    info!("Validating structural integrity: {}", hive_path.display());
    let hive = RegHive::from(hive_path)?;
    let result = hive.validate();

    if json {
        let out = match &result {
            Ok(_) => ValidateJson {
                valid: true,
                error: None,
            },
            Err(e) => ValidateJson {
                valid: false,
                error: Some(e.to_string()),
            },
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        match &result {
            Ok(_) => println!(
                "Validation succeeded: hive '{}' is structurally valid.",
                hive_path.display()
            ),
            Err(e) => {
                eprintln!("Validation error for '{}': {}", hive_path.display(), e);
                return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
            }
        }
    }

    Ok(())
}

fn handle_ls(hive_path: &Path, key_path: Option<&str>, json: bool) -> io::Result<()> {
    info!("Listing key in: {}", hive_path.display());
    let hive = RegHive::from(hive_path)?;
    let target_path = key_path.unwrap_or("");
    let key = hive.find_key(target_path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key not found: '{}'", target_path),
        )
    })?;

    if json {
        let subkeys: Vec<String> = key.subkeys.iter().map(|k| k.name.clone()).collect();
        let values: Vec<ValueJson> = key.values.iter().map(value_to_json).collect();
        let out = KeyListJson {
            key_path: target_path.to_string(),
            subkeys,
            values,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "Key: {}",
            if target_path.is_empty() {
                &key.name
            } else {
                target_path
            }
        );
        if !key.subkeys.is_empty() {
            println!("\nSubkeys ({}):", key.subkeys.len());
            for sk in &key.subkeys {
                println!("  {}", sk.name);
            }
        } else {
            println!("\nSubkeys: (none)");
        }

        if !key.values.is_empty() {
            println!("\nValues ({}):", key.values.len());
            for v in &key.values {
                println!(
                    "  {:<24} [{:<14}] {}",
                    v.name,
                    format_reg_type(&v.value_type),
                    format_value_preview(v)
                );
            }
        } else {
            println!("Values:  (none)");
        }
    }

    Ok(())
}

fn handle_tree(
    hive_path: &Path,
    key_path: Option<&str>,
    max_depth: Option<usize>,
    include_values: bool,
    json: bool,
) -> io::Result<()> {
    info!("Rendering tree for: {}", hive_path.display());
    let hive = RegHive::from(hive_path)?;
    let target_path = key_path.unwrap_or("");
    let key = hive.find_key(target_path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key not found: '{}'", target_path),
        )
    })?;

    if json {
        let tree = build_tree_json(
            key,
            target_path,
            0,
            max_depth.unwrap_or(usize::MAX),
            include_values,
        );
        println!("{}", serde_json::to_string_pretty(&tree)?);
    } else {
        println!(
            "{}",
            if target_path.is_empty() {
                &key.name
            } else {
                target_path
            }
        );
        print_tree_ascii(key, "", 0, max_depth.unwrap_or(usize::MAX), include_values);
    }

    Ok(())
}

fn handle_get(
    hive_path: &Path,
    key_path: &str,
    value_name: Option<&str>,
    raw: bool,
    json: bool,
) -> io::Result<()> {
    info!("Querying values in '{}': {}", key_path, hive_path.display());
    let hive = RegHive::from(hive_path)?;
    let key = hive.find_key(key_path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key not found: '{}'", key_path),
        )
    })?;

    match value_name {
        Some(vname) => {
            let val = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(vname))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Value '{}' not found in key '{}'", vname, key_path),
                    )
                })?;

            if raw {
                io::stdout().write_all(&val.data)?;
                io::stdout().flush()?;
            } else if json {
                let out = value_to_json(val);
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("{}", format_value_full(val));
            }
        }
        None => {
            if json {
                let out: Vec<ValueJson> = key.values.iter().map(value_to_json).collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Values in key '{}':", key_path);
                for val in &key.values {
                    println!(
                        "  {:<24} [{:<14}] {}",
                        val.name,
                        format_reg_type(&val.value_type),
                        format_value_preview(val)
                    );
                }
            }
        }
    }

    Ok(())
}

fn handle_new(output: &Path, root_name: &str) -> io::Result<()> {
    info!(
        "Creating new hive at '{}' with root '{}'",
        output.display(),
        root_name
    );
    let mut hive = RegHive::new_empty_with_name(root_name)?;
    hive.save_to(output)?;
    println!(
        "Created new empty hive at '{}' with root key '{}'.",
        output.display(),
        root_name
    );
    Ok(())
}

fn handle_create_key(
    hive_path: &Path,
    key_path: &str,
    output: Option<&Path>,
    dry_run: bool,
) -> io::Result<()> {
    info!("Opening hive for key creation: {}", hive_path.display());
    let mut hive = RegHive::from(hive_path)?;
    hive.create_key(key_path)?;
    hive.validate()?;

    if dry_run {
        println!("Dry run: verified creation of key '{}'.", key_path);
    } else {
        save_hive_mutation(&mut hive, hive_path, output)?;
        println!("Created key '{}'.", key_path);
    }

    Ok(())
}

fn handle_set(
    hive_path: &Path,
    key_path: &str,
    value_name: &str,
    r#type: ValueTypeArg,
    value_data: &str,
    output: Option<&Path>,
    dry_run: bool,
) -> io::Result<()> {
    match r#type {
        ValueTypeArg::String | ValueTypeArg::Sz => {
            handle_set_string(hive_path, key_path, value_name, value_data, output, dry_run)
        }
        ValueTypeArg::ExpandString => {
            info!("Setting REG_EXPAND_SZ '{}' in '{}'", value_name, key_path);
            let mut hive = RegHive::from(hive_path)?;
            let u16_data: Vec<u8> = value_data
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(|c| c.to_le_bytes())
                .collect();
            hive.set_value(key_path, value_name, RegValueType::ExpandString, &u16_data)?;
            hive.validate()?;
            if dry_run {
                println!(
                    "Dry run: verified REG_EXPAND_SZ value '{}' on '{}'.",
                    value_name, key_path
                );
            } else {
                save_hive_mutation(&mut hive, hive_path, output)?;
                println!(
                    "Set REG_EXPAND_SZ value '{}' = \"{}\" on '{}'.",
                    value_name, value_data, key_path
                );
            }
            Ok(())
        }
        ValueTypeArg::Dword => {
            handle_set_dword(hive_path, key_path, value_name, value_data, output, dry_run)
        }
        ValueTypeArg::Qword => {
            handle_set_qword(hive_path, key_path, value_name, value_data, output, dry_run)
        }
        ValueTypeArg::Binary | ValueTypeArg::Hex => {
            handle_set_binary(hive_path, key_path, value_name, value_data, output, dry_run)
        }
        ValueTypeArg::MultiString | ValueTypeArg::Multi => {
            let parts: Vec<&str> = value_data.split(',').map(|s| s.trim()).collect();
            handle_set_multi(hive_path, key_path, value_name, &parts, output, dry_run)
        }
    }
}

fn handle_set_string(
    hive_path: &Path,
    key_path: &str,
    value_name: &str,
    value: &str,
    output: Option<&Path>,
    dry_run: bool,
) -> io::Result<()> {
    info!("Setting REG_SZ '{}' in '{}'", value_name, key_path);
    let mut hive = RegHive::from(hive_path)?;
    hive.set_string(key_path, value_name, value)?;
    hive.validate()?;

    if dry_run {
        println!(
            "Dry run: verified REG_SZ value '{}' on '{}'.",
            value_name, key_path
        );
    } else {
        save_hive_mutation(&mut hive, hive_path, output)?;
        println!(
            "Set REG_SZ value '{}' = \"{}\" on '{}'.",
            value_name, value, key_path
        );
    }

    Ok(())
}

fn handle_set_dword(
    hive_path: &Path,
    key_path: &str,
    value_name: &str,
    value_str: &str,
    output: Option<&Path>,
    dry_run: bool,
) -> io::Result<()> {
    let dword_val = parse_int_u32(value_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid DWORD integer '{}': {}", value_str, e),
        )
    })?;

    info!(
        "Setting REG_DWORD '{}' = {} in '{}'",
        value_name, dword_val, key_path
    );
    let mut hive = RegHive::from(hive_path)?;
    hive.set_dword(key_path, value_name, dword_val)?;
    hive.validate()?;

    if dry_run {
        println!(
            "Dry run: verified REG_DWORD value '{}' on '{}'.",
            value_name, key_path
        );
    } else {
        save_hive_mutation(&mut hive, hive_path, output)?;
        println!(
            "Set REG_DWORD value '{}' = {} (0x{:08X}) on '{}'.",
            value_name, dword_val, dword_val, key_path
        );
    }

    Ok(())
}

fn handle_set_qword(
    hive_path: &Path,
    key_path: &str,
    value_name: &str,
    value_str: &str,
    output: Option<&Path>,
    dry_run: bool,
) -> io::Result<()> {
    let qword_val = parse_int_u64(value_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid QWORD integer '{}': {}", value_str, e),
        )
    })?;

    info!(
        "Setting REG_QWORD '{}' = {} in '{}'",
        value_name, qword_val, key_path
    );
    let mut hive = RegHive::from(hive_path)?;
    hive.set_qword(key_path, value_name, qword_val)?;
    hive.validate()?;

    if dry_run {
        println!(
            "Dry run: verified REG_QWORD value '{}' on '{}'.",
            value_name, key_path
        );
    } else {
        save_hive_mutation(&mut hive, hive_path, output)?;
        println!(
            "Set REG_QWORD value '{}' = {} (0x{:016X}) on '{}'.",
            value_name, qword_val, qword_val, key_path
        );
    }

    Ok(())
}

fn handle_set_binary(
    hive_path: &Path,
    key_path: &str,
    value_name: &str,
    data_spec: &str,
    output: Option<&Path>,
    dry_run: bool,
) -> io::Result<()> {
    let binary_data = if let Some(stripped) = data_spec.strip_prefix('@') {
        info!("Reading binary payload from file: {}", stripped);
        fs::read(stripped)?
    } else {
        parse_hex_string(data_spec)?
    };

    info!(
        "Setting REG_BINARY '{}' ({} bytes) in '{}'",
        value_name,
        binary_data.len(),
        key_path
    );
    let mut hive = RegHive::from(hive_path)?;
    hive.set_binary(key_path, value_name, &binary_data)?;
    hive.validate()?;

    if dry_run {
        println!(
            "Dry run: verified REG_BINARY value '{}' ({} bytes) on '{}'.",
            value_name,
            binary_data.len(),
            key_path
        );
    } else {
        save_hive_mutation(&mut hive, hive_path, output)?;
        println!(
            "Set REG_BINARY value '{}' ({} bytes) on '{}'.",
            value_name,
            binary_data.len(),
            key_path
        );
    }

    Ok(())
}

fn handle_set_multi<S: AsRef<str>>(
    hive_path: &Path,
    key_path: &str,
    value_name: &str,
    values: &[S],
    output: Option<&Path>,
    dry_run: bool,
) -> io::Result<()> {
    info!(
        "Setting REG_MULTI_SZ '{}' ({} entries) in '{}'",
        value_name,
        values.len(),
        key_path
    );
    let mut hive = RegHive::from(hive_path)?;
    hive.set_multi_string(key_path, value_name, values)?;
    hive.validate()?;

    if dry_run {
        println!(
            "Dry run: verified REG_MULTI_SZ value '{}' ({} entries) on '{}'.",
            value_name,
            values.len(),
            key_path
        );
    } else {
        save_hive_mutation(&mut hive, hive_path, output)?;
        println!(
            "Set REG_MULTI_SZ value '{}' ({} entries) on '{}'.",
            value_name,
            values.len(),
            key_path
        );
    }

    Ok(())
}

fn handle_export(
    hive_path: &Path,
    key_path: Option<&str>,
    format: ExportFormat,
    output: Option<&Path>,
) -> io::Result<()> {
    info!("Exporting hive: {}", hive_path.display());
    let hive = RegHive::from(hive_path)?;
    let target_path = key_path.unwrap_or("");
    let key = hive.find_key(target_path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("Key not found: '{}'", target_path),
        )
    })?;

    let rendered = match format {
        ExportFormat::Json => {
            let tree = build_tree_json(key, target_path, 0, usize::MAX, true);
            serde_json::to_string_pretty(&tree)?
        }
        ExportFormat::Text => {
            let mut buf = Vec::new();
            writeln!(buf, "; ReBecca Registry Hive Export")?;
            writeln!(buf, "; Hive: {}", hive_path.display())?;
            writeln!(
                buf,
                "; Target: {}\n",
                if target_path.is_empty() {
                    &key.name
                } else {
                    target_path
                }
            )?;
            render_text_export(key, target_path, &mut buf)?;
            String::from_utf8_lossy(&buf).to_string()
        }
    };

    if let Some(out_path) = output {
        fs::write(out_path, rendered)?;
        println!("Exported registry data to '{}'.", out_path.display());
    } else {
        println!("{}", rendered);
    }

    Ok(())
}

fn save_hive_mutation(
    hive: &mut RegHive,
    hive_path: &Path,
    output: Option<&Path>,
) -> io::Result<()> {
    if let Some(out) = output {
        info!("Saving mutation to destination file: {}", out.display());
        hive.save_to(out)?;
    } else {
        info!(
            "Performing atomic in-place commit on: {}",
            hive_path.display()
        );
        hive.commit()?;
    }
    Ok(())
}

fn parse_int_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u32>()
    }
}

fn parse_int_u64(s: &str) -> Result<u64, std::num::ParseIntError> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    }
}

fn parse_hex_string(s: &str) -> io::Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect();
    let hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);

    if !hex.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hex string length must be an even number of characters",
        ));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().as_chunks::<2>().0 {
        let byte_str = std::str::from_utf8(chunk)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let byte = u8::from_str_radix(byte_str, 16).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid hex byte '{}': {}", byte_str, e),
            )
        })?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn format_filetime(ft: u64) -> String {
    if ft == 0 {
        return "N/A".to_string();
    }
    const EPOCH_DIFFERENCE: u64 = 116_444_736_000_000_000;
    if ft < EPOCH_DIFFERENCE {
        return format!("Pre-1970 (FILETIME {})", ft);
    }
    let unix_secs = (ft - EPOCH_DIFFERENCE) / 10_000_000;
    let days = unix_secs / 86400;
    let rem_secs = unix_secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let secs = rem_secs % 60;

    let mut year = 1970i64;
    let mut d = days as i64;
    loop {
        let leap = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
            1
        } else {
            0
        };
        let days_in_year = 365 + leap;
        if d >= days_in_year {
            d -= days_in_year;
            year += 1;
        } else {
            let leap_b = leap == 1;
            let month_days = [
                31,
                if leap_b { 29 } else { 28 },
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
            let mut month = 1;
            for m_days in month_days {
                if d >= m_days {
                    d -= m_days;
                    month += 1;
                } else {
                    break;
                }
            }
            let day = d + 1;
            return format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                year, month, day, hours, mins, secs
            );
        }
    }
}

fn format_value_preview(val: &RegValue) -> String {
    match val.value_type {
        RegValueType::String | RegValueType::ExpandString => val
            .as_string()
            .map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "(invalid string)".to_string()),
        RegValueType::Dword => val
            .as_dword()
            .map(|d| format!("{} (0x{:08X})", d, d))
            .unwrap_or_else(|| "(invalid dword)".to_string()),
        RegValueType::Qword => val
            .as_qword()
            .map(|q| format!("{} (0x{:016X})", q, q))
            .unwrap_or_else(|| "(invalid qword)".to_string()),
        RegValueType::MultiString => val
            .as_multi_string()
            .map(|arr| format!("{:?}", arr))
            .unwrap_or_else(|| "(invalid multi-sz)".to_string()),
        RegValueType::Binary => {
            if val.data.len() <= 16 {
                format!("{:02X?}", val.data)
            } else {
                format!("{:02X?}... ({} bytes)", &val.data[..16], val.data.len())
            }
        }
        _ => format!("({} bytes)", val.data.len()),
    }
}

fn format_value_full(val: &RegValue) -> String {
    match val.value_type {
        RegValueType::String | RegValueType::ExpandString => val.as_string().unwrap_or_default(),
        RegValueType::Dword => val.as_dword().map(|d| d.to_string()).unwrap_or_default(),
        RegValueType::Qword => val.as_qword().map(|q| q.to_string()).unwrap_or_default(),
        RegValueType::MultiString => val
            .as_multi_string()
            .map(|arr| arr.join("\n"))
            .unwrap_or_default(),
        RegValueType::Binary => val
            .data
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" "),
        _ => format!("{:02X?}", val.data),
    }
}

fn value_to_json(val: &RegValue) -> ValueJson {
    let json_val = match val.value_type {
        RegValueType::String | RegValueType::ExpandString => {
            serde_json::Value::String(val.as_string().unwrap_or_default())
        }
        RegValueType::Dword => {
            serde_json::json!(val.as_dword().unwrap_or_default())
        }
        RegValueType::Qword => {
            serde_json::json!(val.as_qword().unwrap_or_default())
        }
        RegValueType::MultiString => {
            serde_json::json!(val.as_multi_string().unwrap_or_default())
        }
        RegValueType::Binary => {
            let hex = val
                .data
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join("");
            serde_json::json!({
                "hex": hex,
                "bytes": val.data
            })
        }
        _ => serde_json::json!(val.data),
    };

    ValueJson {
        name: val.name.clone(),
        value_type: format_reg_type(&val.value_type).to_string(),
        size_bytes: val.data.len(),
        value: json_val,
    }
}

fn print_tree_ascii(
    key: &RegKey,
    prefix: &str,
    current_depth: usize,
    max_depth: usize,
    include_values: bool,
) {
    if current_depth >= max_depth {
        return;
    }

    let mut entries: Vec<(&str, bool, Option<&RegValue>)> = Vec::new();
    for sk in &key.subkeys {
        entries.push((&sk.name, true, None));
    }
    if include_values {
        for val in &key.values {
            entries.push((&val.name, false, Some(val)));
        }
    }

    let total = entries.len();
    for (i, entry) in entries.iter().enumerate() {
        let is_last = i == total - 1;
        let branch = if is_last { "└── " } else { "├── " };
        let next_prefix = if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        };

        if entry.1 {
            println!("{}{}{}", prefix, branch, entry.0);
            if let Some(sub) = key.subkeys.iter().find(|k| k.name == entry.0) {
                print_tree_ascii(
                    sub,
                    &next_prefix,
                    current_depth + 1,
                    max_depth,
                    include_values,
                );
            }
        } else if let Some(val) = entry.2 {
            println!(
                "{}{}[{}] {} = {}",
                prefix,
                branch,
                format_reg_type(&val.value_type),
                val.name,
                format_value_preview(val)
            );
        }
    }
}

fn build_tree_json(
    key: &RegKey,
    current_path: &str,
    current_depth: usize,
    max_depth: usize,
    include_values: bool,
) -> TreeNodeJson {
    let values = if include_values {
        key.values.iter().map(value_to_json).collect()
    } else {
        Vec::new()
    };

    let mut subkeys = Vec::new();
    if current_depth < max_depth {
        for sk in &key.subkeys {
            let child_path = if current_path.is_empty() {
                sk.name.clone()
            } else {
                format!("{}\\{}", current_path, sk.name)
            };
            subkeys.push(build_tree_json(
                sk,
                &child_path,
                current_depth + 1,
                max_depth,
                include_values,
            ));
        }
    }

    TreeNodeJson {
        name: key.name.clone(),
        path: current_path.to_string(),
        values,
        subkeys,
    }
}

fn render_text_export(key: &RegKey, current_path: &str, out: &mut Vec<u8>) -> io::Result<()> {
    let full_path = if current_path.is_empty() {
        key.name.clone()
    } else {
        current_path.to_string()
    };

    writeln!(out, "[{}]", full_path)?;
    for v in &key.values {
        match v.value_type {
            RegValueType::String => {
                writeln!(
                    out,
                    "\"{}\"=\"{}\"",
                    v.name,
                    v.as_string().unwrap_or_default()
                )?;
            }
            RegValueType::Dword => {
                writeln!(
                    out,
                    "\"{}\"=dword:{:08x}",
                    v.name,
                    v.as_dword().unwrap_or_default()
                )?;
            }
            RegValueType::Binary => {
                let hex = v
                    .data
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(",");
                writeln!(out, "\"{}\"=hex:{}", v.name, hex)?;
            }
            _ => {
                writeln!(
                    out,
                    "\"{}\"={}:{}",
                    v.name,
                    format_reg_type(&v.value_type),
                    format_value_preview(v)
                )?;
            }
        }
    }
    writeln!(out)?;

    for sk in &key.subkeys {
        let child_path = format!("{}\\{}", full_path, sk.name);
        render_text_export(sk, &child_path, out)?;
    }

    Ok(())
}
