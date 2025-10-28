pub mod constants;
pub mod model;
mod registry;

use crate::model::{RegHive, RegValueType};
use std::io::{self};

fn main() -> io::Result<()> {
    let mut hive = RegHive::from("SYSTEM_c")?;

    println!("Base Block:");
    println!(
        "  Signature: {}",
        String::from_utf8_lossy(&hive.base_block.signature)
    );
    println!("  Major Version: {}", hive.base_block.major_version);
    println!("  Minor Version: {}", hive.base_block.minor_version);
    println!(
        "  Root Cell Offset: 0x{:X}",
        hive.base_block.root_cell_offset
    );

    if let Some(key) = hive.find_key("Setup") {
        println!("\nkey: {}", key.name);
        println!("Values:");
        for value in &key.values {
            print!("  {} = ", value.name);
            match &value.value_type {
                RegValueType::String | RegValueType::ExpandString => {
                    if let Some(s) = value.as_string() {
                        println!("\"{}\"", s);
                    } else {
                        println!("(invalid string)");
                    }
                }
                RegValueType::Dword => {
                    if let Some(d) = value.as_dword() {
                        println!("0x{:08X}", d);
                    } else {
                        println!("(invalid dword)");
                    }
                }
                RegValueType::Binary => {
                    println!("{:02X?}", &value.data[..value.data.len().min(16)]);
                }
                _ => println!("({:?})", value.value_type),
            }
        }
    }

    println!("\nDword update (SystemSetupInProgress):");
    if hive
        .update_dword("Setup", "SystemSetupInProgress", 1)
        .is_ok()
    {
        println!("Updated");
    }

    println!("\nCmdLine update (reg_sz)");
    if let Some(key) = hive.find_key("Setup")
        && let Some(value) = key.values.iter().find(|v| v.name == "CmdLine")
    {
        println!("Before: CmdLine = {:?}", value.as_string());
        println!("  Data size: {} bytes", value.data.len());
        println!(
            "  Raw data: {:02X?}",
            &value.data[..value.data.len().min(32)]
        );
        if let Some(loc) = value.get_location_info() {
            println!("  Location: {}", loc);
        }
    }

    match hive.update_string_value("Setup", "CmdLine", "cmd.exe") {
        Ok(_) => println!("✓ Updated CmdLine"),
        Err(e) => println!("✗ Failed to update: {}", e),
    }

    println!("\nSaving changes");

    // hive.commit().expect("Failed to commit changes");
    hive.save_to("SYSTEM_mod")?;
    println!("Saved hive to SYSTEM_mod");
    //
    println!("\nVerifying");
    let hive = RegHive::from("SYSTEM_mod")?;
    if let Some(key) = hive.find_key("Setup")
        && let Some(value) = key.values.iter().find(|v| v.name == "CmdLine")
        && let Some(current) = value.as_string()
    {
        println!("Setup\\CmdLine = {}", current);
    }

    if let Some(key) = hive.find_key("Setup")
        && let Some(value) = key
            .values
            .iter()
            .find(|v| v.name == "SystemSetupInProgress")
        && let Some(current) = value.as_dword()
    {
        println!("Setup\\SystemSetupInProgress = {}", current);
    }

    Ok(())
}
