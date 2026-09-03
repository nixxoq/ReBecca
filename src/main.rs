pub mod constants;
pub mod model;
mod registry;

use crate::model::{RegHive, RegValueType};
use std::io::{self};

fn main() -> io::Result<()> {
    let mut hive = RegHive::from("SYSTEM_orig")?;

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

    // match hive.update_string_value("Setup", "CmdLine", "cmd.exe") {
    match hive.update_string_value(
        "Setup",
        "CmdLine",
        "THIS_IS_A_TEST_STRING_THAT_MUST_BE_LONGER_THAN_THE_EXISTING_REGISTRY_CELL_\
         0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
    ) {
        Ok(_) => println!("✓ Updated CmdLine"),
        Err(e) => println!("✗ Failed to update: {}", e),
    }

    println!("\nCreating key path and values (Software\\MyApp\\Config):");
    hive.create_key("Software\\MyApp\\Config")?;
    hive.set_string("Software\\MyApp\\Config", "Name", "Example")?;
    hive.set_dword("Software\\MyApp\\Config", "Enabled", 1)?;
    hive.set_binary("Software\\MyApp\\Config", "Blob", &[0xDE, 0xAD, 0xBE, 0xEF])?;
    println!("✓ Created Software\\MyApp\\Config with Name, Enabled, and Blob");

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

    if let Some(key) = hive.find_key("Software\\MyApp\\Config") {
        println!("\nSoftware\\MyApp\\Config values:");
        for v in &key.values {
            match &v.value_type {
                RegValueType::String => println!("  {} = \"{}\"", v.name, v.as_string().unwrap()),
                RegValueType::Dword => println!("  {} = {}", v.name, v.as_dword().unwrap()),
                RegValueType::Binary => println!("  {} = {:02X?}", v.name, v.data),
                _ => println!("  {} = {:?}", v.name, v.value_type),
            }
        }
    }

    println!("\nCreating brand-new empty hive from scratch:");
    let mut new_hive = RegHive::new_empty()?;
    new_hive.create_key("Software\\MyApp\\Config")?;
    new_hive.set_string("Software\\MyApp\\Config", "Name", "ReBecca")?;
    new_hive.set_dword("Software\\MyApp\\Config", "Enabled", 1)?;
    new_hive.save_to("my_hive")?;
    println!("✓ Saved brand-new hive with keys and values to 'my_hive'");

    Ok(())
}
