use std::path::PathBuf;

#[derive(Debug)]
pub struct RegHive {
    pub path: Option<PathBuf>,
    pub base_block: RegHeader,
    pub root_key: Option<RegKey>,
    pub(crate) raw_data: Vec<u8>,
}

#[derive(Debug)]
pub struct RegHeader {
    pub signature: [u8; 4],
    pub sequence1: u32,
    pub sequence2: u32,
    pub last_written: u64,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,
    pub root_cell_offset: u32,
    pub hive_bins_data_size: u32,
}

#[derive(Debug, Clone)]
pub struct RegKey {
    pub name: String,
    pub last_written: u64,
    pub subkeys_count: u32,
    pub values_count: u32,
    pub subkeys: Vec<RegKey>,
    pub values: Vec<RegValue>,
    pub class_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegValue {
    pub name: String,
    pub value_type: RegValueType,
    pub data: Vec<u8>,
    pub(crate) location: Option<RegValueLoc>
}

#[derive(Debug, Clone)]
pub struct RegValueLoc {
    pub(crate) cell_offset: usize,
    pub(crate) data_offset: usize,
    pub(crate) data_size: u32,
    pub(crate) inline: bool
}

#[derive(Debug, Clone, PartialEq)]
pub enum RegValueType {
    None,
    String,
    ExpandString,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiString,
    ResourceList,
    Qword,
    Unknown(u32),
}

impl RegValueType {
    pub fn from(value: u32) -> Self {
        match value {
            0 => RegValueType::None,
            1 => RegValueType::String,
            2 => RegValueType::ExpandString,
            3 => RegValueType::Binary,
            4 => RegValueType::Dword,
            5 => RegValueType::DwordBigEndian,
            6 => RegValueType::Link,
            7 => RegValueType::MultiString,
            8 => RegValueType::ResourceList,
            11 => RegValueType::Qword,
            _ => RegValueType::Unknown(value),
        }
    }
}
