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
    pub location: Option<RegKeyLoc>,
}

impl RegKey {
    pub fn cell_offset(&self) -> Option<usize> {
        self.location.as_ref().map(|l| l.cell_offset)
    }

    pub fn location(&self) -> Option<&RegKeyLoc> {
        self.location.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct RegKeyLoc {
    pub cell_offset: usize,   // Absolute file offset in raw_data
    pub cell_size: usize,     // Total allocated cell size
    pub parent_offset: u32,   // Relative cell offset of parent NK (or MAX_OFFSET)
    pub subkeys_offset: u32,  // Relative cell offset of subkey index (or MAX_OFFSET)
    pub values_offset: u32,   // Relative cell offset of value list (or MAX_OFFSET)
    pub security_offset: u32, // Relative cell offset of security descriptor (or MAX_OFFSET)
    pub class_offset: u32,    // Relative cell offset of class name (or MAX_OFFSET)
    pub flags: u16,           // NK flags (KEY_COMP_NAME, etc.)
}

#[derive(Debug, Clone)]
pub struct RegValue {
    pub name: String,
    pub value_type: RegValueType,
    pub data: Vec<u8>,
    pub(crate) location: Option<RegValueLoc>,
}

#[derive(Debug, Clone)]
pub struct RegValueLoc {
    pub(crate) cell_offset: usize,
    pub(crate) data_offset: usize,
    pub(crate) data_size: u32,
    pub(crate) inline: bool,
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
    pub fn to_u32(&self) -> u32 {
        match self {
            RegValueType::None => 0,
            RegValueType::String => 1,
            RegValueType::ExpandString => 2,
            RegValueType::Binary => 3,
            RegValueType::Dword => 4,
            RegValueType::DwordBigEndian => 5,
            RegValueType::Link => 6,
            RegValueType::MultiString => 7,
            RegValueType::ResourceList => 8,
            RegValueType::Qword => 11,
            RegValueType::Unknown(value) => *value,
        }
    }

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
