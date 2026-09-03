use crate::{
    constants::{
        BIG_DATA_THRESHOLD, DEFAULT_ROOT_KEY_NAME, INLINE_DATA_FLAG, MAX_OFFSET, MIN_REG_SIZE,
        REG_HEAD_OFFSET, SIGNATURE_BIG_DATA, SIGNATURE_LEAF, SIGNATURE_LEAF_HASH_1,
        SIGNATURE_LEAF_HASH_2, SIGNATURE_ROOT_INDEX,
    },
    model::{RegHeader, RegHive, RegKey, RegKeyLoc, RegValue, RegValueLoc, RegValueType},
    registry::allocator::{self, create_empty_hive, read_value_data},
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

impl RegHive {
    pub fn from<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path.as_ref())?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let mut hive = Self::parse(&data)?;
        hive.path = Some(path.as_ref().to_path_buf());

        Ok(hive)
    }

    /// Creates a completely new, valid empty Windows REGF registry hive with the default root name ("ROOT").
    pub fn new_empty() -> io::Result<Self> {
        Self::new_empty_with_name(DEFAULT_ROOT_KEY_NAME)
    }

    /// Creates a completely new, valid empty Windows REGF registry hive with a custom root key name.
    pub fn new_empty_with_name(root_name: &str) -> io::Result<Self> {
        let (_base_block, raw_data) = create_empty_hive(root_name)?;
        Self::parse(&raw_data)
    }

    pub fn root_key(&self) -> Option<&RegKey> {
        self.root_key.as_ref()
    }

    pub fn parse(data: &[u8]) -> io::Result<Self> {
        if data.len() < REG_HEAD_OFFSET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "File too small"));
        }

        let base_block = RegHeader::parse(&data[0..REG_HEAD_OFFSET])?;

        let root_key = if base_block.root_cell_offset > 0 {
            Some(Self::parse_key(
                data,
                ((REG_HEAD_OFFSET as u32) + base_block.root_cell_offset) as usize,
                0,
            )?)
        } else {
            None
        };

        Ok(RegHive {
            base_block,
            root_key,
            raw_data: data.to_vec(),
            path: None,
        })
    }

    fn parse_key(data: &[u8], offset: usize, depth: u32) -> io::Result<RegKey> {
        if depth > MIN_REG_SIZE as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Max depth exceeded",
            ));
        }

        // EOF check
        if offset + 4 > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Invalid offset",
            ));
        }

        let cell_size = i32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
        .unsigned_abs() as usize;

        if offset + cell_size > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Cell size exceeds data",
            ));
        }

        let cell_data = &data[offset + 4..offset + 4 + cell_size - 4];

        // Node key check
        if cell_data.len() < 2 || &cell_data[0..2] != b"nk" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid NK signature",
            ));
        } else if cell_data.len() < 0x4C {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NK cell too small",
            ));
        }

        let last_written = u64::from_le_bytes([
            cell_data[4],
            cell_data[5],
            cell_data[6],
            cell_data[7],
            cell_data[8],
            cell_data[9],
            cell_data[10],
            cell_data[11],
        ]);

        let flags = u16::from_le_bytes([cell_data[2], cell_data[3]]);
        let parent_offset = u32::from_le_bytes([
            cell_data[0x10],
            cell_data[0x11],
            cell_data[0x12],
            cell_data[0x13],
        ]);
        let (subkeys_count, subkeys_offset) = (
            u32::from_le_bytes([
                cell_data[0x14],
                cell_data[0x15],
                cell_data[0x16],
                cell_data[0x17],
            ]),
            u32::from_le_bytes([
                cell_data[0x1C],
                cell_data[0x1D],
                cell_data[0x1E],
                cell_data[0x1F],
            ]),
        );

        let (values_count, values_offset) = (
            u32::from_le_bytes([
                cell_data[0x24],
                cell_data[0x25],
                cell_data[0x26],
                cell_data[0x27],
            ]),
            u32::from_le_bytes([
                cell_data[0x28],
                cell_data[0x29],
                cell_data[0x2A],
                cell_data[0x2B],
            ]),
        );

        let security_offset = u32::from_le_bytes([
            cell_data[0x2C],
            cell_data[0x2D],
            cell_data[0x2E],
            cell_data[0x2F],
        ]);

        let class_offset = u32::from_le_bytes([
            cell_data[0x30],
            cell_data[0x31],
            cell_data[0x32],
            cell_data[0x33],
        ]);

        let name_length = u16::from_le_bytes([cell_data[0x48], cell_data[0x49]]) as usize;
        let name = if name_length > 0 && cell_data.len() >= 0x4C + name_length {
            let name_bytes = &cell_data[0x4C..0x4C + name_length];
            if (flags & 0x0020) != 0 {
                String::from_utf8_lossy(name_bytes).to_string()
            } else {
                let utf16: Vec<u16> = name_bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                String::from_utf16_lossy(&utf16)
            }
        } else {
            String::new()
        };

        let mut subkeys = Vec::new();
        if subkeys_count > 0
            && subkeys_offset != MAX_OFFSET
            && subkeys_offset > 0
            && let Ok(offsets) =
                Self::parse_subkey_list(data, REG_HEAD_OFFSET + subkeys_offset as usize)
        {
            for subkey_offset in offsets.iter().take(subkeys_count as usize) {
                if let Ok(subkey) =
                    Self::parse_key(data, REG_HEAD_OFFSET + *subkey_offset as usize, depth + 1)
                {
                    subkeys.push(subkey);
                }
            }
        }

        let values: Vec<RegValue> = if values_count > 0
            && values_offset != MAX_OFFSET
            && values_offset > 0
            && let Ok(value_offsets) =
                Self::parse_value_list(data, REG_HEAD_OFFSET + values_offset as usize, values_count)
        {
            value_offsets
                .iter()
                .map(|&offset| Self::parse_value(data, REG_HEAD_OFFSET + offset as usize, true))
                .filter_map(Result::ok)
                .collect()
        } else {
            Vec::new()
        };

        let location = Some(RegKeyLoc {
            cell_offset: offset,
            cell_size,
            parent_offset,
            subkeys_offset,
            values_offset,
            security_offset,
            class_offset,
            flags,
        });

        Ok(RegKey {
            name,
            last_written,
            subkeys_count,
            values_count,
            subkeys,
            values,
            class_name: None,
            location,
        })
    }

    fn parse_subkey_list(data: &[u8], offset: usize) -> io::Result<Vec<u32>> {
        if offset + 8 > data.len() {
            return Ok(Vec::new());
        }

        let cell_data = &data[offset + 4..];
        if cell_data.len() < 2 {
            return Ok(Vec::new());
        }

        let signature = &cell_data[0..2];
        let mut offsets = Vec::new();

        match signature {
            SIGNATURE_LEAF_HASH_1 | SIGNATURE_LEAF_HASH_2 => {
                // Leaf with hash
                if cell_data.len() < 4 {
                    return Ok(Vec::new());
                }

                let cell_values = u16::from_le_bytes([cell_data[2], cell_data[3]]) as usize;

                for i in 0..cell_values {
                    let offset = 4 + i * 8;
                    if offset + 4 > cell_data.len() {
                        continue;
                    }

                    let subkey_offset = u32::from_le_bytes([
                        cell_data[offset],
                        cell_data[offset + 1],
                        cell_data[offset + 2],
                        cell_data[offset + 3],
                    ]);
                    offsets.push(subkey_offset);
                }
            }
            SIGNATURE_LEAF => {
                // Leaf without hash
                if cell_data.len() < 4 {
                    return Ok(Vec::new());
                }
                let cell_values = u16::from_le_bytes([cell_data[2], cell_data[3]]) as usize;

                for i in 0..cell_values {
                    let offset = 4 + i * 4;
                    if offset + 4 > cell_data.len() {
                        continue;
                    }

                    let subkey_offset = u32::from_le_bytes([
                        cell_data[offset],
                        cell_data[offset + 1],
                        cell_data[offset + 2],
                        cell_data[offset + 3],
                    ]);
                    offsets.push(subkey_offset);
                }
            }
            SIGNATURE_ROOT_INDEX => {
                if cell_data.len() < 4 {
                    return Ok(Vec::new());
                }
                let cell_values = u16::from_le_bytes([cell_data[2], cell_data[3]]) as usize;

                for i in 0..cell_values {
                    let offset = 4 + i * 4;
                    if offset + 4 <= cell_data.len() {
                        let list_offset = u32::from_le_bytes([
                            cell_data[offset],
                            cell_data[offset + 1],
                            cell_data[offset + 2],
                            cell_data[offset + 3],
                        ]);
                        if let Ok(mut sub_offsets) =
                            Self::parse_subkey_list(data, 4096 + list_offset as usize)
                        {
                            offsets.append(&mut sub_offsets);
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(offsets)
    }

    fn parse_value_list(data: &[u8], offset: usize, count: u32) -> io::Result<Vec<u32>> {
        if offset + 4 > data.len() {
            return Ok(Vec::new());
        }

        let mut offsets = Vec::new();

        for i in 0..count as usize {
            let entries = offset + 4 + i * 4;

            if entries + 4 <= data.len() {
                let value_offset = u32::from_le_bytes([
                    data[entries],
                    data[entries + 1],
                    data[entries + 2],
                    data[entries + 3],
                ]);
                offsets.push(value_offset);
            }
        }

        Ok(offsets)
    }

    fn parse_value(data: &[u8], offset: usize, track_loc: bool) -> io::Result<RegValue> {
        if offset + 8 > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Invalid value offset",
            ));
        }

        let cell_data = &data[offset + 4..];

        if cell_data.len() < 2 || &cell_data[0..2] != b"vk" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid value key signature",
            ));
        } else if cell_data.len() < 0x14 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Value Key cell too small",
            ));
        }

        // VK (Value Key):
        // ==================================
        // - 0x00: signature "vk" (2 bytes) =
        // - 0x02: name_length (2 bytes)    =
        // - 0x04: data_size (4 bytes)      =
        // - 0x08: data_offset (4 bytes)    =
        // - 0x0C: value_type (4 bytes)     =
        // - 0x10: flags (2 bytes)          =
        // - 0x12: unused/padding (2 bytes) =
        // - 0x14: name (variable length)   =
        // ==================================

        let (name_length, data_size, data_offset, value_type) = (
            u16::from_le_bytes([cell_data[2], cell_data[3]]) as usize,
            u32::from_le_bytes([cell_data[4], cell_data[5], cell_data[6], cell_data[7]]),
            u32::from_le_bytes([cell_data[8], cell_data[9], cell_data[10], cell_data[11]]),
            u32::from_le_bytes([cell_data[12], cell_data[13], cell_data[14], cell_data[15]]),
        );

        let name = if name_length > 0 && cell_data.len() >= 0x14 + name_length {
            let name_bytes = &cell_data[0x14..0x14 + name_length];

            String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string()
        } else {
            String::from("(Default)") // default reg value
        };

        let (value_data, location) = if data_size & INLINE_DATA_FLAG != 0 {
            let size = (data_size & !INLINE_DATA_FLAG) as usize;
            let offset_b = data_offset.to_le_bytes();
            let loc = if track_loc {
                Some(RegValueLoc {
                    cell_offset: offset,
                    data_offset: offset + 4 + 8,
                    data_size: size as u32,
                    inline: true,
                })
            } else {
                None
            };
            (offset_b.get(..size).unwrap_or_default().to_vec(), loc)
        } else if data_offset > 0 && data_offset != MAX_OFFSET {
            let real_offset = REG_HEAD_OFFSET + data_offset as usize;
            let result = read_value_data(data, data_size, data_offset)?;

            let loc = if track_loc {
                Some(RegValueLoc {
                    cell_offset: offset,
                    data_offset: real_offset,
                    data_size,
                    inline: false,
                })
            } else {
                None
            };

            (result, loc)
        } else {
            (Vec::new(), None)
        };

        Ok(RegValue {
            name,
            value_type: RegValueType::from(value_type),
            data: value_data,
            location,
        })
    }

    pub fn find_key(&self, path: &str) -> Option<&RegKey> {
        let root = self.root_key.as_ref()?;
        let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Some(root);
        }
        let parts_slice = if parts[0].eq_ignore_ascii_case(&root.name) {
            &parts[1..]
        } else {
            &parts[..]
        };

        parts_slice.iter().try_fold(root, |key, &part| {
            key.subkeys
                .iter()
                .find(|subkey| subkey.name.eq_ignore_ascii_case(part))
        })
    }

    pub fn find_key_mut(&mut self, key_path: &str) -> Option<&mut RegKey> {
        let parts: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
        let current_key = self.root_key.as_mut()?;
        if parts.is_empty() {
            return Some(current_key);
        }

        let skip_root = parts[0].eq_ignore_ascii_case(&current_key.name);
        let mut key = current_key;
        let iter = if skip_root { &parts[1..] } else { &parts[..] };

        for part in iter {
            key = key
                .subkeys
                .iter_mut()
                .find(|sk| sk.name.eq_ignore_ascii_case(part))?;
        }
        Some(key)
    }

    pub fn create_child_key(&mut self, parent_path: &str, child_name: &str) -> io::Result<()> {
        let child_name = child_name.trim();
        if child_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Child key name cannot be empty",
            ));
        }
        if child_name.contains('\\') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Child key name cannot contain backslashes",
            ));
        }
        if child_name.chars().count() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Key name exceeds 255 characters",
            ));
        }

        let parent = self.find_key(parent_path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Parent key '{}' not found", parent_path),
            )
        })?;

        if parent
            .subkeys
            .iter()
            .any(|k| k.name.eq_ignore_ascii_case(child_name))
        {
            return Ok(());
        }

        let parent_loc = parent.location.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Parent key location not tracked",
            )
        })?;

        let parent_rel = (parent_loc.cell_offset - REG_HEAD_OFFSET) as u32;
        let security_rel = parent_loc.security_offset;

        let (child_rel, child_size) = allocator::create_key_node(
            &mut self.raw_data,
            &mut self.base_block,
            parent_rel,
            child_name,
            security_rel,
        )?;

        let new_subkeys_off = match allocator::add_subkey_to_parent(
            &mut self.raw_data,
            &mut self.base_block,
            parent_rel,
            child_rel,
            child_name,
        ) {
            Ok(off) => off,
            Err(e) => {
                allocator::free_cell(
                    &mut self.raw_data,
                    child_rel,
                    self.base_block.hive_bins_data_size,
                );
                return Err(e);
            }
        };

        let child_loc = RegKeyLoc {
            cell_offset: REG_HEAD_OFFSET + child_rel as usize,
            cell_size: child_size,
            parent_offset: parent_rel,
            subkeys_offset: MAX_OFFSET,
            values_offset: MAX_OFFSET,
            security_offset: security_rel,
            class_offset: MAX_OFFSET,
            flags: if child_name.chars().all(|c| (c as u32) <= 0xFF) {
                0x0020
            } else {
                0
            },
        };

        let new_child = RegKey {
            name: child_name.to_string(),
            last_written: allocator::current_filetime(),
            subkeys_count: 0,
            values_count: 0,
            subkeys: Vec::new(),
            values: Vec::new(),
            class_name: None,
            location: Some(child_loc),
        };

        let parent_mut = self.find_key_mut(parent_path).unwrap();
        parent_mut.subkeys_count += 1;
        if let Some(loc) = parent_mut.location.as_mut() {
            loc.subkeys_offset = new_subkeys_off;
        }
        parent_mut.subkeys.push(new_child);
        parent_mut.subkeys.sort_by_key(|a| a.name.to_lowercase());

        Ok(())
    }

    pub fn create_key(&mut self, key_path: &str) -> io::Result<()> {
        let parts: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Ok(());
        }

        let mut current_path = String::new();
        for part in parts {
            let next_path = if current_path.is_empty() {
                part.to_string()
            } else {
                format!("{}\\{}", current_path, part)
            };

            if self.find_key(&next_path).is_none() {
                self.create_child_key(&current_path, part)?;
            }
            current_path = next_path;
        }

        Ok(())
    }

    pub fn set_value(
        &mut self,
        key_path: &str,
        value_name: &str,
        value_type: RegValueType,
        data: &[u8],
    ) -> io::Result<()> {
        if self.find_key(key_path).is_none() {
            self.create_key(key_path)?;
        }

        let existing = self
            .find_key(key_path)
            .and_then(|k| {
                k.values
                    .iter()
                    .find(|v| v.name.eq_ignore_ascii_case(value_name))
            })
            .cloned();

        if let Some(val) = existing {
            self.set_raw_value_data(key_path, value_name, data, None)?;

            if val.value_type != value_type {
                if let Some(loc) = val.location {
                    let vk_abs = loc.cell_offset;
                    if vk_abs + 4 + 0x10 <= self.raw_data.len() {
                        self.raw_data[vk_abs + 4 + 0x0C..vk_abs + 4 + 0x10]
                            .copy_from_slice(&value_type.to_u32().to_le_bytes());
                    }
                }
                let k_mut = self.find_key_mut(key_path).unwrap();
                if let Some(v_mut) = k_mut
                    .values
                    .iter_mut()
                    .find(|v| v.name.eq_ignore_ascii_case(value_name))
                {
                    v_mut.value_type = value_type;
                }
            }
            return Ok(());
        }

        let parent_loc = self
            .find_key(key_path)
            .and_then(|k| k.location.clone())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Key location not tracked")
            })?;

        let parent_rel = (parent_loc.cell_offset - REG_HEAD_OFFSET) as u32;

        let (vk_rel, _vk_sz) = allocator::create_value_node(
            &mut self.raw_data,
            &mut self.base_block,
            value_name,
            value_type.to_u32(),
            data,
        )?;

        let new_list_off = match allocator::add_value_to_parent(
            &mut self.raw_data,
            &mut self.base_block,
            parent_rel,
            vk_rel,
            value_name.chars().count(),
            data.len(),
        ) {
            Ok(off) => off,
            Err(e) => {
                allocator::free_cell(
                    &mut self.raw_data,
                    vk_rel,
                    self.base_block.hive_bins_data_size,
                );
                return Err(e);
            }
        };

        let vk_abs = REG_HEAD_OFFSET + vk_rel as usize;
        let is_inline = data.len() <= 4;
        let data_offset = if is_inline {
            vk_abs + 4 + 8
        } else {
            let d_off = u32::from_le_bytes(
                self.raw_data[vk_abs + 12..vk_abs + 16]
                    .try_into()
                    .unwrap_or_default(),
            );
            REG_HEAD_OFFSET + d_off as usize
        };

        let new_val = RegValue {
            name: if value_name.is_empty() {
                "(Default)".to_string()
            } else {
                value_name.to_string()
            },
            value_type,
            data: data.to_vec(),
            location: Some(RegValueLoc {
                cell_offset: vk_abs,
                data_offset,
                data_size: data.len() as u32,
                inline: is_inline,
            }),
        };

        let k_mut = self.find_key_mut(key_path).unwrap();
        k_mut.values_count += 1;
        if let Some(loc) = k_mut.location.as_mut() {
            loc.values_offset = new_list_off;
        }
        k_mut.values.push(new_val);

        Ok(())
    }

    pub fn set_string(&mut self, key_path: &str, value_name: &str, value: &str) -> io::Result<()> {
        let mut data: Vec<u8> = value.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        data.extend_from_slice(&[0, 0]);
        self.set_value(key_path, value_name, RegValueType::String, &data)
    }

    pub fn set_dword(&mut self, key_path: &str, value_name: &str, value: u32) -> io::Result<()> {
        self.set_value(
            key_path,
            value_name,
            RegValueType::Dword,
            &value.to_le_bytes(),
        )
    }

    pub fn set_qword(&mut self, key_path: &str, value_name: &str, value: u64) -> io::Result<()> {
        self.set_value(
            key_path,
            value_name,
            RegValueType::Qword,
            &value.to_le_bytes(),
        )
    }

    pub fn set_binary(&mut self, key_path: &str, value_name: &str, value: &[u8]) -> io::Result<()> {
        self.set_value(key_path, value_name, RegValueType::Binary, value)
    }

    pub fn set_multi_string<S: AsRef<str>>(
        &mut self,
        key_path: &str,
        value_name: &str,
        values: &[S],
    ) -> io::Result<()> {
        let mut data = Vec::new();
        for s in values {
            for c in s.as_ref().encode_utf16() {
                data.extend_from_slice(&c.to_le_bytes());
            }
            data.extend_from_slice(&[0, 0]);
        }
        data.extend_from_slice(&[0, 0]);
        self.set_value(key_path, value_name, RegValueType::MultiString, &data)
    }

    fn set_raw_value_data(
        &mut self,
        key_path: &str,
        value_name: &str,
        new_data: &[u8],
        expected_type: Option<RegValueType>,
    ) -> io::Result<()> {
        let location = {
            let key = self
                .find_key(key_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))?;

            let value = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(value_name))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Value not found"))?;

            if let Some(ref exp) = expected_type
                && &value.value_type != exp
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Value is not {:?} type", exp),
                ));
            }

            value.location.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Value location not tracked")
            })?
        };

        let vk_cell = location.cell_offset + 4;
        let final_location: RegValueLoc;

        if location.inline {
            if new_data.len() <= 4 {
                let mut inline_buf = [0u8; 4];
                inline_buf[..new_data.len()].copy_from_slice(new_data);
                self.raw_data[vk_cell + 8..vk_cell + 12].copy_from_slice(&inline_buf);

                let new_size = (new_data.len() as u32) | INLINE_DATA_FLAG;
                self.raw_data[vk_cell + 4..vk_cell + 8].copy_from_slice(&new_size.to_le_bytes());

                final_location = RegValueLoc {
                    cell_offset: location.cell_offset,
                    data_offset: location.cell_offset + 4 + 8,
                    data_size: new_data.len() as u32,
                    inline: true,
                };
            } else {
                let (new_vk_size, new_vk_offset, is_inline) = allocator::allocate_value_data(
                    &mut self.raw_data,
                    &mut self.base_block,
                    new_data,
                )?;

                self.raw_data[vk_cell + 4..vk_cell + 8].copy_from_slice(&new_vk_size.to_le_bytes());
                self.raw_data[vk_cell + 8..vk_cell + 12]
                    .copy_from_slice(&new_vk_offset.to_le_bytes());

                final_location = RegValueLoc {
                    cell_offset: location.cell_offset,
                    data_offset: if is_inline {
                        location.cell_offset + 4 + 8
                    } else {
                        REG_HEAD_OFFSET + new_vk_offset as usize
                    },
                    data_size: new_data.len() as u32,
                    inline: is_inline,
                };
            }
        } else {
            if new_data.len() <= 4 {
                allocator::free_value_data(
                    &mut self.raw_data,
                    self.base_block.hive_bins_data_size,
                    false,
                    location.data_offset,
                );

                let mut inline_buf = [0u8; 4];
                inline_buf[..new_data.len()].copy_from_slice(new_data);
                self.raw_data[vk_cell + 8..vk_cell + 12].copy_from_slice(&inline_buf);

                let new_size = (new_data.len() as u32) | INLINE_DATA_FLAG;
                self.raw_data[vk_cell + 4..vk_cell + 8].copy_from_slice(&new_size.to_le_bytes());

                final_location = RegValueLoc {
                    cell_offset: location.cell_offset,
                    data_offset: location.cell_offset + 4 + 8,
                    data_size: new_data.len() as u32,
                    inline: true,
                };
            } else {
                let old_cell_abs = location.data_offset;
                let old_raw_size = if old_cell_abs + 4 <= self.raw_data.len() {
                    i32::from_le_bytes(
                        self.raw_data[old_cell_abs..old_cell_abs + 4]
                            .try_into()
                            .unwrap_or_default(),
                    )
                } else {
                    0
                };

                let is_db = if old_cell_abs + 6 <= self.raw_data.len() {
                    &self.raw_data[old_cell_abs + 4..old_cell_abs + 6] == SIGNATURE_BIG_DATA
                } else {
                    false
                };

                let old_cap = allocator::cell_capacity(old_raw_size);

                if !is_db && new_data.len() <= BIG_DATA_THRESHOLD && new_data.len() <= old_cap {
                    let data_start = old_cell_abs + 4;
                    self.raw_data[data_start..data_start + new_data.len()]
                        .copy_from_slice(new_data);
                    if data_start + old_cap <= self.raw_data.len() {
                        self.raw_data[data_start + new_data.len()..data_start + old_cap].fill(0);
                    }

                    self.raw_data[vk_cell + 4..vk_cell + 8]
                        .copy_from_slice(&(new_data.len() as u32).to_le_bytes());

                    final_location = RegValueLoc {
                        cell_offset: location.cell_offset,
                        data_offset: location.data_offset,
                        data_size: new_data.len() as u32,
                        inline: false,
                    };
                } else {
                    let (new_vk_size, new_vk_offset, is_inline) = allocator::allocate_value_data(
                        &mut self.raw_data,
                        &mut self.base_block,
                        new_data,
                    )?;

                    allocator::free_value_data(
                        &mut self.raw_data,
                        self.base_block.hive_bins_data_size,
                        false,
                        location.data_offset,
                    );

                    self.raw_data[vk_cell + 4..vk_cell + 8]
                        .copy_from_slice(&new_vk_size.to_le_bytes());
                    self.raw_data[vk_cell + 8..vk_cell + 12]
                        .copy_from_slice(&new_vk_offset.to_le_bytes());

                    final_location = RegValueLoc {
                        cell_offset: location.cell_offset,
                        data_offset: if is_inline {
                            location.cell_offset + 4 + 8
                        } else {
                            REG_HEAD_OFFSET + new_vk_offset as usize
                        },
                        data_size: new_data.len() as u32,
                        inline: is_inline,
                    };
                }
            }
        }

        let key_mut = self
            .find_key_mut(key_path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key became invalid"))?;
        let value_mut = key_mut
            .values
            .iter_mut()
            .find(|v| v.name.eq_ignore_ascii_case(value_name))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Value became invalid"))?;

        value_mut.data = new_data.to_vec();
        value_mut.location = Some(final_location);

        Ok(())
    }

    pub fn update_dword(
        &mut self,
        key_path: &str,
        value: &str,
        new_value: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.set_raw_value_data(
            key_path,
            value,
            &new_value.to_le_bytes(),
            Some(RegValueType::Dword),
        )?;
        Ok(())
    }

    pub fn update_qword_value(
        &mut self,
        key_path: &str,
        value_name: &str,
        new_value: u64,
    ) -> io::Result<()> {
        self.set_raw_value_data(
            key_path,
            value_name,
            &new_value.to_le_bytes(),
            Some(RegValueType::Qword),
        )
    }

    pub fn update_string_value(
        &mut self,
        key_path: &str,
        value_name: &str,
        new_value: &str,
    ) -> io::Result<()> {
        let mut utf16 = new_value
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect::<Vec<u8>>();
        utf16.extend_from_slice(&[0, 0]);

        self.set_raw_value_data(key_path, value_name, &utf16, None)
    }

    pub fn update_binary_value(
        &mut self,
        key_path: &str,
        value_name: &str,
        new_data: &[u8],
    ) -> io::Result<()> {
        self.set_raw_value_data(key_path, value_name, new_data, Some(RegValueType::Binary))
    }

    fn rebuild_sequence(&mut self) {
        self.base_block.sequence1 = self.base_block.sequence1.wrapping_add(1);
        self.base_block.sequence2 = self.base_block.sequence1;

        self.raw_data[4..8].copy_from_slice(&self.base_block.sequence1.to_le_bytes());
        self.raw_data[8..12].copy_from_slice(&self.base_block.sequence2.to_le_bytes());

        self.raw_data[40..44].copy_from_slice(&self.base_block.hive_bins_data_size.to_le_bytes());

        let mut checksum: u32 = 0;
        for chunk in self.raw_data[0..508].as_chunks::<4>().0.iter() {
            checksum ^= u32::from_le_bytes(*chunk);
        }
        if checksum == 0xFFFFFFFF {
            checksum = 0xFFFFFFFE;
        } else if checksum == 0 {
            checksum = 1;
        }
        self.raw_data[508..512].copy_from_slice(&checksum.to_le_bytes());
    }

    pub fn commit(&mut self) -> io::Result<()> {
        let path = self.path.clone().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Path to hive was not found. Use save_to() first.",
            )
        })?;

        self.rebuild_sequence();

        let mut temp_file = path.as_os_str().to_owned();
        temp_file.push(".tmp");
        let temp_path = PathBuf::from(temp_file);

        {
            let mut temp = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&temp_path)?;

            temp.write_all(&self.raw_data)?;
            temp.sync_all()?;
        }

        std::fs::rename(&temp_path, &path)?;
        Ok(())
    }

    pub fn save_to<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        self.rebuild_sequence();

        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(path.as_ref())?;
        file.write_all(&self.raw_data)?;
        file.sync_all()?;
        self.path = Some(path.as_ref().to_path_buf());

        Ok(())
    }

    pub fn validate(&self) -> io::Result<()> {
        allocator::validate_hive_structures(&self.raw_data, &self.base_block)
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }
}
