use crate::{
    constants::{
        INLINE_DATA_FLAG, MAX_OFFSET, MIN_REG_SIZE, REG_HEAD_OFFSET, SIGNATURE_LEAF,
        SIGNATURE_LEAF_HASH_1, SIGNATURE_LEAF_HASH_2, SIGNATURE_ROOT_INDEX,
    },
    model::{RegHeader, RegHive, RegKey, RegValue, RegValueLoc, RegValueType},
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

        let (subkeys_count, subkeys_offset) = (
            u32::from_le_bytes([cell_data[14], cell_data[15], cell_data[16], cell_data[17]]),
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

        let name_length = u16::from_le_bytes([cell_data[0x48], cell_data[0x49]]) as usize;
        let name = if name_length > 0 && cell_data.len() >= 0x4C + name_length {
            String::from_utf8_lossy(&cell_data[0x4C..0x4C + name_length]).to_string()
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

        Ok(RegKey {
            name,
            last_written,
            subkeys_count,
            values_count,
            subkeys,
            values,
            class_name: None,
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

            let result = {
                let data_cell = data.get(real_offset..real_offset + 4).unwrap_or_default();
                let data_cell_s = i32::from_le_bytes(data_cell.try_into().ok().unwrap_or_default())
                    .unsigned_abs() as usize;

                let offset_start = real_offset + 4;
                let data_end = (offset_start + data_size as usize).min(real_offset + data_cell_s);

                let data = data.get(offset_start..data_end).unwrap_or_default();
                Some(data.to_vec())
            };

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

            (result.unwrap_or_default(), loc)
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

        parts.iter().try_fold(root, |root, &part| {
            root.subkeys
                .iter()
                .find(|subkey| subkey.name.eq_ignore_ascii_case(part))
        })
    }

    fn find_key_mut(&mut self, key_path: &str) -> Option<&mut RegKey> {
        let parts: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
        let mut current_key = self.root_key.as_mut()?;

        for part in parts {
            current_key = current_key
                .subkeys
                .iter_mut()
                .find(|sk| sk.name.eq_ignore_ascii_case(part))?;
        }
        Some(current_key)
    }

    fn find_space(&self, size_needed: usize) -> Option<u32> {
        let aligned_size = (size_needed + 4 + 7) & !7;
        let mut current_offset = REG_HEAD_OFFSET;

        while current_offset < self.raw_data.len() {
            if current_offset + 4 > self.raw_data.len() {
                break;
            }

            // hbin blocks are usually aligned to 4096 bytes.
            // We must jump from one to another based on their actual size.
            if &self.raw_data[current_offset..current_offset + 4] == b"hbin" {
                let hbin_size = u32::from_le_bytes(
                    self.raw_data[current_offset + 8..current_offset + 12]
                        .try_into()
                        .unwrap(),
                );
                let mut offset_hbin = 24;

                while offset_hbin < hbin_size {
                    let cell_offset = current_offset + offset_hbin as usize;
                    if cell_offset + 4 > self.raw_data.len() {
                        break;
                    }

                    let cell_size = i32::from_le_bytes(
                        self.raw_data[cell_offset..cell_offset + 4]
                            .try_into()
                            .unwrap(),
                    );

                    if cell_size.unsigned_abs() < 4 {
                        break;
                    } else if cell_size > 0 && cell_size as usize >= aligned_size {
                        return Some((cell_offset - REG_HEAD_OFFSET) as u32);
                    }

                    offset_hbin += cell_size.unsigned_abs();
                }
                current_offset += hbin_size as usize;
            } else {
                current_offset += 4096;
            }
        }

        None
    }

    fn expand_hive(&mut self, size_needed: usize) -> io::Result<u32> {
        let current_size = self.raw_data.len();

        // hbin-block size must be multiple with REG_HEAD_OFFSET value
        if !current_size.is_multiple_of(REG_HEAD_OFFSET) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hive size is not aligned to 4096 bytes",
            ));
        }

        let hbin_offset = current_size;
        let new_size = current_size + REG_HEAD_OFFSET;
        self.raw_data.resize(new_size, 0);

        self.raw_data[hbin_offset..hbin_offset + 4].copy_from_slice(b"hbin");
        self.raw_data[hbin_offset + 4..hbin_offset + 8]
            .copy_from_slice(&(hbin_offset as u32 - REG_HEAD_OFFSET as u32).to_le_bytes());
        self.raw_data[hbin_offset + 8..hbin_offset + 12]
            .copy_from_slice(&(REG_HEAD_OFFSET as u32).to_le_bytes());

        let cell_offset = hbin_offset + 24;
        let cell_size = REG_HEAD_OFFSET - 24;

        self.raw_data[cell_offset..cell_offset + 4]
            .copy_from_slice(&(cell_size as i32).to_le_bytes());

        self.base_block.hive_bins_data_size = new_size as u32 - REG_HEAD_OFFSET as u32;
        self.raw_data[12..16].copy_from_slice(&self.base_block.hive_bins_data_size.to_le_bytes());

        if cell_size < size_needed + 4 {
            return Err(io::Error::other(
                "Failed to allocate enough space even after expansion",
            ));
        }

        Ok((cell_offset - REG_HEAD_OFFSET) as u32)
    }

    fn write_to_cell(&mut self, offset: u32, data: &[u8]) -> io::Result<()> {
        let cell_absolute_offset = REG_HEAD_OFFSET + offset as usize;
        let cell_size_with_header = data.len() + 4;
        let aligned_size = (cell_size_with_header + 7) & !7;

        self.raw_data[cell_absolute_offset..cell_absolute_offset + 4]
            .copy_from_slice(&(-(aligned_size as i32)).to_le_bytes());

        let data_start = cell_absolute_offset + 4;
        self.raw_data[data_start..data_start + data.len()].copy_from_slice(data);

        Ok(())
    }

    pub fn update_dword(
        &mut self,
        key_path: &str,
        value: &str,
        new_value: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let location = {
            let key = self
                .find_key(key_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))?;

            let value = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(value))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Value not found"))?;

            if !matches!(value.value_type, RegValueType::Dword) {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "Value is not DWORD type").into(),
                );
            }

            value.location.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Value location not tracked")
            })?
        };

        let new_bytes = new_value.to_le_bytes();

        if location.inline {
            let data_slice = self
                .raw_data
                .get_mut(location.data_offset..location.data_offset + 4)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Inline data offset out of bounds",
                    )
                })?;
            data_slice.copy_from_slice(&new_bytes);
        } else {
            let data_start = location.data_offset + 4;
            let data_slice = self
                .raw_data
                .get_mut(data_start..data_start + 4)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Data cell offset out of bounds")
                })?;
            data_slice.copy_from_slice(&new_bytes);
        }

        let value_mut: &mut RegValue = self
            .find_key_mut(key_path)
            .and_then(|key| {
                key.values
                    .iter_mut()
                    .find(|v| v.name.eq_ignore_ascii_case(value))
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Value became invalid after checks")
            })?;

        value_mut.data = new_bytes.to_vec();
        // let parts: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
        // let mut current_key = self.root_key.as_mut().ok_or("Root key is missing")?;
        //
        // for part in parts {
        //     current_key = current_key
        //         .subkeys
        //         .iter_mut()
        //         .find(|sk| sk.name.eq_ignore_ascii_case(part))
        //         .ok_or_else(|| {
        //             io::Error::new(io::ErrorKind::NotFound, "Key path became invalid")
        //         })?;
        // }
        //
        // let value_mut = current_key
        //     .values
        //     .iter_mut()
        //     .find(|v| v.name.eq_ignore_ascii_case(value))
        //     .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Value became invalid"))?;
        //
        // value_mut.data = new_bytes.to_vec();

        Ok(())
    }

    pub fn update_qword_value(
        &mut self,
        key_path: &str,
        value_name: &str,
        new_value: u64,
    ) -> io::Result<()> {
        let location = {
            let key = self
                .find_key(key_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))?;

            let value: &RegValue = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(value_name))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Value not found"))?;

            if !matches!(value.value_type, RegValueType::Qword) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Value is not QWORD type",
                ));
            }

            let location = value.location.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Value location not tracked")
            })?;

            if location.data_size < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "QWORD data size mismatch",
                ));
            }
            if location.inline {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "QWORD cannot be inline",
                ));
            }

            location
        };

        let new_bytes = new_value.to_le_bytes();

        let data_start = location.data_offset + 4;
        self.raw_data[data_start..data_start + 8].copy_from_slice(&new_bytes);

        let value_mut = self
            .find_key_mut(key_path)
            .and_then(|key| {
                key.values
                    .iter_mut()
                    .find(|v| v.name.eq_ignore_ascii_case(value_name))
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "Value became invalid after checks")
            })?;

        value_mut.data = new_bytes.to_vec();

        Ok(())
    }

    pub fn update_string_value(
        &mut self,
        key_path: &str,
        value_name: &str,
        new_value: &str,
    ) -> io::Result<()> {
        let (location, new_utf16_data, available_size) = {
            let key = self
                .find_key(key_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))?;
            let value = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(value_name))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Value not found"))?;

            if !matches!(
                value.value_type,
                RegValueType::String | RegValueType::ExpandString
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Value is not string type",
                ));
            }

            let location = value.location.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Value location not tracked")
            })?;

            let available_size = if location.inline {
                4
            } else {
                location.data_size as usize
            };

            let mut utf16 = new_value
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<u8>>();
            utf16.extend_from_slice(&[0, 0]); // null terminator

            (location, utf16, available_size)
        };

        let (final_data, final_location) = if new_utf16_data.len() <= available_size {
            // ===
            // free space method
            // ===
            let mut data_to_write = new_utf16_data;
            data_to_write.resize(available_size, 0);

            if location.inline {
                let vk_data_offset_pos = location.cell_offset + 4 + 0x08;
                self.raw_data[vk_data_offset_pos..vk_data_offset_pos + 4]
                    .copy_from_slice(&data_to_write[..4]);
            } else {
                let data_start = location.data_offset + 4;
                self.raw_data[data_start..data_start + data_to_write.len()]
                    .copy_from_slice(&data_to_write);
            }

            (data_to_write, location)
        } else {
            // ===
            // expanding have
            // ===
            let final_offset = match self.find_space(new_utf16_data.len()) {
                Some(offset) => offset,
                None => self.expand_hive(new_utf16_data.len())?,
            };

            self.write_to_cell(final_offset, &new_utf16_data)?;

            let vk_cell = location.cell_offset + 4;
            let new_size = new_utf16_data.len() as u32;
            self.raw_data[vk_cell + 4..vk_cell + 8].copy_from_slice(&new_size.to_le_bytes());
            self.raw_data[vk_cell + 8..vk_cell + 12].copy_from_slice(&final_offset.to_le_bytes());

            let new_location = RegValueLoc {
                cell_offset: location.cell_offset,
                inline: false,
                data_offset: REG_HEAD_OFFSET + final_offset as usize,
                data_size: new_size,
            };

            (new_utf16_data, new_location)
        };

        let key_mut = self.find_key_mut(key_path).unwrap();
        let value_mut = key_mut
            .values
            .iter_mut()
            .find(|v| v.name.eq_ignore_ascii_case(value_name))
            .unwrap();

        value_mut.data = final_data;
        value_mut.location = Some(final_location);

        Ok(())
    }

    pub fn update_binary_value(
        &mut self,
        key_path: &str,
        value_name: &str,
        new_data: &[u8],
    ) -> io::Result<()> {
        let location: RegValueLoc;

        {
            let key = self
                .find_key(key_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Key not found"))?;

            let value = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(value_name))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Value not found"))?;

            location = value.location.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Value location not tracked")
            })?;

            if new_data.len() > location.data_size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "New data too long: {} > {}",
                        new_data.len(),
                        location.data_size
                    ),
                ));
            }
        }

        let mut padded_data = new_data.to_vec();
        padded_data.resize(location.data_size as usize, 0);

        if location.inline {
            self.raw_data[location.data_offset..location.data_offset + padded_data.len()]
                .copy_from_slice(&padded_data);
        } else {
            let data_start = location.data_offset + 4;
            self.raw_data[data_start..data_start + padded_data.len()].copy_from_slice(&padded_data);
        }

        let key_mut = self.find_key_mut(key_path).unwrap();
        let value_mut = key_mut
            .values
            .iter_mut()
            .find(|v| v.name.eq_ignore_ascii_case(value_name))
            .unwrap();
        value_mut.data = padded_data;

        Ok(())
    }

    fn rebuild_sequence(&mut self) {
        self.base_block.sequence1 = self.base_block.sequence1.wrapping_add(1);
        self.base_block.sequence2 = self.base_block.sequence1;

        self.raw_data[4..8].copy_from_slice(&self.base_block.sequence1.to_le_bytes());
        self.raw_data[8..12].copy_from_slice(&self.base_block.sequence2.to_le_bytes());

        // checksum
        let mut checksum: u32 = 0;
        for chunk in self.raw_data[0..508].chunks_exact(4) {
            checksum ^= u32::from_le_bytes(chunk.try_into().unwrap());
        }
        self.raw_data[508..512].copy_from_slice(&checksum.to_le_bytes());
    }

    pub fn commit(&mut self) -> io::Result<()> {
        // quite simple
        // path -> temp_file -> renaming -> done
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
            let mut temp_file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(&temp_path)?;

            temp_file.write_all(&self.raw_data)?;
            temp_file.sync_all()?;
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
}
