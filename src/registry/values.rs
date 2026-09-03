use crate::model::{RegValue, RegValueType};

impl RegValue {
    /// convert reg_sz and reg_expand_sz values to String
    pub fn as_string(&self) -> Option<String> {
        match self.value_type {
            RegValueType::String | RegValueType::ExpandString => {
                // convert UTF-16 LE string
                if self.data.len() >= 2 {
                    let u16_data: Vec<u16> = self
                        .data
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|chunk| u16::from_le_bytes(*chunk))
                        .take_while(|&c| c != 0)
                        .collect();

                    if u16_data.is_empty() && self.data.len() >= 2 {
                        if self.data[0] == 0 && self.data[1] == 0 {
                            Some(String::new())
                        } else {
                            String::from_utf16(&u16_data).ok()
                        }
                    } else {
                        String::from_utf16(&u16_data).ok()
                    }
                } else {
                    Some(String::new())
                }
            }
            _ => None,
        }
    }

    /// Get uint32 value from REG_DWORD
    pub fn as_dword(&self) -> Option<u32> {
        if matches!(self.value_type, RegValueType::Dword) && self.data.len() >= 4 {
            Some(u32::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
            ]))
        } else {
            None
        }
    }

    /// Get uint64 value from REG_QWORD
    pub fn as_qword(&self) -> Option<u64> {
        if matches!(self.value_type, RegValueType::Qword) && self.data.len() >= 8 {
            Some(u64::from_le_bytes([
                self.data[0],
                self.data[1],
                self.data[2],
                self.data[3],
                self.data[4],
                self.data[5],
                self.data[6],
                self.data[7],
            ]))
        } else {
            None
        }
    }

    /// Convert REG_MULTI_SZ value to Vec<String>
    pub fn as_multi_string(&self) -> Option<Vec<String>> {
        if matches!(self.value_type, RegValueType::MultiString) {
            let u16_chars: Vec<u16> = self
                .data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let mut result = Vec::new();
            let mut current = Vec::new();
            for c in u16_chars {
                if c == 0 {
                    if !current.is_empty() {
                        result.push(String::from_utf16_lossy(&current));
                        current.clear();
                    }
                } else {
                    current.push(c);
                }
            }
            if !current.is_empty() {
                result.push(String::from_utf16_lossy(&current));
            }
            Some(result)
        } else {
            None
        }
    }

    pub fn as_binary(&self) -> &[u8] {
        &self.data
    }

    pub fn get_location_info(&self) -> Option<String> {
        self.location.as_ref().map(|loc| {
            format!(
                "cell_offset: 0x{:X}, data_offset: 0x{:X}, size: {}, inline: {}",
                loc.cell_offset, loc.data_offset, loc.data_size, loc.inline
            )
        })
    }

    pub fn is_inline(&self) -> Option<bool> {
        self.location.as_ref().map(|loc| loc.inline)
    }

    pub fn data_offset(&self) -> Option<usize> {
        self.location.as_ref().map(|loc| loc.data_offset)
    }
}
