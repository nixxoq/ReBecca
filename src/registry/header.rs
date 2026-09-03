use crate::{
    constants::{HEADER_NAME, MIN_REG_SIZE},
    model::RegHeader,
};
use std::io;

impl RegHeader {
    pub(crate) fn parse(data: &[u8]) -> io::Result<Self> {
        if data.len() < MIN_REG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Base header too small",
            ));
        }

        let signature = [data[0], data[1], data[2], data[3]];

        if &signature != HEADER_NAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid header name",
            ));
        }

        Ok(Self {
            signature,
            sequence1: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            sequence2: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            last_written: u64::from_le_bytes([
                data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
            ]),
            major_version: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            minor_version: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            file_type: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            root_cell_offset: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            hive_bins_data_size: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
        })
    }
}
