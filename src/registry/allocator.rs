use crate::{
    constants::{
        BIG_DATA_THRESHOLD, CELL_ALIGNMENT, CELL_HEADER_SIZE, DEFAULT_SYSTEM_SECURITY_DESCRIPTOR,
        HBIN_HEADER_SIZE, INITIAL_BIN_SIZE, INLINE_DATA_FLAG, MAX_OFFSET, MIN_CELL_SIZE,
        REG_HEAD_OFFSET, SIGNATURE_BIG_DATA,
    },
    model::RegHeader,
};
use std::io;

#[inline]
pub fn align_cell_size(payload_size: usize) -> usize {
    ((payload_size + CELL_HEADER_SIZE + (CELL_ALIGNMENT - 1)) & !(CELL_ALIGNMENT - 1))
        .max(MIN_CELL_SIZE)
}

/// returns payload capacity of an allocated cell given its raw cell size field.
#[inline]
pub fn cell_capacity(raw_cell_size: i32) -> usize {
    if raw_cell_size < 0 {
        ((-raw_cell_size) as usize).saturating_sub(CELL_HEADER_SIZE)
    } else {
        0
    }
}

/// scans the hive bins for an existing free cell
pub fn find_free_cell(
    raw_data: &[u8],
    bins_data_size: u32,
    needed_cell_size: usize,
) -> Option<u32> {
    let mut bin_rel = 0u32;

    while bin_rel < bins_data_size {
        let bin_abs = REG_HEAD_OFFSET + bin_rel as usize;
        if bin_abs + HBIN_HEADER_SIZE > raw_data.len() {
            break;
        }

        if &raw_data[bin_abs..bin_abs + 4] != b"hbin" {
            break;
        }

        let bin_size = u32::from_le_bytes(
            raw_data[bin_abs + 8..bin_abs + 12]
                .try_into()
                .unwrap_or_default(),
        );
        if bin_size == 0 || bin_size % 4096 != 0 {
            break;
        }

        let mut cell_rel = bin_rel + HBIN_HEADER_SIZE as u32;
        let bin_end_rel = bin_rel + bin_size;

        while cell_rel < bin_end_rel {
            let cell_abs = REG_HEAD_OFFSET + cell_rel as usize;
            if cell_abs + 4 > raw_data.len() {
                break;
            }

            let cell_size = i32::from_le_bytes(
                raw_data[cell_abs..cell_abs + 4]
                    .try_into()
                    .unwrap_or_default(),
            );
            let abs_size = cell_size.unsigned_abs() as usize;

            if abs_size < MIN_CELL_SIZE || !abs_size.is_multiple_of(CELL_ALIGNMENT) {
                break;
            }

            if cell_size > 0 && abs_size >= needed_cell_size {
                return Some(cell_rel);
            }

            cell_rel += abs_size as u32;
        }

        bin_rel += bin_size;
    }

    None
}

/// splits a free cell at `cell_rel_offset` into an allocated cell of `alloc_size` and an optional
/// valid free remainder cell.
pub fn split_free_cell(raw_data: &mut [u8], cell_rel_offset: u32, alloc_size: usize) {
    let cell_abs = REG_HEAD_OFFSET + cell_rel_offset as usize;
    let free_size = i32::from_le_bytes(
        raw_data[cell_abs..cell_abs + 4]
            .try_into()
            .unwrap_or_default(),
    ) as usize;

    debug_assert!(free_size >= alloc_size);

    let remainder = free_size.saturating_sub(alloc_size);
    if remainder >= MIN_CELL_SIZE {
        raw_data[cell_abs..cell_abs + 4].copy_from_slice(&(-(alloc_size as i32)).to_le_bytes());

        let rem_abs = cell_abs + alloc_size;
        raw_data[rem_abs..rem_abs + 4].copy_from_slice(&(remainder as i32).to_le_bytes());
    } else {
        raw_data[cell_abs..cell_abs + 4].copy_from_slice(&(-(free_size as i32)).to_le_bytes());
    }
}

pub fn free_cell(raw_data: &mut [u8], cell_rel_offset: u32, bins_data_size: u32) {
    let cell_abs = REG_HEAD_OFFSET + cell_rel_offset as usize;

    if cell_abs + 4 > raw_data.len() {
        return;
    }

    let mut bin_rel = 0u32;
    let mut containing_bin = None;

    while bin_rel < bins_data_size {
        let bin_abs = REG_HEAD_OFFSET + bin_rel as usize;

        if bin_abs + HBIN_HEADER_SIZE > raw_data.len() {
            break;
        }
        if &raw_data[bin_abs..bin_abs + 4] != b"hbin" {
            break;
        }

        let bin_size = u32::from_le_bytes(
            raw_data[bin_abs + 8..bin_abs + 12]
                .try_into()
                .unwrap_or_default(),
        );

        if bin_size == 0 {
            break;
        }

        if cell_rel_offset >= bin_rel + HBIN_HEADER_SIZE as u32
            && cell_rel_offset < bin_rel + bin_size
        {
            containing_bin = Some((bin_rel, bin_size));
            break;
        }
        bin_rel += bin_size;
    }

    let (bin_start_rel, bin_size) = match containing_bin {
        Some(b) => b,
        None => return,
    };

    let raw_sz = i32::from_le_bytes(
        raw_data[cell_abs..cell_abs + 4]
            .try_into()
            .unwrap_or_default(),
    );

    if raw_sz >= 0 {
        return;
    }

    let mut current_free_size = raw_sz.unsigned_abs() as usize;
    raw_data[cell_abs..cell_abs + 4].copy_from_slice(&(current_free_size as i32).to_le_bytes());

    // check neighbor within the same hbin
    let next_rel = cell_rel_offset + current_free_size as u32;
    if next_rel < bin_start_rel + bin_size {
        let next_abs = REG_HEAD_OFFSET + next_rel as usize;

        if next_abs + 4 <= raw_data.len() {
            let next_sz = i32::from_le_bytes(
                raw_data[next_abs..next_abs + 4]
                    .try_into()
                    .unwrap_or_default(),
            );

            if next_sz > 0 {
                current_free_size += next_sz as usize;

                raw_data[cell_abs..cell_abs + 4]
                    .copy_from_slice(&(current_free_size as i32).to_le_bytes());
                raw_data[next_abs..next_abs + 4].copy_from_slice(&0i32.to_le_bytes());
            }
        }
    }

    // scan cells in current hbin
    let mut scan_rel = bin_start_rel + HBIN_HEADER_SIZE as u32;
    while scan_rel < cell_rel_offset {
        let scan_abs = REG_HEAD_OFFSET + scan_rel as usize;

        if scan_abs + 4 > raw_data.len() {
            break;
        }

        let scan_sz = i32::from_le_bytes(
            raw_data[scan_abs..scan_abs + 4]
                .try_into()
                .unwrap_or_default(),
        );
        let scan_abs_sz = scan_sz.unsigned_abs() as usize;

        if scan_abs_sz < MIN_CELL_SIZE {
            break;
        }

        if scan_rel + scan_abs_sz as u32 == cell_rel_offset {
            if scan_sz > 0 {
                let merged_size = scan_abs_sz + current_free_size;
                raw_data[scan_abs..scan_abs + 4]
                    .copy_from_slice(&(merged_size as i32).to_le_bytes());
                raw_data[cell_abs..cell_abs + 4].copy_from_slice(&0i32.to_le_bytes());
            }
            break;
        }

        scan_rel += scan_abs_sz as u32;
    }
}

/// appends a new `hbin` at the logical end of the hive bins data (`REG_HEAD_OFFSET + base_block.hive_bins_data_size`).
///
/// returns the relative offset of the initial free cell in the new bin.
pub fn add_hbin(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    required_cell_size: usize,
) -> io::Result<u32> {
    let (hbin_offset, bin_space) = (
        base_block.hive_bins_data_size,
        required_cell_size + HBIN_HEADER_SIZE,
    );
    let bin_size = bin_space.div_ceil(4096) * 4096;

    let nbin_size = hbin_offset
        .checked_add(bin_size as u32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::OutOfMemory, "Hive bins size overflow"))?;

    let hbin_aoffset = REG_HEAD_OFFSET + hbin_offset as usize;
    let total_size = REG_HEAD_OFFSET + nbin_size as usize;

    if raw_data.len() < total_size {
        raw_data.resize(total_size, 0);
    }

    // 32-byte hbin header
    raw_data[hbin_aoffset..hbin_aoffset + 4].copy_from_slice(b"hbin");
    raw_data[hbin_aoffset + 4..hbin_aoffset + 8].copy_from_slice(&hbin_offset.to_le_bytes());
    raw_data[hbin_aoffset + 8..hbin_aoffset + 12].copy_from_slice(&(bin_size as u32).to_le_bytes());
    raw_data[hbin_aoffset + 12..hbin_aoffset + 20].fill(0); // reserved
    raw_data[hbin_aoffset + 20..hbin_aoffset + 28].fill(0); // timestamp
    raw_data[hbin_aoffset + 28..hbin_aoffset + 32].fill(0); // spare

    let (free_cell, free_cell_s) = (
        hbin_aoffset + HBIN_HEADER_SIZE,
        (bin_size - HBIN_HEADER_SIZE) as i32,
    );
    raw_data[free_cell..free_cell + 4].copy_from_slice(&free_cell_s.to_le_bytes());

    base_block.hive_bins_data_size = nbin_size;
    raw_data[40..44].copy_from_slice(&nbin_size.to_le_bytes());

    // Update checksum over first 508 bytes
    let mut checksum = 0u32;
    for chunk in raw_data[0..508].as_chunks::<4>().0 {
        checksum ^= u32::from_le_bytes(*chunk);
    }
    raw_data[508..512].copy_from_slice(&checksum.to_le_bytes());

    Ok(hbin_offset + HBIN_HEADER_SIZE as u32)
}

/// allocates an 8-byte aligned cell for `payload_size` bytes.
///
/// reuses an existing free cell if available; otherwise it appends a new `hbin`.
pub fn allocate_cell(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    payload_size: usize,
) -> io::Result<u32> {
    let needed_cell_size = align_cell_size(payload_size);

    if let Some(free_rel) =
        find_free_cell(raw_data, base_block.hive_bins_data_size, needed_cell_size)
    {
        split_free_cell(raw_data, free_rel, needed_cell_size);
        Ok(free_rel)
    } else {
        let free_rel = add_hbin(raw_data, base_block, needed_cell_size)?;
        split_free_cell(raw_data, free_rel, needed_cell_size);
        Ok(free_rel)
    }
}

pub fn read_value_data(raw_data: &[u8], data_size: u32, data_offset: u32) -> io::Result<Vec<u8>> {
    if data_size & INLINE_DATA_FLAG != 0 {
        let size = (data_size & !INLINE_DATA_FLAG) as usize;
        let bytes = data_offset.to_le_bytes();
        return Ok(bytes.get(..size).unwrap_or_default().to_vec());
    }

    if data_offset == 0 || data_offset == MAX_OFFSET {
        return Ok(Vec::new());
    }

    let real_offset = REG_HEAD_OFFSET + data_offset as usize;
    if real_offset + 4 > raw_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Data cell offset exceeds file size",
        ));
    }

    let cell_size = i32::from_le_bytes(
        raw_data[real_offset..real_offset + 4]
            .try_into()
            .unwrap_or_default(),
    )
    .unsigned_abs() as usize;

    if real_offset + cell_size > raw_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Cell size exceeds file size",
        ));
    }

    let cell_payload = &raw_data[real_offset + 4..real_offset + cell_size];

    // check for Big Data ("db") signature
    if cell_payload.len() >= 8 && &cell_payload[0..2] == SIGNATURE_BIG_DATA {
        let num_segments = u16::from_le_bytes([cell_payload[2], cell_payload[3]]) as usize;
        let seg_list = u32::from_le_bytes([
            cell_payload[4],
            cell_payload[5],
            cell_payload[6],
            cell_payload[7],
        ]) as usize;

        let seg_list_a = REG_HEAD_OFFSET + seg_list;
        if seg_list_a + 4 > raw_data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Segment list offset exceeds file size",
            ));
        }

        let seg_list_cell_size = i32::from_le_bytes(
            raw_data[seg_list_a..seg_list_a + 4]
                .try_into()
                .unwrap_or_default(),
        )
        .unsigned_abs() as usize;

        let seg_payload = &raw_data[seg_list_a + 4..seg_list_a + seg_list_cell_size];
        let mut data = Vec::with_capacity(data_size as usize);

        for i in 0..num_segments {
            let offset_pos = i * 4;
            if offset_pos + 4 > seg_payload.len() {
                break;
            }
            let seg_rel = u32::from_le_bytes([
                seg_payload[offset_pos],
                seg_payload[offset_pos + 1],
                seg_payload[offset_pos + 2],
                seg_payload[offset_pos + 3],
            ]) as usize;

            let seg_abs = REG_HEAD_OFFSET + seg_rel;
            if seg_abs + 4 > raw_data.len() {
                break;
            }

            let seg_cell_size = i32::from_le_bytes(
                raw_data[seg_abs..seg_abs + 4]
                    .try_into()
                    .unwrap_or_default(),
            )
            .unsigned_abs() as usize;

            let needed = (data_size as usize).saturating_sub(data.len());
            let seg_usable = (seg_cell_size.saturating_sub(4))
                .min(BIG_DATA_THRESHOLD)
                .min(needed);
            let seg_start = seg_abs + 4;

            if seg_start + seg_usable <= raw_data.len() {
                data.extend_from_slice(&raw_data[seg_start..seg_start + seg_usable]);
            }
        }

        return Ok(data);
    }

    let usable_len = (data_size as usize).min(cell_payload.len());
    Ok(cell_payload[..usable_len].to_vec())
}

pub fn free_value_data(
    raw_data: &mut [u8],
    bins_data_size: u32,
    is_inline: bool,
    data_offset: usize,
) {
    if is_inline || data_offset < REG_HEAD_OFFSET {
        return;
    }

    let cell_offset = (data_offset - REG_HEAD_OFFSET) as u32;
    if data_offset + 4 > raw_data.len() {
        return;
    }

    let cell_sz = i32::from_le_bytes(
        raw_data[data_offset..data_offset + 4]
            .try_into()
            .unwrap_or_default(),
    )
    .unsigned_abs() as usize;

    if data_offset + cell_sz <= raw_data.len() {
        let cell_payload = &raw_data[data_offset + 4..data_offset + cell_sz];
        if cell_payload.len() >= 8 && &cell_payload[0..2] == SIGNATURE_BIG_DATA {
            let num_segments = u16::from_le_bytes([cell_payload[2], cell_payload[3]]) as usize;
            let list_rel = u32::from_le_bytes([
                cell_payload[4],
                cell_payload[5],
                cell_payload[6],
                cell_payload[7],
            ]);

            let list_a = REG_HEAD_OFFSET + list_rel as usize;
            if list_a + 4 <= raw_data.len() {
                let list_cell_sz =
                    i32::from_le_bytes(raw_data[list_a..list_a + 4].try_into().unwrap_or_default())
                        .unsigned_abs() as usize;

                let mut seg_offsets = Vec::with_capacity(num_segments);
                if list_a + 4 + list_cell_sz <= raw_data.len() {
                    let list_payload = &raw_data[list_a + 4..list_a + list_cell_sz];
                    for i in 0..num_segments {
                        let pos = i * 4;
                        if pos + 4 <= list_payload.len() {
                            let seg_rel = u32::from_le_bytes([
                                list_payload[pos],
                                list_payload[pos + 1],
                                list_payload[pos + 2],
                                list_payload[pos + 3],
                            ]);
                            seg_offsets.push(seg_rel);
                        }
                    }
                }

                for seg_rel in seg_offsets {
                    free_cell(raw_data, seg_rel, bins_data_size);
                }
                free_cell(raw_data, list_rel, bins_data_size);
            }
        }
    }

    free_cell(raw_data, cell_offset, bins_data_size);
}

/// Allocates storage for a value's data. Supports inline data (<= 4 bytes), standard cells
/// (<= 16344 bytes), and Big Data ("db") structures (> 16344 bytes).
///
/// Returns `(vk_data_size, vk_data_offset, is_inline)`.
pub fn allocate_value_data(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    data: &[u8],
) -> io::Result<(u32, u32, bool)> {
    if data.len() <= 4 {
        let mut inline_buf = [0u8; 4];
        inline_buf[..data.len()].copy_from_slice(data);

        let (data_offset, data_size) = (
            u32::from_le_bytes(inline_buf),
            (data.len() as u32) | INLINE_DATA_FLAG,
        );

        Ok((data_size, data_offset, true))
    } else if data.len() <= BIG_DATA_THRESHOLD {
        let cell = allocate_cell(raw_data, base_block, data.len())?;
        let cell_a = REG_HEAD_OFFSET + cell as usize;
        let data_start = cell_a + 4;

        raw_data[data_start..data_start + data.len()].copy_from_slice(data);
        Ok((data.len() as u32, cell, false))
    } else {
        // Big Data (db)
        let chunks: Vec<&[u8]> = data.chunks(BIG_DATA_THRESHOLD).collect();
        let mut seg_offsets = Vec::with_capacity(chunks.len());

        for chunk in &chunks {
            let seg = allocate_cell(raw_data, base_block, chunk.len())?;
            let seg_a = REG_HEAD_OFFSET + seg as usize;
            let data_start = seg_a + 4;

            raw_data[data_start..data_start + chunk.len()].copy_from_slice(chunk);
            seg_offsets.push(seg);
        }

        let mut l_bytes = Vec::with_capacity(seg_offsets.len() * 4);
        for off in &seg_offsets {
            l_bytes.extend_from_slice(&off.to_le_bytes());
        }

        let list_rel = allocate_cell(raw_data, base_block, l_bytes.len())?;
        let list_abs = REG_HEAD_OFFSET + list_rel as usize;
        let list_start = list_abs + 4;

        raw_data[list_start..list_start + l_bytes.len()].copy_from_slice(&l_bytes);

        // db record: 2 bytes "db" + 2 bytes num_segs + 4 bytes list_rel = 8 bytes payload
        let db = allocate_cell(raw_data, base_block, 8)?;
        let db_a = REG_HEAD_OFFSET + db as usize;
        let db_start = db_a + 4;

        raw_data[db_start..db_start + 2].copy_from_slice(SIGNATURE_BIG_DATA);
        raw_data[db_start + 2..db_start + 4].copy_from_slice(&(chunks.len() as u16).to_le_bytes());
        raw_data[db_start + 4..db_start + 8].copy_from_slice(&list_rel.to_le_bytes());

        Ok((data.len() as u32, db, false))
    }
}

pub fn validate_hive_structures(raw_data: &[u8], base_block: &RegHeader) -> io::Result<()> {
    if raw_data.len() < REG_HEAD_OFFSET {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File too small"));
    }

    if &raw_data[0..4] != b"regf" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid regf signature",
        ));
    }

    if base_block.sequence1 != base_block.sequence2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Sequence numbers mismatch",
        ));
    }

    let mut checksum: u32 = 0;
    for chunk in raw_data[0..508].as_chunks::<4>().0.iter() {
        checksum ^= u32::from_le_bytes(*chunk);
    }

    if checksum == 0xFFFFFFFF {
        checksum = 0xFFFFFFFE;
    } else if checksum == 0 {
        checksum = 1;
    }

    let stored_checksum = u32::from_le_bytes(
        raw_data[508..512]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid checksum field"))?,
    );

    if checksum != stored_checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Checksum mismatch: calculated 0x{:08X} != stored 0x{:08X}",
                checksum, stored_checksum
            ),
        ));
    }

    let bins_sz = base_block.hive_bins_data_size as usize;
    if !bins_sz.is_multiple_of(4096) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hive_bins_data_size is not a multiple of 4096",
        ));
    }

    if raw_data.len() < REG_HEAD_OFFSET + bins_sz {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "File size is smaller than BaseBlock + hive_bins_data_size",
        ));
    }

    let mut offset = 0usize;
    while offset < bins_sz {
        let bin_abs = REG_HEAD_OFFSET + offset;

        if bin_abs + HBIN_HEADER_SIZE > raw_data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("hbin at relative 0x{:X} extends beyond file", offset),
            ));
        }

        if &raw_data[bin_abs..bin_abs + 4] != b"hbin" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Missing hbin signature at relative 0x{:X}", offset),
            ));
        }

        let hbin_rel = u32::from_le_bytes(
            raw_data[bin_abs + 4..bin_abs + 8]
                .try_into()
                .unwrap_or_default(),
        ) as usize;

        if hbin_rel != offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "hbin relative offset mismatch: field 0x{:X} != actual 0x{:X}",
                    hbin_rel, offset
                ),
            ));
        }

        let hbin_size = u32::from_le_bytes(
            raw_data[bin_abs + 8..bin_abs + 12]
                .try_into()
                .unwrap_or_default(),
        ) as usize;

        if hbin_size == 0 || !hbin_size.is_multiple_of(4096) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid hbin size 0x{:X} at relative 0x{:X}",
                    hbin_size, offset
                ),
            ));
        }

        let mut cell = offset + HBIN_HEADER_SIZE;
        let bin_end = offset + hbin_size;

        while cell < bin_end {
            let cell_a = REG_HEAD_OFFSET + cell;
            if cell_a + 4 > raw_data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("Cell header at relative 0x{:X} exceeds file bounds", cell),
                ));
            }

            let cell_size =
                i32::from_le_bytes(raw_data[cell_a..cell_a + 4].try_into().unwrap_or_default());
            let abs_size = cell_size.unsigned_abs() as usize;

            if abs_size < MIN_CELL_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Invalid cell size {} (< 8) at relative 0x{:X}",
                        cell_size, cell
                    ),
                ));
            }

            if !abs_size.is_multiple_of(CELL_ALIGNMENT) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Cell size {} is not 8-byte aligned at relative 0x{:X}",
                        cell_size, cell
                    ),
                ));
            }

            cell += abs_size;
        }

        if cell != bin_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Cells in hbin at relative 0x{:X} do not end exactly at bin boundary: ended at 0x{:X}, expected 0x{:X}",
                    offset, cell, bin_end
                ),
            ));
        }

        offset += hbin_size;
    }

    let root_rel = base_block.root_cell_offset;
    validate_nk_graph(
        raw_data,
        base_block.hive_bins_data_size,
        root_rel,
        MAX_OFFSET,
    )?;

    Ok(())
}

fn validate_nk_graph(
    raw_data: &[u8],
    bins_data_sz: u32,
    nk_rel: u32,
    expected_parent: u32,
) -> io::Result<()> {
    if nk_rel >= bins_data_sz {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "NK cell relative 0x{:X} exceeds bins size 0x{:X}",
                nk_rel, bins_data_sz
            ),
        ));
    }

    let nk_abs = REG_HEAD_OFFSET + nk_rel as usize;
    if nk_abs + 4 > raw_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("NK cell relative 0x{:X} exceeds raw data length", nk_rel),
        ));
    }

    let cell_sz = i32::from_le_bytes(raw_data[nk_abs..nk_abs + 4].try_into().unwrap_or_default());
    if cell_sz >= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Referenced NK cell at relative 0x{:X} is marked FREE (size {})",
                nk_rel, cell_sz
            ),
        ));
    }

    let abs_sz = cell_sz.unsigned_abs() as usize;
    if abs_sz < 0x50 || nk_abs + abs_sz > raw_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "NK cell at relative 0x{:X} has invalid size {}",
                nk_rel, abs_sz
            ),
        ));
    }

    let nk_data = &raw_data[nk_abs + 4..nk_abs + abs_sz];
    if &nk_data[0..2] != b"nk" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Cell at relative 0x{:X} does not have 'nk' signature",
                nk_rel
            ),
        ));
    }

    let parent_rel = u32::from_le_bytes(nk_data[0x10..0x14].try_into().unwrap_or_default());
    if expected_parent != MAX_OFFSET && parent_rel != expected_parent {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "NK at relative 0x{:X} points to parent 0x{:X}, expected 0x{:X}",
                nk_rel, parent_rel, expected_parent
            ),
        ));
    }

    // Security cell ref
    let sec_rel = u32::from_le_bytes(nk_data[0x2C..0x30].try_into().unwrap_or_default());
    if sec_rel != MAX_OFFSET && sec_rel > 0 {
        if sec_rel >= bins_data_sz {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Security cell relative 0x{:X} exceeds bins size", sec_rel),
            ));
        }
        let sec_abs = REG_HEAD_OFFSET + sec_rel as usize;
        if sec_abs + 8 <= raw_data.len() {
            let s_sz = i32::from_le_bytes(
                raw_data[sec_abs..sec_abs + 4]
                    .try_into()
                    .unwrap_or_default(),
            );
            if s_sz >= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Referenced security cell at 0x{:X} is FREE", sec_rel),
                ));
            }
            if &raw_data[sec_abs + 4..sec_abs + 6] != b"sk" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Cell at relative 0x{:X} lacks 'sk' signature", sec_rel),
                ));
            }
        }
    }

    // value list and vk cells
    let (values, values_offset) = (
        u32::from_le_bytes(nk_data[0x24..0x28].try_into().unwrap_or_default()) as usize,
        u32::from_le_bytes(nk_data[0x28..0x2C].try_into().unwrap_or_default()),
    );

    if values > 0 && values_offset != MAX_OFFSET && values_offset > 0 {
        if values_offset >= bins_data_sz {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Value list relative 0x{:X} exceeds bins size",
                    values_offset
                ),
            ));
        }

        let values_a = REG_HEAD_OFFSET + values_offset as usize;
        if values_a + 4 > raw_data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Value list relative 0x{:X} exceeds file bounds",
                    values_offset
                ),
            ));
        }

        let values_sz = i32::from_le_bytes(
            raw_data[values_a..values_a + 4]
                .try_into()
                .unwrap_or_default(),
        );
        if values_sz >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Value list at relative 0x{:X} is FREE", values_offset),
            ));
        }

        for i in 0..values {
            let entry_p = values_a + 4 + i * 4;
            if entry_p + 4 > raw_data.len() {
                break;
            }

            let vk = u32::from_le_bytes(
                raw_data[entry_p..entry_p + 4]
                    .try_into()
                    .unwrap_or_default(),
            );
            if vk >= bins_data_sz {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VK relative 0x{:X} exceeds bins size", vk),
                ));
            }

            let vk_a = REG_HEAD_OFFSET + vk as usize;
            if vk_a + 6 <= raw_data.len() {
                let vk_sz =
                    i32::from_le_bytes(raw_data[vk_a..vk_a + 4].try_into().unwrap_or_default());
                if vk_sz >= 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Referenced VK cell at relative 0x{:X} is FREE", vk),
                    ));
                }
                if &raw_data[vk_a + 4..vk_a + 6] != b"vk" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Cell at relative 0x{:X} lacks 'vk' signature", vk),
                    ));
                }
            }
        }
    }

    let (subkeys, subkeys_offset) = (
        u32::from_le_bytes(nk_data[0x14..0x18].try_into().unwrap_or_default()) as usize,
        u32::from_le_bytes(nk_data[0x1C..0x20].try_into().unwrap_or_default()),
    );

    if subkeys > 0 && subkeys_offset != MAX_OFFSET && subkeys_offset > 0 {
        if subkeys_offset >= bins_data_sz {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Subkeys list relative 0x{:X} exceeds bins size",
                    subkeys_offset
                ),
            ));
        }

        let list_a = REG_HEAD_OFFSET + subkeys_offset as usize;
        if list_a + 8 > raw_data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "Subkeys list relative 0x{:X} exceeds file bounds",
                    subkeys_offset
                ),
            ));
        }
        let list_sz =
            i32::from_le_bytes(raw_data[list_a..list_a + 4].try_into().unwrap_or_default());
        if list_sz >= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Subkey list cell at relative 0x{:X} is FREE",
                    subkeys_offset
                ),
            ));
        }

        let child_offsets = parse_subkey_list_offsets(raw_data, bins_data_sz, subkeys_offset)?;
        for child in child_offsets {
            validate_nk_graph(raw_data, bins_data_sz, child, nk_rel)?;
        }
    }

    Ok(())
}

fn parse_subkey_list_offsets(
    raw_data: &[u8],
    bins_data_size: u32,
    list_rel: u32,
) -> io::Result<Vec<u32>> {
    let mut offsets = Vec::new();
    if list_rel >= bins_data_size {
        return Ok(offsets);
    }

    let list_a = REG_HEAD_OFFSET + list_rel as usize;
    if list_a + 8 > raw_data.len() {
        return Ok(offsets);
    }

    let sig = &raw_data[list_a + 4..list_a + 6];
    let count = u16::from_le_bytes(
        raw_data[list_a + 6..list_a + 8]
            .try_into()
            .unwrap_or_default(),
    ) as usize;

    match sig {
        b"lh" | b"lf" => {
            for i in 0..count {
                let entry_p = list_a + 8 + i * 8;
                if entry_p + 4 <= raw_data.len() {
                    let child = u32::from_le_bytes(
                        raw_data[entry_p..entry_p + 4]
                            .try_into()
                            .unwrap_or_default(),
                    );
                    offsets.push(child);
                }
            }
        }
        b"li" => {
            for i in 0..count {
                let entry_p = list_a + 8 + i * 4;
                if entry_p + 4 <= raw_data.len() {
                    let child = u32::from_le_bytes(
                        raw_data[entry_p..entry_p + 4]
                            .try_into()
                            .unwrap_or_default(),
                    );
                    offsets.push(child);
                }
            }
        }
        b"ri" => {
            for i in 0..count {
                let entry_p = list_a + 8 + i * 4;
                if entry_p + 4 <= raw_data.len() {
                    let sublist = u32::from_le_bytes(
                        raw_data[entry_p..entry_p + 4]
                            .try_into()
                            .unwrap_or_default(),
                    );

                    let mut sublist_offsets =
                        parse_subkey_list_offsets(raw_data, bins_data_size, sublist)?;
                    offsets.append(&mut sublist_offsets);
                }
            }
        }
        _ => {}
    }

    Ok(offsets)
}

/// computes the 32-bit hash used in REGF CM_KEY_HASH_LEAF (AKA `lf`).
///
/// `hash = hash * 37 + uppercase(char)`.
#[inline]
pub fn compute_lh_hash(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for c in name.chars() {
        let mut val = c as u32;
        if (0x61..=0x7A).contains(&val) {
            val = val - 0x61 + 0x41;
        } else if val > 0x7A {
            val = c.to_uppercase().next().unwrap_or(c) as u32;
        }
        hash = hash.wrapping_mul(37).wrapping_add(val);
    }
    hash
}

pub fn encode_key_name(name: &str) -> (Vec<u8>, u16, u16) {
    if name.chars().all(|c| (c as u32) <= 0xFF) {
        let bytes = name.bytes().collect::<Vec<u8>>();
        let len = bytes.len() as u16;
        (bytes, len, 0x0020)
    } else {
        let utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let len = utf16.len() as u16;
        (utf16, len, 0)
    }
}

pub fn encode_value_name(name: &str) -> (Vec<u8>, u16, u16) {
    if name.is_empty() {
        (Vec::new(), 0, 0)
    } else if name.chars().all(|c| (c as u32) <= 0xFF) {
        let bytes = name.bytes().collect::<Vec<u8>>();
        let len = bytes.len() as u16;
        (bytes, len, 0x0001)
    } else {
        let utf16: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let len = utf16.len() as u16;
        (utf16, len, 0)
    }
}

/// Returns the current Windows FILETIME (100-nanosecond intervals since January 1, 1601 UTC).
pub fn current_filetime() -> u64 {
    const SECS_BETWEEN_1601_AND_1970: u64 = 11_644_473_600;
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = duration.as_secs() + SECS_BETWEEN_1601_AND_1970;
    (total_secs * 10_000_000) + (duration.subsec_nanos() as u64 / 100)
}

pub fn get_key_name_at_cell(raw_data: &[u8], cell: u32) -> Option<String> {
    let nk_a = REG_HEAD_OFFSET + cell as usize;
    if nk_a + 4 + 0x4C > raw_data.len() || &raw_data[nk_a + 4..nk_a + 6] != b"nk" {
        return None;
    }

    let flags = u16::from_le_bytes(raw_data[nk_a + 6..nk_a + 8].try_into().ok()?);
    let name_len =
        u16::from_le_bytes(raw_data[nk_a + 4 + 0x48..nk_a + 4 + 0x4A].try_into().ok()?) as usize;

    if nk_a + 4 + 0x4C + name_len > raw_data.len() {
        return None;
    }

    let name_bytes = &raw_data[nk_a + 4 + 0x4C..nk_a + 4 + 0x4C + name_len];
    if (flags & 0x0020) != 0 {
        Some(String::from_utf8_lossy(name_bytes).to_string())
    } else {
        let utf16: Vec<u16> = name_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Some(String::from_utf16_lossy(&utf16))
    }
}

pub fn create_key_node(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    parent_offset: u32,
    name: &str,
    security_offset: u32,
) -> io::Result<(u32, usize)> {
    let (name_bytes, name_len, flags) = encode_key_name(name);
    let payload_size = 0x4C + name_bytes.len();
    let nk = allocate_cell(raw_data, base_block, payload_size)?;
    let nk_a = REG_HEAD_OFFSET + nk as usize;

    raw_data[nk_a + 4..nk_a + 4 + payload_size].fill(0);

    // 0x00: Signature "nk"
    raw_data[nk_a + 4..nk_a + 6].copy_from_slice(b"nk");

    // 0x02: Flags
    raw_data[nk_a + 6..nk_a + 8].copy_from_slice(&flags.to_le_bytes());

    // 0x04: LastWriteTime
    let time = current_filetime();
    raw_data[nk_a + 8..nk_a + 16].copy_from_slice(&time.to_le_bytes());

    // 0x10: Parent cell relative offset
    raw_data[nk_a + 0x14..nk_a + 0x18].copy_from_slice(&parent_offset.to_le_bytes());

    // 0x14: SubKeyCounts[0] = 0 (stable)
    // 0x18: SubKeyCounts[1] = 0 (volatile)

    // 0x1C: SubKeyLists[0] = MAX_OFFSET
    raw_data[nk_a + 0x20..nk_a + 0x24].copy_from_slice(&MAX_OFFSET.to_le_bytes());
    // 0x20: SubKeyLists[1] = MAX_OFFSET
    raw_data[nk_a + 0x24..nk_a + 0x28].copy_from_slice(&MAX_OFFSET.to_le_bytes());

    // 0x24: ValueList.Count = 0
    // 0x28: ValueList.List = MAX_OFFSET
    raw_data[nk_a + 0x2C..nk_a + 0x30].copy_from_slice(&MAX_OFFSET.to_le_bytes());

    // 0x2C: SecurityKeyOffset
    raw_data[nk_a + 0x30..nk_a + 0x34].copy_from_slice(&security_offset.to_le_bytes());

    // 0x30: ClassNameOffset = MAX_OFFSET
    raw_data[nk_a + 0x34..nk_a + 0x38].copy_from_slice(&MAX_OFFSET.to_le_bytes());

    // 0x48: NameLength
    raw_data[nk_a + 0x4C..nk_a + 0x4E].copy_from_slice(&name_len.to_le_bytes());

    // 0x4C: Name bytes
    raw_data[nk_a + 0x50..nk_a + 0x50 + name_bytes.len()].copy_from_slice(&name_bytes);

    // Increment ReferenceCount in the security cell
    if security_offset != MAX_OFFSET && security_offset > 0 {
        let sec_abs = REG_HEAD_OFFSET + security_offset as usize;
        if sec_abs + 0x14 <= raw_data.len() && &raw_data[sec_abs + 4..sec_abs + 6] == b"sk" {
            let rc_pos = sec_abs + 4 + 0x0C;
            let current_rc =
                u32::from_le_bytes(raw_data[rc_pos..rc_pos + 4].try_into().unwrap_or_default());
            raw_data[rc_pos..rc_pos + 4]
                .copy_from_slice(&current_rc.saturating_add(1).to_le_bytes());
        }
    }

    let cell_size =
        i32::from_le_bytes(raw_data[nk_a..nk_a + 4].try_into().unwrap()).unsigned_abs() as usize;
    Ok((nk, cell_size))
}

pub fn add_subkey_to_parent(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    parent_rel_offset: u32,
    child_rel_offset: u32,
    child_name: &str,
) -> io::Result<u32> {
    let parent_abs = REG_HEAD_OFFSET + parent_rel_offset as usize;
    if parent_abs + 0x50 > raw_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Parent NK out of bounds",
        ));
    }

    let subkeys = u32::from_le_bytes(
        raw_data[parent_abs + 4 + 0x14..parent_abs + 4 + 0x18]
            .try_into()
            .unwrap_or_default(),
    );
    let subkeys_offset = u32::from_le_bytes(
        raw_data[parent_abs + 4 + 0x1C..parent_abs + 4 + 0x20]
            .try_into()
            .unwrap_or_default(),
    );

    let f_list = if subkeys == 0 || subkeys_offset == MAX_OFFSET {
        // no subkeys only
        let leaf = allocate_cell(raw_data, base_block, 4 + 4 * 8)?;
        let leaf_a = REG_HEAD_OFFSET + leaf as usize;

        raw_data[leaf_a + 4..leaf_a + 6].copy_from_slice(b"lh");
        raw_data[leaf_a + 6..leaf_a + 8].copy_from_slice(&1u16.to_le_bytes());
        raw_data[leaf_a + 8..leaf_a + 12].copy_from_slice(&child_rel_offset.to_le_bytes());
        let hash = compute_lh_hash(child_name);
        raw_data[leaf_a + 12..leaf_a + 16].copy_from_slice(&hash.to_le_bytes());

        raw_data[parent_abs + 4 + 0x14..parent_abs + 4 + 0x18].copy_from_slice(&1u32.to_le_bytes());
        raw_data[parent_abs + 4 + 0x1C..parent_abs + 4 + 0x20].copy_from_slice(&leaf.to_le_bytes());
        leaf
    } else {
        let list_abs = REG_HEAD_OFFSET + subkeys_offset as usize;
        let sig = [raw_data[list_abs + 4], raw_data[list_abs + 5]];

        // has index root
        if &sig == b"ri" {
            let ri = u16::from_le_bytes(
                raw_data[list_abs + 6..list_abs + 8]
                    .try_into()
                    .unwrap_or_default(),
            ) as usize;
            let mut leaf_idx = 0;

            for i in 0..ri {
                let leaf_rel = u32::from_le_bytes(
                    raw_data[list_abs + 8 + i * 4..list_abs + 12 + i * 4]
                        .try_into()
                        .unwrap_or_default(),
                );
                let l_abs = REG_HEAD_OFFSET + leaf_rel as usize;
                let l_cnt = u16::from_le_bytes(
                    raw_data[l_abs + 6..l_abs + 8]
                        .try_into()
                        .unwrap_or_default(),
                ) as usize;

                if l_cnt == 0 {
                    leaf_idx = i;
                    break;
                }

                let last_entry = l_abs + 8 + (l_cnt - 1) * 8;
                if last_entry + 4 <= raw_data.len() {
                    let last_c_rel = u32::from_le_bytes(
                        raw_data[last_entry..last_entry + 4]
                            .try_into()
                            .unwrap_or_default(),
                    );
                    if let Some(last_name) = get_key_name_at_cell(raw_data, last_c_rel)
                        && child_name.to_lowercase() <= last_name.to_lowercase()
                    {
                        leaf_idx = i;
                        break;
                    }
                }
                leaf_idx = i;
            }

            let cur_leaf = u32::from_le_bytes(
                raw_data[list_abs + 8 + leaf_idx * 4..list_abs + 12 + leaf_idx * 4]
                    .try_into()
                    .unwrap_or_default(),
            );
            let updated_leaf =
                insert_into_leaf(raw_data, base_block, cur_leaf, child_rel_offset, child_name)?;

            if updated_leaf != cur_leaf {
                raw_data[list_abs + 8 + leaf_idx * 4..list_abs + 12 + leaf_idx * 4]
                    .copy_from_slice(&updated_leaf.to_le_bytes());
            }

            raw_data[parent_abs + 4 + 0x14..parent_abs + 4 + 0x18]
                .copy_from_slice(&(subkeys + 1).to_le_bytes());
            subkeys_offset
        } else {
            // single leaf
            let updated_leaf_rel = insert_into_leaf(
                raw_data,
                base_block,
                subkeys_offset,
                child_rel_offset,
                child_name,
            )?;
            raw_data[parent_abs + 4 + 0x14..parent_abs + 4 + 0x18]
                .copy_from_slice(&(subkeys + 1).to_le_bytes());

            if updated_leaf_rel != subkeys_offset {
                raw_data[parent_abs + 4 + 0x1C..parent_abs + 4 + 0x20]
                    .copy_from_slice(&updated_leaf_rel.to_le_bytes());
            }
            updated_leaf_rel
        }
    };

    // update MaxNameLen
    let utf16_len = (child_name.chars().count() * 2) as u32;
    let c_max_len = u32::from_le_bytes(
        raw_data[parent_abs + 4 + 0x34..parent_abs + 4 + 0x38]
            .try_into()
            .unwrap_or_default(),
    );

    if utf16_len > c_max_len {
        raw_data[parent_abs + 4 + 0x34..parent_abs + 4 + 0x38]
            .copy_from_slice(&utf16_len.to_le_bytes());
    }

    // update LastWriteTime
    let now = current_filetime();
    raw_data[parent_abs + 4 + 0x04..parent_abs + 4 + 0x0C].copy_from_slice(&now.to_le_bytes());

    Ok(f_list)
}

/// Inserts a child entry into an `lh`, `lf`, or `li` leaf cell in alphabetical order.
fn insert_into_leaf(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    leaf: u32,
    child: u32,
    child_name: &str,
) -> io::Result<u32> {
    let leaf_a = REG_HEAD_OFFSET + leaf as usize;
    let sig = [raw_data[leaf_a + 4], raw_data[leaf_a + 5]];

    let count = u16::from_le_bytes(
        raw_data[leaf_a + 6..leaf_a + 8]
            .try_into()
            .unwrap_or_default(),
    ) as usize;
    let entry_sz = if &sig == b"li" { 4 } else { 8 };
    let mut insert_idx = count;

    for i in 0..count {
        let entry_p = leaf_a + 8 + i * entry_sz;
        let c_rel = u32::from_le_bytes(
            raw_data[entry_p..entry_p + 4]
                .try_into()
                .unwrap_or_default(),
        );

        if let Some(existing_name) = get_key_name_at_cell(raw_data, c_rel)
            && child_name.to_lowercase() < existing_name.to_lowercase()
        {
            insert_idx = i;
            break;
        }
    }

    let mut entry_b = [0u8; 8];
    entry_b[0..4].copy_from_slice(&child.to_le_bytes());
    if &sig == b"lh" {
        let hash = compute_lh_hash(child_name);
        entry_b[4..8].copy_from_slice(&hash.to_le_bytes());
    } else if &sig == b"lf" {
        for (idx, ch) in child_name.chars().take(4).enumerate() {
            if (ch as u32) <= 0xFF {
                entry_b[4 + idx] = ch.to_ascii_uppercase() as u8;
            }
        }
    }

    let cell_sz = i32::from_le_bytes(raw_data[leaf_a..leaf_a + 4].try_into().unwrap())
        .unsigned_abs() as usize;
    let cap = cell_capacity(cell_sz as i32);
    let needed = 4 + (count + 1) * entry_sz;

    if needed <= cap {
        if insert_idx < count {
            let src_start = leaf_a + 8 + insert_idx * entry_sz;
            let src_end = leaf_a + 8 + count * entry_sz;
            let dst_start = src_start + entry_sz;
            raw_data.copy_within(src_start..src_end, dst_start);
        }

        let write_pos = leaf_a + 8 + insert_idx * entry_sz;
        raw_data[write_pos..write_pos + entry_sz].copy_from_slice(&entry_b[..entry_sz]);
        raw_data[leaf_a + 6..leaf_a + 8].copy_from_slice(&((count + 1) as u16).to_le_bytes());
        Ok(leaf)
    } else {
        let new_c_entries = count + 4;
        let new_leaf = allocate_cell(raw_data, base_block, 4 + new_c_entries * entry_sz)?;
        let new_leaf_a = REG_HEAD_OFFSET + new_leaf as usize;

        raw_data[new_leaf_a + 4..new_leaf_a + 6].copy_from_slice(&sig);
        raw_data[new_leaf_a + 6..new_leaf_a + 8]
            .copy_from_slice(&((count + 1) as u16).to_le_bytes());

        if insert_idx > 0 {
            let old_src = leaf_a + 8;
            let new_dst = new_leaf_a + 8;
            raw_data.copy_within(old_src..old_src + insert_idx * entry_sz, new_dst);
        }

        let write_pos = new_leaf_a + 8 + insert_idx * entry_sz;
        raw_data[write_pos..write_pos + entry_sz].copy_from_slice(&entry_b[..entry_sz]);

        if insert_idx < count {
            let old_src = leaf_a + 8 + insert_idx * entry_sz;
            let new_dst = write_pos + entry_sz;
            raw_data.copy_within(old_src..old_src + (count - insert_idx) * entry_sz, new_dst);
        }

        free_cell(raw_data, leaf, base_block.hive_bins_data_size);
        Ok(new_leaf)
    }
}

pub fn create_value_node(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    value_name: &str,
    value_type: u32,
    data: &[u8],
) -> io::Result<(u32, usize)> {
    let (data_size, data_offset, _inline) = allocate_value_data(raw_data, base_block, data)?;
    let (name_bytes, name_len, flags) = encode_value_name(value_name);
    let payload_size = 0x14 + name_bytes.len();

    let vk = allocate_cell(raw_data, base_block, payload_size)?;
    let vk_a = REG_HEAD_OFFSET + vk as usize;

    raw_data[vk_a + 4..vk_a + 6].copy_from_slice(b"vk");
    // 0x02: NameLength
    raw_data[vk_a + 6..vk_a + 8].copy_from_slice(&name_len.to_le_bytes());
    // 0x04: DataLength (includes INLINE_DATA_FLAG if inline)
    raw_data[vk_a + 8..vk_a + 12].copy_from_slice(&data_size.to_le_bytes());
    // 0x08: DataOffset
    raw_data[vk_a + 12..vk_a + 16].copy_from_slice(&data_offset.to_le_bytes());
    // 0x0C: Type
    raw_data[vk_a + 16..vk_a + 20].copy_from_slice(&value_type.to_le_bytes());
    // 0x10: Flags (VALUE_COMP_NAME = 0x0001 if ASCII)
    raw_data[vk_a + 20..vk_a + 22].copy_from_slice(&flags.to_le_bytes());
    // 0x12: Spare
    raw_data[vk_a + 22..vk_a + 24].copy_from_slice(&0u16.to_le_bytes());
    // 0x14: Name bytes
    if !name_bytes.is_empty() {
        raw_data[vk_a + 24..vk_a + 24 + name_bytes.len()].copy_from_slice(&name_bytes);
    }

    let cell_sz =
        i32::from_le_bytes(raw_data[vk_a..vk_a + 4].try_into().unwrap()).unsigned_abs() as usize;
    Ok((vk, cell_sz))
}

pub fn add_value_to_parent(
    raw_data: &mut Vec<u8>,
    base_block: &mut RegHeader,
    parent_offset: u32,
    vk_offset: u32,
    val_name_chars: usize,
    val_data_len: usize,
) -> io::Result<u32> {
    let parent_abs = REG_HEAD_OFFSET + parent_offset as usize;
    if parent_abs + 0x50 > raw_data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Parent NK out of bounds",
        ));
    }

    let val = u32::from_le_bytes(
        raw_data[parent_abs + 4 + 0x24..parent_abs + 4 + 0x28]
            .try_into()
            .unwrap_or_default(),
    );
    let val_l_offset = u32::from_le_bytes(
        raw_data[parent_abs + 4 + 0x28..parent_abs + 4 + 0x2C]
            .try_into()
            .unwrap_or_default(),
    );

    let f_list = if val == 0 || val_l_offset == MAX_OFFSET {
        let list = allocate_cell(raw_data, base_block, 16)?;
        let list_a = REG_HEAD_OFFSET + list as usize;
        raw_data[list_a + 4..list_a + 8].copy_from_slice(&vk_offset.to_le_bytes());

        raw_data[parent_abs + 4 + 0x24..parent_abs + 4 + 0x28].copy_from_slice(&1u32.to_le_bytes());
        raw_data[parent_abs + 4 + 0x28..parent_abs + 4 + 0x2C].copy_from_slice(&list.to_le_bytes());
        list
    } else {
        let list_a = REG_HEAD_OFFSET + val_l_offset as usize;
        let cell_sz = i32::from_le_bytes(raw_data[list_a..list_a + 4].try_into().unwrap())
            .unsigned_abs() as usize;
        let cap = cell_capacity(cell_sz as i32) / 4;

        if (val as usize + 1) <= cap {
            let entry_p = list_a + 4 + (val as usize) * 4;
            raw_data[entry_p..entry_p + 4].copy_from_slice(&vk_offset.to_le_bytes());
            raw_data[parent_abs + 4 + 0x24..parent_abs + 4 + 0x28]
                .copy_from_slice(&(val + 1).to_le_bytes());
            val_l_offset
        } else {
            let new_cap = val as usize + 4;
            let new_list = allocate_cell(raw_data, base_block, new_cap * 4)?;
            let new_list_a = REG_HEAD_OFFSET + new_list as usize;

            let old_len = (val as usize) * 4;
            raw_data.copy_within(list_a + 4..list_a + 4 + old_len, new_list_a + 4);

            let new_entry_p = new_list_a + 4 + old_len;
            raw_data[new_entry_p..new_entry_p + 4].copy_from_slice(&vk_offset.to_le_bytes());

            free_cell(raw_data, val_l_offset, base_block.hive_bins_data_size);

            raw_data[parent_abs + 4 + 0x24..parent_abs + 4 + 0x28]
                .copy_from_slice(&(val + 1).to_le_bytes());
            raw_data[parent_abs + 4 + 0x28..parent_abs + 4 + 0x2C]
                .copy_from_slice(&new_list.to_le_bytes());
            new_list
        }
    };

    // update parent MaxValueNameLen
    let val_name_l = (val_name_chars * 2) as u32;
    let cur_max_name = u32::from_le_bytes(
        raw_data[parent_abs + 4 + 0x3C..parent_abs + 4 + 0x40]
            .try_into()
            .unwrap_or_default(),
    );
    if val_name_l > cur_max_name {
        raw_data[parent_abs + 4 + 0x3C..parent_abs + 4 + 0x40]
            .copy_from_slice(&val_name_l.to_le_bytes());
    }

    // update parent MaxValueDataLen
    let cur_max_data = u32::from_le_bytes(
        raw_data[parent_abs + 4 + 0x40..parent_abs + 4 + 0x44]
            .try_into()
            .unwrap_or_default(),
    );
    if (val_data_len as u32) > cur_max_data {
        raw_data[parent_abs + 4 + 0x40..parent_abs + 4 + 0x44]
            .copy_from_slice(&(val_data_len as u32).to_le_bytes());
    }

    // update parent LastWriteTime
    let now = current_filetime();
    raw_data[parent_abs + 4 + 0x04..parent_abs + 4 + 0x0C].copy_from_slice(&now.to_le_bytes());

    Ok(f_list)
}

/// Create an empty, valid Windows regf binary hive in memory following ReactOS structure
pub fn create_empty_hive(root_name: &str) -> io::Result<(RegHeader, Vec<u8>)> {
    let total_file_size = REG_HEAD_OFFSET + INITIAL_BIN_SIZE; // 8192 bytes
    let mut raw_data = vec![0u8; total_file_size];

    let now_ft = current_filetime();

    let (name_bytes, name_len, name_flags) = encode_key_name(root_name);
    let nk_payload = 0x4C + name_bytes.len();
    let nk_cell_sz = align_cell_size(nk_payload);
    let root_rel = 0x20u32; // starts right after 32-byte hbin header

    // security cell placement
    let sec_rel = root_rel + nk_cell_sz as u32;
    let sec_desc = &DEFAULT_SYSTEM_SECURITY_DESCRIPTOR;
    let sec_payload = 20 + sec_desc.len();
    let sec_cell_sz = align_cell_size(sec_payload);

    // check remaining free cell space
    let free_rel = sec_rel + sec_cell_sz as u32;
    if (free_rel as usize) > INITIAL_BIN_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Root key name is too long to fit in initial 4KB hbin",
        ));
    }
    let free_cell_sz = INITIAL_BIN_SIZE - (free_rel as usize);

    raw_data[0..4].copy_from_slice(b"regf");
    // 0x04: Sequence1 = 1
    raw_data[4..8].copy_from_slice(&1u32.to_le_bytes());
    // 0x08: Sequence2 = 1
    raw_data[8..12].copy_from_slice(&1u32.to_le_bytes());
    // 0x0C: TimeStamp
    raw_data[12..20].copy_from_slice(&now_ft.to_le_bytes());
    // 0x14: Major version = 1
    raw_data[20..24].copy_from_slice(&1u32.to_le_bytes());
    // 0x18: Minor version = 5 (Windows XP/2003 through Windows 11)
    raw_data[24..28].copy_from_slice(&5u32.to_le_bytes());
    // 0x1C: Type = 0 (Primary)
    raw_data[28..32].copy_from_slice(&0u32.to_le_bytes());
    // 0x20: Format = 1 (Direct store)
    raw_data[32..36].copy_from_slice(&1u32.to_le_bytes());
    // 0x24: Root cell offset
    raw_data[36..40].copy_from_slice(&root_rel.to_le_bytes());
    // 0x28: Hive bins data size = 4096 (0x1000)
    raw_data[40..44].copy_from_slice(&(INITIAL_BIN_SIZE as u32).to_le_bytes());
    // 0x2C: Clustering factor = 1
    raw_data[44..48].copy_from_slice(&1u32.to_le_bytes());

    // build checksum over first 508 bytes
    let mut checksum = 0u32;
    for chunk in raw_data[0..508].as_chunks::<4>().0 {
        checksum ^= u32::from_le_bytes(*chunk);
    }
    raw_data[508..512].copy_from_slice(&checksum.to_le_bytes());

    let hbin_start = REG_HEAD_OFFSET;
    raw_data[hbin_start..hbin_start + 4].copy_from_slice(b"hbin");
    raw_data[hbin_start + 4..hbin_start + 8].copy_from_slice(&0u32.to_le_bytes()); // FileOffset = 0
    raw_data[hbin_start + 8..hbin_start + 12]
        .copy_from_slice(&(INITIAL_BIN_SIZE as u32).to_le_bytes());
    raw_data[hbin_start + 16..hbin_start + 24].copy_from_slice(&now_ft.to_le_bytes());

    let root_a = hbin_start + root_rel as usize;
    let nk_size = -(nk_cell_sz as i32);
    raw_data[root_a..root_a + 4].copy_from_slice(&nk_size.to_le_bytes());

    let root_nk = root_a + 4;
    raw_data[root_nk..root_nk + 2].copy_from_slice(b"nk");

    // Flags: KEY_HIVE_ENTRY (0x0004) | KEY_NO_DELETE (0x0008) | (KEY_COMP_NAME if ASCII)
    let root_flags = 0x000Cu16 | name_flags;
    raw_data[root_nk + 2..root_nk + 4].copy_from_slice(&root_flags.to_le_bytes());
    raw_data[root_nk + 4..root_nk + 12].copy_from_slice(&now_ft.to_le_bytes());
    // Parent = MAX_OFFSET (0xFFFFFFFF)
    raw_data[root_nk + 0x10..root_nk + 0x14].copy_from_slice(&MAX_OFFSET.to_le_bytes());
    // SubKeyCounts[0..2] = 0
    raw_data[root_nk + 0x14..root_nk + 0x1C].fill(0);
    // SubKeyLists[0..2] = MAX_OFFSET
    raw_data[root_nk + 0x1C..root_nk + 0x24].copy_from_slice(&[0xFF; 8]);
    // ValueList.Count = 0, ValueList.List = MAX_OFFSET
    raw_data[root_nk + 0x24..root_nk + 0x28].copy_from_slice(&0u32.to_le_bytes());
    raw_data[root_nk + 0x28..root_nk + 0x2C].copy_from_slice(&MAX_OFFSET.to_le_bytes());
    // SecurityKeyOffset = sec_rel
    raw_data[root_nk + 0x2C..root_nk + 0x30].copy_from_slice(&sec_rel.to_le_bytes());
    // ClassNameOffset = MAX_OFFSET
    raw_data[root_nk + 0x30..root_nk + 0x34].copy_from_slice(&MAX_OFFSET.to_le_bytes());
    // NameLength
    raw_data[root_nk + 0x48..root_nk + 0x4A].copy_from_slice(&name_len.to_le_bytes());
    // Name bytes
    if !name_bytes.is_empty() {
        raw_data[root_nk + 0x4C..root_nk + 0x4C + name_bytes.len()].copy_from_slice(&name_bytes);
    }

    let sec_a = hbin_start + sec_rel as usize;
    let sec_sz = -(sec_cell_sz as i32);
    raw_data[sec_a..sec_a + 4].copy_from_slice(&sec_sz.to_le_bytes());

    let sk_cell = sec_a + 4;
    raw_data[sk_cell..sk_cell + 2].copy_from_slice(b"sk");
    raw_data[sk_cell + 2..sk_cell + 4].copy_from_slice(&0u16.to_le_bytes()); // Reserved
    raw_data[sk_cell + 4..sk_cell + 8].copy_from_slice(&sec_rel.to_le_bytes()); // Flink -> self
    raw_data[sk_cell + 8..sk_cell + 12].copy_from_slice(&sec_rel.to_le_bytes()); // Blink -> self
    raw_data[sk_cell + 12..sk_cell + 16].copy_from_slice(&1u32.to_le_bytes()); // ReferenceCount = 1
    raw_data[sk_cell + 16..sk_cell + 20].copy_from_slice(&(sec_desc.len() as u32).to_le_bytes());
    raw_data[sk_cell + 20..sk_cell + 20 + sec_desc.len()].copy_from_slice(sec_desc);

    let free_a = hbin_start + free_rel as usize;
    raw_data[free_a..free_a + 4].copy_from_slice(&(free_cell_sz as i32).to_le_bytes());

    let base_block = RegHeader::parse(&raw_data[0..REG_HEAD_OFFSET])?;

    Ok((base_block, raw_data))
}
