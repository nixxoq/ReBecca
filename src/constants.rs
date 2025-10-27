pub const REG_HEAD_OFFSET: usize = 4096;
pub const MAX_OFFSET: u32 = 0xFFFFFFFF;
pub const INLINE_DATA_FLAG: u32 = 0x80000000;
pub const HEADER_NAME: &[u8; 4] = b"regf";
pub const MIN_REG_SIZE: usize = 512;

// Signature type
pub const SIGNATURE_LEAF_HASH_1: &[u8] = b"lf";
pub const SIGNATURE_LEAF_HASH_2: &[u8] = b"lh";
pub const SIGNATURE_LEAF: &[u8] = b"li";
pub const SIGNATURE_ROOT_INDEX: &[u8] = b"ri";
