// src/constants.rs

pub const FALCON_DET1024_LOGN: u32 = 10;
pub const FALCON_DET1024_PUBKEY_SIZE: usize = 1793;
pub const FALCON_DET1024_PRIVKEY_SIZE: usize = 2305;

// Deterministic sigs replace the 40-byte random salt with a 1-byte salt version.
// FALCON_SIG_COMPRESSED_MAXSIZE(10) = (((11<<10) + (101>>0) + 7) >> 3) + 41 = 1462
// FALCON_DET1024_SIG_COMPRESSED_MAXSIZE = 1462 - 40 + 1 = 1423
pub const FALCON_DET1024_SIG_COMPRESSED_MAXSIZE: usize = 1423;
pub const FALCON_DET1024_SIG_CT_SIZE: usize = 1538; // FALCON_SIG_CT_SIZE(10) - 40 + 1

pub const FALCON_DET1024_SIG_COMPRESSED_HEADER: u8 = 0x3A | 0x80; // 0xBA
pub const FALCON_DET1024_SIG_CT_HEADER: u8 = 0x5A | 0x80; // 0xDA

pub const FALCON_DET1024_CURRENT_SALT_VERSION: u8 = 0;

// SHAKE-256 internal layout constants.
pub const SHAKE256_STATE_WORDS: usize = 25;  // Keccak-1600: 25 x u64 = 200 bytes
pub const SHAKE256_RATE: u64 = 136; // rate in bytes; dptr is always 136 after init
pub const SHAKE256_CONTEXT_SIZE: usize = 208; // 25xu64 (st) + u64 (dptr)

pub const FALCON_DET1024_N: usize = 1024; // polynomial degree: 1 << FALCON_DET1024_LOGN
