// src/constants.rs

// ─── Key Sizes ───────────────────────────────────────────────────────────────
pub const FALCON_DET1024_PUBKEY_SIZE: usize = 1793;
pub const FALCON_DET1024_PRIVKEY_SIZE: usize = 2305;

// ─── Polynomial Degree ───────────────────────────────────────────────────────
pub const FALCON_DET1024_N: usize = 1024; // 1 << FALCON_DET1024_LOGN

// ─── Signature Sizes ─────────────────────────────────────────────────────────
//
// Deterministic signatures replace the 40-byte random salt with a 1-byte salt version field.
// FALCON_SIG_COMPRESSED_MAXSIZE(10) = (((11<<10) + (101>>0) + 7) >> 3) + 41 = 1462
// FALCON_DET1024_SIG_COMPRESSED_MAXSIZE = 1462 - 40 + 1 = 1423
// FALCON_DET1024_SIG_CT_SIZE = FALCON_SIG_CT_SIZE(10) - 40 + 1 = 1538

pub const FALCON_DET1024_SIG_COMPRESSED_MAXSIZE: usize = 1423;
pub const FALCON_DET1024_SIG_CT_SIZE: usize = 1538;

// ─── Signature Header Bytes ───────────────────────────────────────────────────
pub const FALCON_DET1024_SIG_COMPRESSED_HEADER: u8 = 0x3A | 0x80; // 0xBA
pub const FALCON_DET1024_SIG_CT_HEADER: u8 = 0x5A | 0x80;         // 0xDA

// ─── Salt Version ────────────────────────────────────────────────────────────
pub const FALCON_DET1024_CURRENT_SALT_VERSION: u8 = 0;

// ─── SHAKE-256 Internal Layout (Keccak-1600 Sponge) ──────────────────────────
pub(crate) const SHAKE256_STATE_WORDS: usize = 25; // 25 × u64 = 200 bytes of Keccak state
#[cfg(test)]
pub const SHAKE256_RATE: u64 = 136; // squeeze rate in bytes; dptr = 136 after init
#[cfg(test)]
pub const SHAKE256_CONTEXT_SIZE: usize = 208; // 200 (st) + 8 (dptr)
