// src/constants.rs

// ─── Key Sizes ───────────────────────────────────────────────────────────────

/// Encoded size in bytes of a Falcon-det1024 public key.
pub const FALCON_DET1024_PUBKEY_SIZE: usize = 1793;

/// Encoded size in bytes of a Falcon-det1024 private key.
pub const FALCON_DET1024_PRIVKEY_SIZE: usize = 2305;

// ─── Polynomial Degree ───────────────────────────────────────────────────────

/// Falcon-1024 polynomial degree (N = 2^10).
pub(crate) const FALCON_DET1024_N: usize = 1024;

// ─── Signature Sizes ─────────────────────────────────────────────────────────
//
// Standard Falcon-1024 sizes (FALCON_SIG_*_SIZE(logn=10) from falcon.h):
//   compressed max: 1462 bytes
//   CT fixed:       1577 bytes
//
// The det1024 variant replaces the 40-byte random nonce with a 1-byte
// salt version field, reducing each size by 39 bytes (−40 + 1):
//   compressed max: 1462 − 40 + 1 = 1423
//   CT fixed:       1577 − 40 + 1 = 1538

/// Maximum encoded size in bytes of a Falcon-det1024 compressed signature.
pub const FALCON_DET1024_SIG_COMPRESSED_MAXSIZE: usize = 1423;

/// Fixed encoded size in bytes of a Falcon-det1024 constant-time (CT) signature.
pub const FALCON_DET1024_SIG_CT_SIZE: usize = 1538;

// ─── Signature Header Bytes ───────────────────────────────────────────────────

/// First byte of a valid Falcon-det1024 compressed signature (0xBA).
pub const FALCON_DET1024_SIG_COMPRESSED_HEADER: u8 = 0x3A | 0x80;

/// First byte of a valid Falcon-det1024 CT signature (0xDA).
pub const FALCON_DET1024_SIG_CT_HEADER: u8 = 0x5A | 0x80;

// ─── Salt Version ────────────────────────────────────────────────────────────

/// Salt version embedded in the second byte of every Falcon-det1024 signature.
pub const FALCON_DET1024_CURRENT_SALT_VERSION: u8 = 0;

// ─── SHAKE-256 Internal Layout (Keccak-1600 Sponge) ──────────────────────────

/// Number of 64-bit lanes in the Keccak-f[1600] permutation state (25 · u64 = 1600 bits).
pub(crate) const SHAKE256_STATE_LANES: usize = 25;
