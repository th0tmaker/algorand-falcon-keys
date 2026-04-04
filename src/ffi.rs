// src/ffi.rs

use std::os::raw::{c_int, c_void};

use crate::constants::SHAKE256_STATE_WORDS;
use crate::zeroize::Zeroize;

/// Sponge state for the SHAKE-256 extendable-output function, used as Falcon's PRNG.
///
/// Mirrors `shake256_context` from `falcon.h` and must remain ABI-compatible with it
/// (`#[repr(C)]`). The lifecycle is: seed → absorb (`shake256_init_prng_from_seed`) →
/// squeeze (`shake256_extract`). Each instance is seeded independently and must not be
/// shared across concurrent callers. The vendor C library zeroes this state on init
/// but has no cleanup function; the `Drop` impl here handles zeroing on the Rust side.
#[derive(Debug, Default)]
#[repr(C)]
pub struct Shake256Context {
    /// The 1600-bit (200-byte) Keccak-f[1600] permutation state, stored as 25 × u64.
    /// Each call to `shake256_init_prng_from_seed` loads a unique seed here,
    /// producing an independent PRNG stream. Never share this across contexts.
    pub st: [u64; SHAKE256_STATE_WORDS],
    /// Byte offset into the current squeezed block (the "output pointer").
    /// - `0`   → not yet initialized / absorb phase
    /// - `136` → a fresh rate block is ready; the next squeeze will read from byte 0
    /// - `1–135` → mid-extraction; bytes up to this offset have already been consumed
    ///
    /// SHAKE-256 has a rate of 136 bytes (= 1600 − 2×256 bits security margin).
    /// When `dptr` reaches 136, the Keccak permutation is applied again to refill.
    pub dptr: u64,
}

impl Drop for Shake256Context {
    fn drop(&mut self) {
        self.st.zeroize();
        self.dptr.zeroize();
    }
}

unsafe extern "C" {
    /// Absorbs `seed` into `sc`, leaving it ready to squeeze randomness.
    /// Must be called before passing `sc` to `falcon_det1024_keygen`.
    pub fn shake256_init_prng_from_seed(
        sc: *mut Shake256Context,
        seed: *const c_void,
        seed_len: usize,
    );

    /// Generates a Falcon-det1024 keypair driven by the PRNG state in `rng`.
    /// Writes `FALCON_DET1024_PRIVKEY_SIZE` bytes to `privkey`
    /// and `FALCON_DET1024_PUBKEY_SIZE` bytes to `pubkey`.
    pub fn falcon_det1024_keygen(
        rng: *mut Shake256Context,
        privkey: *mut c_void,
        pubkey: *mut c_void,
    ) -> c_int;

    /// Signs `data` with `privkey`, writing a variable-length compressed signature to `sig`
    /// and its byte length to `sig_len`. Returns 0 on success.
    pub fn falcon_det1024_sign_compressed(
        sig: *mut c_void,
        sig_len: *mut usize,
        privkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;

    /// Verifies a compressed signature over `data` against `pubkey`.
    /// Returns 0 if valid, -4 if the signature is rejected, or another non-zero code on error.
    pub fn falcon_det1024_verify_compressed(
        sig: *const c_void,
        sig_len: usize,
        pubkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;

    /// Returns the salt version embedded in the compressed signature header byte.
    #[cfg(test)]
    pub fn falcon_det1024_get_salt_version(sig: *const c_void) -> c_int;

    /// Converts a compressed signature to constant-time (CT) format, writing
    /// exactly `FALCON_DET1024_SIG_CT_SIZE` bytes to `sig_ct`. Returns 0 on success.
    pub fn falcon_det1024_convert_compressed_to_ct(
        sig_ct: *mut c_void,
        sig_compressed: *const c_void,
        sig_compressed_len: usize,
    ) -> c_int;

    /// Verifies a constant-time format signature over `data` against `pubkey`.
    /// Returns 0 if valid, -4 if the signature is rejected, or another non-zero code on error.
    pub fn falcon_det1024_verify_ct(
        sig: *const c_void,
        pubkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;

    /// Decodes `pubkey` into its `N` NTT coefficients, writing them to `h`.
    /// Returns 0 on success, non-zero if the encoding is malformed.
    pub fn falcon_det1024_pubkey_coeffs(h: *mut u16, pubkey: *const c_void) -> c_int;

    /// Hashes `data` to a polynomial point `c` of degree N, using `salt_version` to select
    /// the domain-separation salt. Deterministic: same inputs always produce the same `c`.
    #[cfg(test)]
    pub fn falcon_det1024_hash_to_point_coeffs(
        c: *mut u16,
        data: *const c_void,
        data_len: usize,
        salt_version: u8,
    );

    /// Extracts the s2 signature polynomial coefficients from a CT-format signature.
    /// Returns 0 on success, non-zero if decoding fails.
    #[cfg(test)]
    pub fn falcon_det1024_s2_coeffs(s2: *mut i16, sig: *const c_void) -> c_int;

    /// Computes s1 = c − s2·h (mod the Falcon ring), verifying the norm bound.
    /// Returns 0 on success, non-zero if the aggregate signature vector is too long.
    #[cfg(test)]
    pub fn falcon_det1024_s1_coeffs(
        s1: *mut i16,
        h: *const u16,
        c: *const u16,
        s2: *const i16,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

    const TEST_SEED: &[u8] = b"test1234";
    const ALT_SEED: &[u8] = b"different";
    const TEST_MSG: &[u8] = b"hello";

    unsafe fn make_keypair(
        seed: &[u8],
    ) -> (
        [u8; FALCON_DET1024_PRIVKEY_SIZE],
        [u8; FALCON_DET1024_PUBKEY_SIZE],
    ) {
        let mut rng = Shake256Context::default();
        unsafe {
            shake256_init_prng_from_seed(&mut rng, seed.as_ptr() as *const c_void, seed.len())
        };
        let mut privkey = [0u8; FALCON_DET1024_PRIVKEY_SIZE];
        let mut pubkey = [0u8; FALCON_DET1024_PUBKEY_SIZE];
        unsafe {
            falcon_det1024_keygen(
                &mut rng,
                privkey.as_mut_ptr() as *mut c_void,
                pubkey.as_mut_ptr() as *mut c_void,
            )
        };
        (privkey, pubkey)
    }

    // Helper: sign TEST_MSG with privkey, return (sig, sig_len).
    unsafe fn sign(
        privkey: &[u8; FALCON_DET1024_PRIVKEY_SIZE],
    ) -> ([u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE], usize) {
        let mut sig = [0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
        let mut sig_len = 0usize;
        unsafe {
            falcon_det1024_sign_compressed(
                sig.as_mut_ptr() as *mut c_void,
                &mut sig_len,
                privkey.as_ptr() as *const c_void,
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
            )
        };
        (sig, sig_len)
    }

    // Helper: sign TEST_MSG and convert to CT format.
    unsafe fn sign_and_convert_to_ct(
        privkey: &[u8; FALCON_DET1024_PRIVKEY_SIZE],
    ) -> [u8; FALCON_DET1024_SIG_CT_SIZE] {
        let (sig, sig_len) = unsafe { sign(privkey) };
        let mut sig_ct = [0u8; FALCON_DET1024_SIG_CT_SIZE];
        unsafe {
            falcon_det1024_convert_compressed_to_ct(
                sig_ct.as_mut_ptr() as *mut c_void,
                sig.as_ptr() as *const c_void,
                sig_len,
            )
        };
        sig_ct
    }

    #[test]
    fn shake256_context_init_from_seed() {
        let mut sc = Shake256Context::default();
        assert_eq!(sc.st, [0u64; SHAKE256_STATE_WORDS]);
        assert_eq!(sc.dptr, 0);

        unsafe {
            shake256_init_prng_from_seed(
                &mut sc,
                TEST_SEED.as_ptr() as *const c_void,
                TEST_SEED.len(),
            );
        }

        assert_eq!(sc.dptr, SHAKE256_RATE); // always SHAKE256_RATE after init
        assert_eq!(
            std::mem::size_of::<Shake256Context>(),
            SHAKE256_CONTEXT_SIZE
        ); // 200 (st) + 8 (dptr)
        assert_ne!(sc.st, [0u64; SHAKE256_STATE_WORDS]); // seed absorbed into Keccak state

        // different seed -> different state, same dptr
        let mut sc2 = Shake256Context::default();
        unsafe {
            shake256_init_prng_from_seed(
                &mut sc2,
                ALT_SEED.as_ptr() as *const c_void,
                ALT_SEED.len(),
            );
        }
        assert_ne!(sc.st, sc2.st);
        assert_eq!(sc.dptr, sc2.dptr);
    }

    #[test]
    fn falcon_det1024_keygen_and_sign_compressed() {
        let (privkey, pubkey) = unsafe { make_keypair(TEST_SEED) };
        assert_ne!(pubkey, [0u8; FALCON_DET1024_PUBKEY_SIZE]); // pubkey was written
        assert_ne!(privkey, [0u8; FALCON_DET1024_PRIVKEY_SIZE]); // privkey was written

        let (sig, sig_len) = unsafe { sign(&privkey) };
        let (sig2, sig2_len) = unsafe { sign(&privkey) };

        assert_eq!(sig[0], FALCON_DET1024_SIG_COMPRESSED_HEADER); // correct header byte
        assert!(sig_len > 0); // sig was written
        assert_eq!(&sig[..sig_len], &sig2[..sig2_len]); // deterministic: identical output
    }

    #[test]
    fn falcon_det1024_verify_compressed_smoke() {
        let (privkey, pubkey) = unsafe { make_keypair(TEST_SEED) };
        let (sig, sig_len) = unsafe { sign(&privkey) };

        // valid sig + correct pubkey + correct msg -> 0
        let ret = unsafe {
            falcon_det1024_verify_compressed(
                sig.as_ptr() as *const c_void,
                sig_len,
                pubkey.as_ptr() as *const c_void,
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
            )
        };
        assert_eq!(ret, 0);

        // valid sig + correct pubkey + wrong msg -> non-zero
        let ret_bad_msg = unsafe {
            falcon_det1024_verify_compressed(
                sig.as_ptr() as *const c_void,
                sig_len,
                pubkey.as_ptr() as *const c_void,
                ALT_SEED.as_ptr() as *const c_void,
                ALT_SEED.len(),
            )
        };
        assert_ne!(ret_bad_msg, 0);

        // valid sig + wrong pubkey + correct msg -> non-zero
        let (_, wrong_pubkey) = unsafe { make_keypair(ALT_SEED) };
        let ret_bad_key = unsafe {
            falcon_det1024_verify_compressed(
                sig.as_ptr() as *const c_void,
                sig_len,
                wrong_pubkey.as_ptr() as *const c_void,
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
            )
        };
        assert_ne!(ret_bad_key, 0);
    }

    #[test]
    fn falcon_det1024_get_salt_version_smoke() {
        let (privkey, _) = unsafe { make_keypair(TEST_SEED) };
        let (sig, _) = unsafe { sign(&privkey) };

        let salt_version =
            unsafe { falcon_det1024_get_salt_version(sig.as_ptr() as *const c_void) };
        assert_eq!(salt_version, FALCON_DET1024_CURRENT_SALT_VERSION as i32); // expect version 0
    }

    #[test]
    fn falcon_det1024_convert_compressed_to_ct_smoke() {
        let (privkey, _) = unsafe { make_keypair(TEST_SEED) };
        let sig_ct = unsafe { sign_and_convert_to_ct(&privkey) };

        assert_ne!(sig_ct, [0u8; FALCON_DET1024_SIG_CT_SIZE]); // ct sig was written
        assert_eq!(sig_ct[0], FALCON_DET1024_SIG_CT_HEADER); // correct CT header byte
    }

    #[test]
    fn falcon_det1024_verify_ct_smoke() {
        let (privkey, pubkey) = unsafe { make_keypair(TEST_SEED) };
        let sig_ct = unsafe { sign_and_convert_to_ct(&privkey) };

        // valid CT sig + correct pubkey + correct msg -> 0
        let ret = unsafe {
            falcon_det1024_verify_ct(
                sig_ct.as_ptr() as *const c_void,
                pubkey.as_ptr() as *const c_void,
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
            )
        };
        assert_eq!(ret, 0);

        // valid CT sig + correct pubkey + wrong msg -> non-zero
        let ret_bad_msg = unsafe {
            falcon_det1024_verify_ct(
                sig_ct.as_ptr() as *const c_void,
                pubkey.as_ptr() as *const c_void,
                ALT_SEED.as_ptr() as *const c_void,
                ALT_SEED.len(),
            )
        };
        assert_ne!(ret_bad_msg, 0);

        // valid CT sig + wrong pubkey + correct msg -> non-zero
        let (_, wrong_pubkey) = unsafe { make_keypair(ALT_SEED) };
        let ret_bad_key = unsafe {
            falcon_det1024_verify_ct(
                sig_ct.as_ptr() as *const c_void,
                wrong_pubkey.as_ptr() as *const c_void,
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
            )
        };
        assert_ne!(ret_bad_key, 0);
    }

    #[test]
    fn falcon_det1024_pubkey_coeffs_smoke() {
        let (_, pubkey) = unsafe { make_keypair(TEST_SEED) };

        let mut h = [0u16; FALCON_DET1024_N];
        let ret = unsafe {
            falcon_det1024_pubkey_coeffs(h.as_mut_ptr(), pubkey.as_ptr() as *const c_void)
        };

        assert_eq!(ret, 0);
        assert_ne!(h, [0u16; FALCON_DET1024_N]); // coefficients were written
    }

    #[test]
    fn falcon_det1024_hash_to_point_coeffs_smoke() {
        let mut c = [0u16; FALCON_DET1024_N];
        unsafe {
            falcon_det1024_hash_to_point_coeffs(
                c.as_mut_ptr(),
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
                FALCON_DET1024_CURRENT_SALT_VERSION,
            );
        }

        assert_ne!(c, [0u16; FALCON_DET1024_N]); // coefficients were written

        // same inputs -> same output (deterministic)
        let mut c2 = [0u16; FALCON_DET1024_N];
        unsafe {
            falcon_det1024_hash_to_point_coeffs(
                c2.as_mut_ptr(),
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
                FALCON_DET1024_CURRENT_SALT_VERSION,
            );
        }
        assert_eq!(c, c2);

        // different msg -> different coefficients
        let mut c3 = [0u16; FALCON_DET1024_N];
        unsafe {
            falcon_det1024_hash_to_point_coeffs(
                c3.as_mut_ptr(),
                ALT_SEED.as_ptr() as *const c_void,
                ALT_SEED.len(),
                FALCON_DET1024_CURRENT_SALT_VERSION,
            );
        }
        assert_ne!(c, c3);
    }

    #[test]
    fn falcon_det1024_s2_coeffs_smoke() {
        let (privkey, _) = unsafe { make_keypair(TEST_SEED) };
        let sig_ct = unsafe { sign_and_convert_to_ct(&privkey) };

        let mut s2 = [0i16; FALCON_DET1024_N];
        let ret =
            unsafe { falcon_det1024_s2_coeffs(s2.as_mut_ptr(), sig_ct.as_ptr() as *const c_void) };

        assert_eq!(ret, 0);
        assert_ne!(s2, [0i16; FALCON_DET1024_N]); // coefficients were written
    }

    #[test]
    fn falcon_det1024_s1_coeffs_smoke() {
        let (privkey, pubkey) = unsafe { make_keypair(TEST_SEED) };
        let sig_ct = unsafe { sign_and_convert_to_ct(&privkey) };

        // unpack h from pubkey
        let mut h = [0u16; FALCON_DET1024_N];
        unsafe {
            falcon_det1024_pubkey_coeffs(h.as_mut_ptr(), pubkey.as_ptr() as *const c_void);
        }

        // hash message to point c
        let mut c = [0u16; FALCON_DET1024_N];
        unsafe {
            falcon_det1024_hash_to_point_coeffs(
                c.as_mut_ptr(),
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
                FALCON_DET1024_CURRENT_SALT_VERSION,
            );
        }

        // unpack s2 from CT sig
        let mut s2 = [0i16; FALCON_DET1024_N];
        unsafe {
            falcon_det1024_s2_coeffs(s2.as_mut_ptr(), sig_ct.as_ptr() as *const c_void);
        }

        // compute s1 = c - s2*h and verify the aggregate is short enough
        let mut s1 = [0i16; FALCON_DET1024_N];
        let ret = unsafe {
            falcon_det1024_s1_coeffs(s1.as_mut_ptr(), h.as_ptr(), c.as_ptr(), s2.as_ptr())
        };

        assert_eq!(ret, 0);
        assert_ne!(s1, [0i16; FALCON_DET1024_N]); // s1 coefficients were written
    }
}
