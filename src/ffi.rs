// src/ffi.rs

use std::os::raw::*;
use crate::constants::SHAKE256_STATE_WORDS;

/// Mirror of `shake256_context` from falcon.h. Used as a PRNG throughout Falcon.
#[derive(Debug, Default)]
#[repr(C)]
pub struct Shake256Context {
    pub st: [u64; SHAKE256_STATE_WORDS],  // Keccak-1600 state, 200 bytes, unique per seed
    pub dptr: u64,  // squeeze position: 0 = uninit, 136 = ready, 1-135 = mid-extraction
}

unsafe extern "C" {
    /// Init Shake256 as a seeded deterministic PRNG (init -> inject -> flip).
    pub fn shake256_init_prng_from_seed(
        sc: *mut Shake256Context,
        seed: *const c_void,
        seed_len: usize
    );

    pub fn falcon_det1024_keygen(
        rng: *mut Shake256Context,
        privkey: *mut c_void,
        pubkey: *mut c_void
    ) -> c_int;

    pub fn falcon_det1024_sign_compressed(
        sig: *mut c_void,
        sig_len: *mut usize,
        privkey: *const c_void,
        data: *const c_void,
        data_len: usize
    ) -> c_int;

    pub fn falcon_det1024_verify_compressed(
        sig: *const c_void,
        sig_len: usize,
        pubkey: *const c_void,
        data: *const c_void,
        data_len: usize
    ) -> c_int;

    pub fn falcon_det1024_get_salt_version(
        sig: *const c_void
    ) -> c_int;

    pub fn falcon_det1024_convert_compressed_to_ct(
        sig_ct: *mut c_void,
        sig_compressed: *const c_void,
        sig_compressed_len: usize
    ) -> c_int;

    pub fn falcon_det1024_verify_ct(
        sig: *const c_void,
        pubkey: *const c_void,
        data: *const c_void,
        data_len: usize
    ) -> c_int;

    pub fn falcon_det1024_pubkey_coeffs(
        h: *mut u16,
        pubkey: *const c_void
    ) -> c_int;

    pub fn falcon_det1024_hash_to_point_coeffs(
        c: *mut u16,
        data: *const c_void,
        data_len: usize,
        salt_version: u8
    );

    pub fn falcon_det1024_s2_coeffs(
        s2: *mut i16,
        sig: *const c_void
    ) -> c_int;

    pub fn falcon_det1024_s1_coeffs(
        s1: *mut i16,
        h: *const u16,
        c: *const u16,
        s2: *const i16
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;

    const TEST_SEED: &[u8] = b"test1234";
    const ALT_SEED: &[u8] = b"different";
    const TEST_MSG: &[u8] = b"hello algorand";

    // Helper: seed a PRNG, generate a keypair, return (privkey, pubkey).
    unsafe fn make_keypair(seed: &[u8]) -> ([u8; FALCON_DET1024_PRIVKEY_SIZE], [u8; FALCON_DET1024_PUBKEY_SIZE]) {
        let mut rng = Shake256Context::default();
        unsafe { shake256_init_prng_from_seed(&mut rng, seed.as_ptr() as *const c_void, seed.len()) };
        let mut privkey = [0u8; FALCON_DET1024_PRIVKEY_SIZE];
        let mut pubkey = [0u8; FALCON_DET1024_PUBKEY_SIZE];
        unsafe { falcon_det1024_keygen(&mut rng, privkey.as_mut_ptr() as *mut c_void, pubkey.as_mut_ptr() as *mut c_void) };
        (privkey, pubkey)
    }

    // Helper: sign TEST_MSG with privkey, return (sig, sig_len).
    unsafe fn sign(privkey: &[u8; FALCON_DET1024_PRIVKEY_SIZE]) -> ([u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE], usize) {
        let mut sig = [0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
        let mut sig_len = 0usize;
        unsafe { falcon_det1024_sign_compressed(
            sig.as_mut_ptr() as *mut c_void,
            &mut sig_len,
            privkey.as_ptr() as *const c_void,
            TEST_MSG.as_ptr() as *const c_void,
            TEST_MSG.len(),
        ) };
        (sig, sig_len)
    }

    // Helper: sign TEST_MSG and convert to CT format.
    unsafe fn sign_and_convert_to_ct(privkey: &[u8; FALCON_DET1024_PRIVKEY_SIZE]) -> [u8; FALCON_DET1024_SIG_CT_SIZE] {
        let (sig, sig_len) = unsafe { sign(privkey) };
        let mut sig_ct = [0u8; FALCON_DET1024_SIG_CT_SIZE];
        unsafe { falcon_det1024_convert_compressed_to_ct(
            sig_ct.as_mut_ptr() as *mut c_void,
            sig.as_ptr() as *const c_void,
            sig_len,
        ) };
        sig_ct
    }

    #[test]
    fn shake256_context_init_from_seed() {
        let mut sc = Shake256Context::default();
        assert_eq!(sc.st, [0u64; SHAKE256_STATE_WORDS]);
        assert_eq!(sc.dptr, 0);

        unsafe {
            shake256_init_prng_from_seed(&mut sc, TEST_SEED.as_ptr() as *const c_void, TEST_SEED.len());
        }

        assert_eq!(sc.dptr, SHAKE256_RATE);  // always SHAKE256_RATE after init
        assert_eq!(std::mem::size_of::<Shake256Context>(), SHAKE256_CONTEXT_SIZE);  // 200 (st) + 8 (dptr)
        assert_ne!(sc.st, [0u64; SHAKE256_STATE_WORDS]);  // seed absorbed into Keccak state

        // different seed -> different state, same dptr
        let mut sc2 = Shake256Context::default();
        unsafe {
            shake256_init_prng_from_seed(&mut sc2, ALT_SEED.as_ptr() as *const c_void, ALT_SEED.len());
        }
        assert_ne!(sc.st, sc2.st);
        assert_eq!(sc.dptr, sc2.dptr);
    }

    #[test]
    fn falcon_det1024_keygen_and_sign_compressed() {
        let (privkey, pubkey) = unsafe { make_keypair(TEST_SEED) };
        assert_ne!(pubkey, [0u8; FALCON_DET1024_PUBKEY_SIZE]);  // pubkey was written
        assert_ne!(privkey, [0u8; FALCON_DET1024_PRIVKEY_SIZE]);  // privkey was written

        let (sig, sig_len) = unsafe { sign(&privkey) };
        let (sig2, sig2_len) = unsafe { sign(&privkey) };

        assert_eq!(sig[0], FALCON_DET1024_SIG_COMPRESSED_HEADER);  // correct header byte
        assert!(sig_len > 0);  // sig was written
        assert_eq!(&sig[..sig_len], &sig2[..sig2_len]);  // deterministic: identical output
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

        let salt_version = unsafe {
            falcon_det1024_get_salt_version(sig.as_ptr() as *const c_void)
        };
        assert_eq!(salt_version, FALCON_DET1024_CURRENT_SALT_VERSION as i32);  // expect version 0
    }

    #[test]
    fn falcon_det1024_convert_compressed_to_ct_smoke() {
        let (privkey, _) = unsafe { make_keypair(TEST_SEED) };
        let sig_ct = unsafe { sign_and_convert_to_ct(&privkey) };

        assert_ne!(sig_ct, [0u8; FALCON_DET1024_SIG_CT_SIZE]);  // ct sig was written
        assert_eq!(sig_ct[0], FALCON_DET1024_SIG_CT_HEADER);  // correct CT header byte
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
        assert_ne!(h, [0u16; FALCON_DET1024_N]);  // coefficients were written
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

        assert_ne!(c, [0u16; FALCON_DET1024_N]);  // coefficients were written

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
        let ret = unsafe {
            falcon_det1024_s2_coeffs(s2.as_mut_ptr(), sig_ct.as_ptr() as *const c_void)
        };

        assert_eq!(ret, 0);
        assert_ne!(s2, [0i16; FALCON_DET1024_N]);  // coefficients were written
    }

    #[test]
    fn falcon_det1024_s1_coeffs_smoke() {
        let (privkey, pubkey) = unsafe { make_keypair(TEST_SEED) };
        let sig_ct = unsafe { sign_and_convert_to_ct(&privkey) };

        // unpack h from pubkey
        let mut h = [0u16; FALCON_DET1024_N];
        unsafe { falcon_det1024_pubkey_coeffs(h.as_mut_ptr(), pubkey.as_ptr() as *const c_void); }

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
        unsafe { falcon_det1024_s2_coeffs(s2.as_mut_ptr(), sig_ct.as_ptr() as *const c_void); }

        // compute s1 = c - s2*h and verify the aggregate is short enough
        let mut s1 = [0i16; FALCON_DET1024_N];
        let ret = unsafe {
            falcon_det1024_s1_coeffs(s1.as_mut_ptr(), h.as_ptr(), c.as_ptr(), s2.as_ptr())
        };

        assert_eq!(ret, 0);
        assert_ne!(s1, [0i16; FALCON_DET1024_N]);  // s1 coefficients were written
    }
}
