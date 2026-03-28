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
        seed_len: usize,
    );

    pub fn falcon_det1024_keygen(
        rng: *mut Shake256Context,
        privkey: *mut c_void,
        pubkey: *mut c_void,
    ) -> c_int;

    pub fn falcon_det1024_sign_compressed(
        sig: *mut c_void,
        sig_len: *mut usize,
        privkey: *const c_void,
        data: *const c_void,
        data_len: usize,
    ) -> c_int;

    pub fn falcon_det1024_verify_compressed(
        sig: *const c_void,
        sig_len: usize,
        pubkey: *const c_void,
        data: *const c_void,
        data_len: usize,
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
        unsafe {
            shake256_init_prng_from_seed(&mut rng, seed.as_ptr() as *const c_void, seed.len());
        }
        let mut privkey = [0u8; FALCON_DET1024_PRIVKEY_SIZE];
        let mut pubkey = [0u8; FALCON_DET1024_PUBKEY_SIZE];
        unsafe {
            falcon_det1024_keygen(&mut rng, privkey.as_mut_ptr() as *mut c_void, pubkey.as_mut_ptr() as *mut c_void);
        }
        (privkey, pubkey)
    }

    // Helper: sign TEST_MSG with privkey, return (sig, sig_len).
    unsafe fn sign(privkey: &[u8; FALCON_DET1024_PRIVKEY_SIZE]) -> ([u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE], usize) {
        let mut sig = [0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
        let mut sig_len = 0usize;
        unsafe {
            falcon_det1024_sign_compressed(
                sig.as_mut_ptr() as *mut c_void,
                &mut sig_len,
                privkey.as_ptr() as *const c_void,
                TEST_MSG.as_ptr() as *const c_void,
                TEST_MSG.len(),
            );
        }
        (sig, sig_len)
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
}
