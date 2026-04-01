// src/keygen.rs

use std::os::raw::c_void;

use crate::{
    constants::{
        FALCON_DET1024_N, FALCON_DET1024_PRIVKEY_SIZE, FALCON_DET1024_PUBKEY_SIZE,
        FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
    },
    error::{Error, SignatureError},
    ffi::{
        Shake256Context, falcon_det1024_keygen, falcon_det1024_pubkey_coeffs,
        falcon_det1024_sign_compressed, falcon_det1024_verify_compressed, falcon_det1024_verify_ct,
        shake256_init_prng_from_seed,
    },
    signature::{CompressedSignature, CtSignature},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; FALCON_DET1024_PUBKEY_SIZE]);

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; FALCON_DET1024_PUBKEY_SIZE]) -> Result<Self, Error> {
        let mut h = [0u16; FALCON_DET1024_N];
        let ret = unsafe {
            falcon_det1024_pubkey_coeffs(h.as_mut_ptr(), bytes.as_ptr() as *const c_void)
        };
        if ret != 0 {
            return Err(Error::InvalidPublicKey);
        }
        Ok(Self(*bytes))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; FALCON_DET1024_PUBKEY_SIZE] {
        &self.0
    }

    pub fn verify_compressed(
        &self,
        signature: &CompressedSignature,
        message: &[u8],
    ) -> Result<(), Error> {
        let sig = signature.as_bytes();

        let ret = unsafe {
            falcon_det1024_verify_compressed(
                sig.as_ptr() as *const c_void,
                sig.len(),
                self.0.as_ptr() as *const c_void,
                message.as_ptr() as *const c_void,
                message.len(),
            )
        };

        match ret {
            0 => Ok(()),
            -4 => Err(SignatureError::VerificationFailed.into()),
            _ => Err(Error::Falcon(ret)),
        }
    }

    pub fn verify_ct(&self, signature: &CtSignature, message: &[u8]) -> Result<(), Error> {
        let ret = unsafe {
            falcon_det1024_verify_ct(
                signature.as_bytes().as_ptr() as *const c_void,
                self.0.as_ptr() as *const c_void,
                message.as_ptr() as *const c_void,
                message.len(),
            )
        };

        match ret {
            0 => Ok(()),
            -4 => Err(SignatureError::VerificationFailed.into()),
            _ => Err(Error::Falcon(ret)),
        }
    }
}

pub struct PrivateKey([u8; FALCON_DET1024_PRIVKEY_SIZE]);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // `write_volatile` marks each write as observable, preventing the compiler
        // from eliding them as dead stores when the value is about to be freed.
        for byte in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(byte, 0) }
        }
        // `compiler_fence` ensures the volatile writes are not reordered past this
        // point at compile time. No CPU fence instruction is emitted — cross-thread
        // visibility of the zeroing is not a concern here.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl PrivateKey {
    pub fn from_seed(seed: &[u8]) -> (Self, PublicKey) {
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

        (Self(privkey), PublicKey(pubkey))
    }

    /// Constructs a `PrivateKey` from raw bytes without validation.
    ///
    /// Intended for round-tripping a key produced by `from_seed` through trusted storage.
    /// Invalid bytes are not rejected here — they will cause `sign` to return
    /// `Err(Error::Falcon(...))` when the C library rejects them during decode.
    pub fn from_bytes(bytes: &[u8; FALCON_DET1024_PRIVKEY_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; FALCON_DET1024_PRIVKEY_SIZE] {
        &self.0
    }

    pub fn sign(&self, message: &[u8]) -> Result<CompressedSignature, Error> {
        let mut sig = [0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
        let mut sig_len = 0usize;

        let ret = unsafe {
            falcon_det1024_sign_compressed(
                sig.as_mut_ptr() as *mut c_void,
                &mut sig_len,
                self.0.as_ptr() as *const c_void,
                message.as_ptr() as *const c_void,
                message.len(),
            )
        };

        if ret != 0 {
            return Err(Error::Falcon(ret));
        }

        CompressedSignature::from_bytes(&sig[..sig_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        FALCON_DET1024_SIG_COMPRESSED_HEADER, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
    };

    const TEST_SEED: &[u8] = b"test1234";
    const ALT_SEED: &[u8] = b"different";
    const TEST_MSG: &[u8] = b"hello algorand";

    #[test]
    fn public_key_as_bytes() {
        let mut pubkey_bytes = [0u8; FALCON_DET1024_PUBKEY_SIZE];
        pubkey_bytes[0] = 0xAB;
        pubkey_bytes[FALCON_DET1024_PUBKEY_SIZE - 1] = 0xCD;

        let pubkey = PublicKey(pubkey_bytes);
        assert_eq!(pubkey.as_bytes().len(), FALCON_DET1024_PUBKEY_SIZE);
        assert_eq!(pubkey.as_bytes()[0], 0xAB);
        assert_eq!(pubkey.as_bytes()[FALCON_DET1024_PUBKEY_SIZE - 1], 0xCD);
    }

    #[test]
    fn public_key_from_bytes_valid() {
        let (_, pubkey) = PrivateKey::from_seed(TEST_SEED);
        let pubkey_bytes = *pubkey.as_bytes();
        let result = PublicKey::from_bytes(&pubkey_bytes);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &pubkey_bytes);
    }

    #[test]
    fn public_key_clone_and_eq() {
        let (_, pubkey) = PrivateKey::from_seed(TEST_SEED);
        let pubkey_bytes = *pubkey.as_bytes();
        let key = PublicKey::from_bytes(&pubkey_bytes).unwrap();
        let cloned = key.clone();

        assert_eq!(key, cloned); // PartialEq: same bytes
        assert_ne!(key, PublicKey(pubkey_bytes.map(|b| b.wrapping_add(1)))); // different bytes -> not equal
    }

    #[test]
    fn public_key_from_bytes_invalid() {
        let invalid_key_bytes = [0xFFu8; FALCON_DET1024_PUBKEY_SIZE];
        let result = PublicKey::from_bytes(&invalid_key_bytes);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidPublicKey));
    }

    #[test]
    fn private_key_from_seed() {
        let (privkey, pubkey) = PrivateKey::from_seed(TEST_SEED);

        assert_ne!(privkey.as_bytes(), &[0u8; FALCON_DET1024_PRIVKEY_SIZE]); // key was written
        assert_ne!(pubkey.as_bytes(), &[0u8; FALCON_DET1024_PUBKEY_SIZE]);
    }

    #[test]
    fn private_key_from_seed_deterministic() {
        let (privkey1, pubkey1) = PrivateKey::from_seed(TEST_SEED);
        let (privkey2, pubkey2) = PrivateKey::from_seed(TEST_SEED);

        assert_eq!(privkey1.as_bytes(), privkey2.as_bytes()); // same seed -> same keys
        assert_eq!(pubkey1.as_bytes(), pubkey2.as_bytes());
    }

    #[test]
    fn private_key_from_seed_different_seeds() {
        let (privkey1, pubkey1) = PrivateKey::from_seed(TEST_SEED);
        let (privkey2, pubkey2) = PrivateKey::from_seed(ALT_SEED);

        assert_ne!(privkey1.as_bytes(), privkey2.as_bytes()); // different seed -> different keys
        assert_ne!(pubkey1.as_bytes(), pubkey2.as_bytes());
    }

    #[test]
    fn private_key_sign() {
        let (privkey, _) = PrivateKey::from_seed(TEST_SEED);
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert_eq!(sig.as_bytes()[0], FALCON_DET1024_SIG_COMPRESSED_HEADER);
        assert!(sig.as_bytes().len() <= FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
    }

    #[test]
    fn private_key_sign_is_deterministic() {
        let (privkey, _) = PrivateKey::from_seed(TEST_SEED);
        let sig1 = privkey.sign(TEST_MSG).unwrap();
        let sig2 = privkey.sign(TEST_MSG).unwrap();

        assert_eq!(sig1.as_bytes(), sig2.as_bytes()); // same key + same message -> same signature
    }

    #[test]
    fn verify_compressed_valid() {
        let (privkey, pubkey) = PrivateKey::from_seed(TEST_SEED);
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert!(pubkey.verify_compressed(&sig, TEST_MSG).is_ok());
    }

    #[test]
    fn verify_compressed_wrong_message() {
        let (privkey, pubkey) = PrivateKey::from_seed(TEST_SEED);
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert!(matches!(
            pubkey.verify_compressed(&sig, b"wrong message"),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    #[test]
    fn verify_compressed_wrong_key() {
        let (privkey, _) = PrivateKey::from_seed(TEST_SEED);
        let (_, wrong_pubkey) = PrivateKey::from_seed(ALT_SEED);
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert!(matches!(
            wrong_pubkey.verify_compressed(&sig, TEST_MSG),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    #[test]
    fn verify_ct_valid() {
        let (privkey, pubkey) = PrivateKey::from_seed(TEST_SEED);
        let sig = privkey.sign(TEST_MSG).unwrap().to_ct().unwrap();

        assert!(pubkey.verify_ct(&sig, TEST_MSG).is_ok());
    }

    #[test]
    fn verify_ct_wrong_message() {
        let (privkey, pubkey) = PrivateKey::from_seed(TEST_SEED);
        let sig = privkey.sign(TEST_MSG).unwrap().to_ct().unwrap();

        assert!(matches!(
            pubkey.verify_ct(&sig, b"wrong message"),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    #[test]
    fn verify_ct_wrong_key() {
        let (privkey, _) = PrivateKey::from_seed(TEST_SEED);
        let (_, wrong_pubkey) = PrivateKey::from_seed(ALT_SEED);
        let sig = privkey.sign(TEST_MSG).unwrap().to_ct().unwrap();

        assert!(matches!(
            wrong_pubkey.verify_ct(&sig, TEST_MSG),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    #[test]
    fn private_key_from_bytes_roundtrip() {
        let (privkey, _) = PrivateKey::from_seed(TEST_SEED);
        let bytes = *privkey.as_bytes();
        let restored = PrivateKey::from_bytes(&bytes);

        assert_eq!(restored.as_bytes(), &bytes);
    }
}
