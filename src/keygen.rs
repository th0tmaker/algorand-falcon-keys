// src/keygen.rs

use std::os::raw::c_void;

use zeroize::ZeroizeOnDrop;

use crate::{
    constants::{FALCON_DET1024_N, FALCON_DET1024_PRIVKEY_SIZE, FALCON_DET1024_PUBKEY_SIZE},
    error::Error,
    ffi::{
        Shake256Context, falcon_det1024_keygen, falcon_det1024_pubkey_coeffs,
        shake256_init_prng_from_seed,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicKey([u8; FALCON_DET1024_PUBKEY_SIZE]);

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

    pub fn as_bytes(&self) -> &[u8; FALCON_DET1024_PUBKEY_SIZE] {
        &self.0
    }
}

#[derive(ZeroizeOnDrop)]
struct PrivateKey([u8; FALCON_DET1024_PRIVKEY_SIZE]);

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

    pub fn from_bytes(bytes: &[u8; FALCON_DET1024_PRIVKEY_SIZE]) -> Self {
        Self(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; FALCON_DET1024_PRIVKEY_SIZE] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &[u8] = b"test1234";
    const ALT_SEED: &[u8] = b"different";

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
    fn private_key_from_bytes_roundtrip() {
        let (privkey, _) = PrivateKey::from_seed(TEST_SEED);
        let bytes = *privkey.as_bytes();
        let restored = PrivateKey::from_bytes(&bytes);

        assert_eq!(restored.as_bytes(), &bytes);
    }
}
