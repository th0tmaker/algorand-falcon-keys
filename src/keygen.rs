// src/keygen.rs

use std::os::raw::c_void;

use crate::{
    constants::{FALCON_DET1024_N, FALCON_DET1024_PRIVKEY_SIZE,
        FALCON_DET1024_PUBKEY_SIZE, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
    },
    error::{Error, SignatureError},
    ffi::{Shake256Context, falcon_det1024_keygen, falcon_det1024_pubkey_coeffs,
        falcon_det1024_sign_compressed, falcon_det1024_verify_compressed,
        falcon_det1024_verify_ct, shake256_init_prng_from_seed
    },
    signature::{CompressedSignature, CtSignature},
    zeroize::Zeroize,
};

/// A Falcon-det1024 public key.
///
/// Wraps the `FALCON_DET1024_PUBKEY_SIZE`-byte encoding produced by keygen.
/// `from_bytes` validates the encoding by decoding the NTT coefficients;
/// the raw bytes are then stored for use in verification calls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; FALCON_DET1024_PUBKEY_SIZE]);

impl PublicKey {
    /// Parses and validates a [`PublicKey`] from its encoded byte representation.
    ///
    /// Returns `Err(Error::InvalidPublicKey)` if the bytes do not decode into
    /// valid NTT coefficients.
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

    /// Returns the underlying bytes of `self`.
    pub fn as_bytes(&self) -> &[u8; FALCON_DET1024_PUBKEY_SIZE] {
        &self.0
    }

    /// Verifies a [`CompressedSignature`] over a `message` against `self`.
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

    /// Verifies a [`CtSignature`] over a `message` against `self`.
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

/// A Falcon-det1024 private key.
///
/// Wraps the `FALCON_DET1024_PRIVKEY_SIZE` byte encoding produced by keygen.
/// The inner bytes are secret and zeroed on drop — do not clone or persist
/// without deliberate intent. Obtain via `derive_keypair` or `from_bytes`.
pub struct PrivateKey([u8; FALCON_DET1024_PRIVKEY_SIZE]);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PrivateKey {
    /// Wraps raw key material into a [`PrivateKey`] **without** validation, consuming the buffer.
    ///
    /// The caller's array is moved in and zeroed after the key material is copied
    /// into `self`. Invalid bytes are not rejected here — they will surface as
    /// `Err(Error::Falcon(...))` when `sign` is called and the vendor C library
    /// decodes the key into its internal polynomial representation (f, g, F, G
    /// coefficients) at sign time.
    pub fn from_bytes(mut bytes: [u8; FALCON_DET1024_PRIVKEY_SIZE]) -> Self {
        let key = Self(bytes);
        bytes.zeroize();
        key
    }

    /// Returns the underlying bytes of `self`.
    pub fn as_bytes(&self) -> &[u8; FALCON_DET1024_PRIVKEY_SIZE] {
        &self.0
    }

    /// Returns an instance of [`CompressedSignature`] that was produced
    /// by signing a `message` with `self`
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

/// Derives a Falcon-det1024 keypair from a seed.
///
/// The seed is absorbed into a SHAKE-256 PRNG which drives key generation.
/// Any byte sequence is a valid seed — callers are responsible for providing
/// a seed with sufficient entropy.
///
/// Returns a tuple containing an instance of [`PrivateKey`] and [`PublicKey`]
/// or `Err(Error::Falcon(...))` if the vendor C library key generation fails. 
pub fn derive_keypair(seed: &[u8]) -> Result<(PrivateKey, PublicKey), Error> {
    let mut rng = Shake256Context::default();

    unsafe {
        shake256_init_prng_from_seed(&mut rng, seed.as_ptr() as *const c_void, seed.len())
    };

    let mut privkey = [0u8; FALCON_DET1024_PRIVKEY_SIZE];
    let mut pubkey = [0u8; FALCON_DET1024_PUBKEY_SIZE];
    
    let ret = unsafe {
        falcon_det1024_keygen(
            &mut rng,
            privkey.as_mut_ptr() as *mut c_void,
            pubkey.as_mut_ptr() as *mut c_void,
        )
    };

    if ret != 0 {
        // Zero the stack buffer before returning — keygen failed but privkey may
        // hold partial key material written by the C library before the error.
        privkey.zeroize();
        return Err(Error::Falcon(ret));
    }

    // PrivateKey(privkey) copies the bytes (Copy type), so the stack buffer still
    // holds key material after the constructor call. Zero it explicitly.
    let result = Ok((PrivateKey(privkey), PublicKey(pubkey)));
    privkey.zeroize();
    result
}

/// Derives a Falcon-det1024 keypair from a BIP-39 mnemonic and optional passphrase.
///
/// Convenience wrapper that chains [`crate::mnemonic::seed_from_mnemonic`]
/// and [`derive_keypair`]: The mnemonic phrase is validated, a 48-byte
/// Falcon seed is derived, and the seed is passed to [`derive_keypair`]
/// in order to return a tuple holding [`PrivateKey`] and [`PublicKey`]. 
///
/// Pass an empty string for `passphrase` if no passphrase was used to
/// derive the 48-byte Falcon seed.
#[cfg(feature = "mnemonic")]
pub fn derive_keypair_from_mnemonic(
    mnemonic: &[&str; crate::mnemonic::MNEMONIC_LEN],
    passphrase: &str,
) -> Result<(PrivateKey, PublicKey), Error> {
    let mut seed = crate::mnemonic::seed_from_mnemonic(mnemonic, passphrase)?;
    let result = derive_keypair(&seed);
    seed.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        FALCON_DET1024_SIG_COMPRESSED_HEADER, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
    };

    const TEST_SEED: &[u8] = b"test1234";
    const ALT_SEED: &[u8] = b"different";
    const TEST_MSG: &[u8] = b"hello";

    // ─── PublicKey tests ─────────────────────────────────────────────────────────

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
        let (_, pubkey) = derive_keypair(TEST_SEED).unwrap();
        let pubkey_bytes = *pubkey.as_bytes();
        let result = PublicKey::from_bytes(&pubkey_bytes);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_bytes(), &pubkey_bytes);
    }

    #[test]
    fn public_key_clone_and_eq() {
        let (_, pubkey) = derive_keypair(TEST_SEED).unwrap();
        let pubkey_bytes = *pubkey.as_bytes();
        let key = PublicKey::from_bytes(&pubkey_bytes).unwrap();
        let cloned = key.clone();

        // PartialEq: same bytes, should be equal
        assert_eq!(key, cloned);
        // Different bytes: should not be equal
        assert_ne!(key, PublicKey(pubkey_bytes.map(|b| b.wrapping_add(1))));

    }

    #[test]
    fn public_key_from_bytes_invalid() {
        let invalid_key_bytes = [0xFFu8; FALCON_DET1024_PUBKEY_SIZE];
        let result = PublicKey::from_bytes(&invalid_key_bytes);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidPublicKey));
    }

    // ─── PrivateKey tests ────────────────────────────────────────────────────────

    #[test]
    fn private_key_from_seed() {
        let (privkey, pubkey) = derive_keypair(TEST_SEED).unwrap();

        assert_ne!(privkey.as_bytes(), &[0u8; FALCON_DET1024_PRIVKEY_SIZE]); // key was written
        assert_ne!(pubkey.as_bytes(), &[0u8; FALCON_DET1024_PUBKEY_SIZE]);
    }

    #[test]
    fn private_key_from_seed_deterministic() {
        let (privkey1, pubkey1) = derive_keypair(TEST_SEED).unwrap();
        let (privkey2, pubkey2) = derive_keypair(TEST_SEED).unwrap();

        assert_eq!(privkey1.as_bytes(), privkey2.as_bytes()); // same seed -> same keys
        assert_eq!(pubkey1.as_bytes(), pubkey2.as_bytes());
    }

    #[test]
    fn private_key_from_seed_different_seeds() {
        let (privkey1, pubkey1) = derive_keypair(TEST_SEED).unwrap();
        let (privkey2, pubkey2) = derive_keypair(ALT_SEED).unwrap();

        assert_ne!(privkey1.as_bytes(), privkey2.as_bytes()); // different seed -> different keys
        assert_ne!(pubkey1.as_bytes(), pubkey2.as_bytes());
    }

    #[test]
    fn private_key_sign() {
        let (privkey, _) = derive_keypair(TEST_SEED).unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert_eq!(sig.as_bytes()[0], FALCON_DET1024_SIG_COMPRESSED_HEADER);
        assert!(sig.as_bytes().len() <= FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
    }

    #[test]
    fn private_key_sign_is_deterministic() {
        let (privkey, _) = derive_keypair(TEST_SEED).unwrap();
        let sig1 = privkey.sign(TEST_MSG).unwrap();
        let sig2 = privkey.sign(TEST_MSG).unwrap();

        assert_eq!(sig1.as_bytes(), sig2.as_bytes()); // same key + same message -> same signature
    }

    #[test]
    fn private_key_from_bytes_roundtrip() {
        let (privkey, _) = derive_keypair(TEST_SEED).unwrap();
        let bytes = *privkey.as_bytes();
        let restored = PrivateKey::from_bytes(bytes);

        assert_eq!(restored.as_bytes(), &bytes);
    }

    // ─── PublicKey & CompressedSignature Verification tests ──────────────────────

    #[test]
    fn verify_compressed_valid() {
        let (privkey, pubkey) = derive_keypair(TEST_SEED).unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert!(pubkey.verify_compressed(&sig, TEST_MSG).is_ok());
    }

    #[test]
    fn verify_compressed_wrong_message() {
        let (privkey, pubkey) = derive_keypair(TEST_SEED).unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert!(matches!(
            pubkey.verify_compressed(&sig, b"wrong message"),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    #[test]
    fn verify_compressed_wrong_key() {
        let (privkey, _) = derive_keypair(TEST_SEED).unwrap();
        let (_, wrong_pubkey) = derive_keypair(ALT_SEED).unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert!(matches!(
            wrong_pubkey.verify_compressed(&sig, TEST_MSG),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    // ─── PublicKey & CtSignature Verification tests ──────────────────────────────

    #[test]
    fn verify_ct_valid() {
        let (privkey, pubkey) = derive_keypair(TEST_SEED).unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap().to_ct().unwrap();

        assert!(pubkey.verify_ct(&sig, TEST_MSG).is_ok());
    }

    #[test]
    fn verify_ct_wrong_message() {
        let (privkey, pubkey) = derive_keypair(TEST_SEED).unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap().to_ct().unwrap();

        assert!(matches!(
            pubkey.verify_ct(&sig, b"wrong message"),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    #[test]
    fn verify_ct_wrong_key() {
        let (privkey, _) = derive_keypair(TEST_SEED).unwrap();
        let (_, wrong_pubkey) = derive_keypair(ALT_SEED).unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap().to_ct().unwrap();

        assert!(matches!(
            wrong_pubkey.verify_ct(&sig, TEST_MSG),
            Err(Error::Signature(SignatureError::VerificationFailed))
        ));
    }

    // ─── Keypair From Mnemonic tests ─────────────────────────────────────────────

    #[cfg(feature = "mnemonic")]
    #[test]
    fn derive_keypair_from_mnemonic_is_deterministic() {
        // All-zeros entropy mnemonic: 23 × "abandon" + "art".
        // Tests the full chain: mnemonic → seed → keypair.
        let mnemonic = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "art",
        ];

        let (privkey1, pubkey1) = derive_keypair_from_mnemonic(&mnemonic, "").unwrap();
        let (privkey2, pubkey2) = derive_keypair_from_mnemonic(&mnemonic, "").unwrap();

        // Same mnemonic + passphrase must always produce identical keys.
        assert_eq!(privkey1.as_bytes(), privkey2.as_bytes());
        assert_eq!(pubkey1.as_bytes(), pubkey2.as_bytes());

        // Different passphrase must produce different keys.
        let (privkey3, pubkey3) = derive_keypair_from_mnemonic(&mnemonic, "passphrase").unwrap();
        assert_ne!(privkey1.as_bytes(), privkey3.as_bytes());
        assert_ne!(pubkey1.as_bytes(), pubkey3.as_bytes());

        // Same non-empty passphrase must also be deterministic.
        let (privkey4, pubkey4) = derive_keypair_from_mnemonic(&mnemonic, "passphrase").unwrap();
        assert_eq!(privkey3.as_bytes(), privkey4.as_bytes());
        assert_eq!(pubkey3.as_bytes(), pubkey4.as_bytes());
    }

    #[cfg(feature = "mnemonic")]
    #[test]
    fn derive_keypair_from_mnemonic_produces_usable_keys() {
        // Verify that keys derived from a mnemonic can actually sign and verify —
        // not just that they look structurally valid.
        let mnemonic = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "art",
        ];

        let (privkey, pubkey) = derive_keypair_from_mnemonic(&mnemonic, "").unwrap();
        let sig = privkey.sign(TEST_MSG).unwrap();

        assert!(pubkey.verify_compressed(&sig, TEST_MSG).is_ok());
    }

    #[cfg(feature = "mnemonic")]
    #[test]
    fn derive_keypair_from_mnemonic_invalid_mnemonic_returns_error() {
        // A mnemonic with an unknown word should propagate a MnemonicError
        // rather than panicking or producing garbage keys.
        let bad_mnemonic = [
            "notaword", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "art",
        ];

        let result = derive_keypair_from_mnemonic(&bad_mnemonic, "");
        assert!(matches!(
            result,
            Err(Error::Mnemonic(crate::error::MnemonicError::UnknownWord))
        ));
    }

    #[test]
    fn private_key_from_bytes_garbage_fails_at_sign_time() {
        // Using `from_bytes` will accept any bytes without validation, hence invalid
        // key material must surface as an error at sign time, not at construction.
        let garbage = [0xFFu8; FALCON_DET1024_PRIVKEY_SIZE];
        let privkey = PrivateKey::from_bytes(garbage);

        assert!(privkey.sign(TEST_MSG).is_err());
    }
}
