// src/signature.rs

use std::os::raw::c_void;

use crate::{
    constants::{
        FALCON_DET1024_CURRENT_SALT_VERSION, FALCON_DET1024_SIG_COMPRESSED_HEADER,
        FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, FALCON_DET1024_SIG_CT_HEADER,
        FALCON_DET1024_SIG_CT_SIZE,
    },
    error::{Error, SignatureError},
    ffi::falcon_det1024_convert_compressed_to_ct,
};

/// A Falcon det1024 signature in compressed (Huffman-coded) format.
///
/// This type enforces structural integrity only: the header byte, salt version,
/// and length are validated on construction. It does not guarantee the signature is cryptographic
/// valid — a well-formed `CompressedSignature` may still fail verification.
/// Cryptographic validity must be established separately by calling
/// `verify_compressed` with the corresponding public key and message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompressedSignature(Box<[u8]>);

impl CompressedSignature {
    /// Constructor: Returns an instance of self from bytes.
    ///
    /// NOTE: Will only fail if input bytes are structurally malformed (invalid size, header, or salt version).
    /// In order to guarantee the `CompressedSignature` type ` or its underyling raw bytes are cryptographically valid,
    /// a seperate verification function must be used, where the signature is computed against a public key and message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Must have at least a header byte and a salt version byte
        if bytes.len() < 2 {
            return Err(Error::Signature(SignatureError::TooShort));
        }
        // First byte must carry the correct det1024 compressed-format header
        if bytes[0] != FALCON_DET1024_SIG_COMPRESSED_HEADER {
            return Err(Error::Signature(SignatureError::InvalidHeader));
        }
        // Second byte must use a valid salt version
        if bytes[1] != FALCON_DET1024_CURRENT_SALT_VERSION {
            return Err(Error::Signature(SignatureError::UnsupportedSaltVersion));
        }
        // Overall length must not exceed the max size limit of a compressed signature
        if bytes.len() > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE {
            return Err(Error::Signature(SignatureError::TooLong));
        }

        // Return `CompressedSignature` type from input bytes
        Ok(Self(bytes.into()))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the salt version embedded in the signature.
    pub fn salt_version(&self) -> u8 {
        self.0[1]
    }

    /// Converts this signature from compressed to constant-time format.
    pub fn to_ct(&self) -> Result<CtSignature, Error> {
        // Init a mutable buffer for the constant-time signature bytes
        let mut ct = [0u8; FALCON_DET1024_SIG_CT_SIZE];

        // Convert signature from compressed to ct
        let ret = unsafe {
            falcon_det1024_convert_compressed_to_ct(
                ct.as_mut_ptr() as *mut c_void,
                self.0.as_ptr() as *const c_void,
                self.0.len(),
            )
        };

        // If return is NOT equal to zero, conversion failed, throw error
        if ret != 0 {
            return Err(SignatureError::MalformedEncoding.into());
        }

        // Return `CtSignature` type from the mutated buffer
        Ok(CtSignature(ct))
    }
}

/// A Falcon det1024 signature in constant-time (CT) format.
///
/// CT format is always exactly `FALCON_DET1024_SIG_CT_SIZE` bytes.
/// This type enforces structural integrity only — header
/// byte, salt version, and exact length. Cryptographic validity must be
/// established separately by calling `verify_ct` with the corresponding public
/// key and message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CtSignature([u8; FALCON_DET1024_SIG_CT_SIZE]);

impl CtSignature {
    /// Constructor: Returns an instance of self from bytes.
    ///
    /// NOTE: Will only fail if input bytes are structurally malformed (invalid header or salt version).
    /// In order to guarantee the `CtSignature` type or its underyling raw bytes are cryptographically valid,
    /// a seperate verification function must be used, where the signature is computed against a public key and message.
    pub fn from_bytes(bytes: &[u8; FALCON_DET1024_SIG_CT_SIZE]) -> Result<Self, Error> {
        // First byte must carry the correct det1024 CT-format header.
        if bytes[0] != FALCON_DET1024_SIG_CT_HEADER {
            return Err(Error::Signature(SignatureError::InvalidHeader));
        }
        // Second byte must use a valid salt version.
        if bytes[1] != FALCON_DET1024_CURRENT_SALT_VERSION {
            return Err(Error::Signature(SignatureError::UnsupportedSaltVersion));
        }

        Ok(Self(*bytes))
    }

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; FALCON_DET1024_SIG_CT_SIZE] {
        &self.0
    }

    /// Returns the salt version embedded in the signature.
    pub fn salt_version(&self) -> u8 {
        self.0[1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::{
            FALCON_DET1024_CURRENT_SALT_VERSION, FALCON_DET1024_SIG_COMPRESSED_HEADER,
            FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, FALCON_DET1024_SIG_CT_HEADER,
            FALCON_DET1024_SIG_CT_SIZE,
        },
        keygen::derive_keypair,
    };

    const TEST_SEED: &[u8] = b"test1234";
    const TEST_MSG: &[u8] = b"hello algorand";

    // Generates a real compressed signature over TEST_MSG.
    fn make_compressed_sig() -> CompressedSignature {
        let (privkey, _) = derive_keypair(TEST_SEED).unwrap();
        privkey.sign(TEST_MSG).unwrap()
    }

    // Minimal structurally valid compressed bytes: correct header, salt version, padded to 10 bytes.
    fn valid_compressed_sig_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 10];
        bytes[0] = FALCON_DET1024_SIG_COMPRESSED_HEADER;
        bytes[1] = FALCON_DET1024_CURRENT_SALT_VERSION;
        bytes
    }

    // Minimal structurally valid CT bytes: correct header, salt version, rest zeroed.
    fn valid_ct_sig_bytes() -> [u8; FALCON_DET1024_SIG_CT_SIZE] {
        let mut bytes = [0u8; FALCON_DET1024_SIG_CT_SIZE];
        bytes[0] = FALCON_DET1024_SIG_CT_HEADER;
        bytes[1] = FALCON_DET1024_CURRENT_SALT_VERSION;
        bytes
    }

    // --- CompressedSignature tests ---

    #[test]
    fn from_bytes_and_as_bytes() {
        let bytes = valid_compressed_sig_bytes();
        let sig = CompressedSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn from_bytes_rejects_malformed() {
        // Too short: empty and single-byte.
        assert!(matches!(
            CompressedSignature::from_bytes(&[]),
            Err(Error::Signature(SignatureError::TooShort))
        ));
        assert!(matches!(
            CompressedSignature::from_bytes(&[FALCON_DET1024_SIG_COMPRESSED_HEADER]),
            Err(Error::Signature(SignatureError::TooShort))
        ));

        // Wrong header byte.
        let mut bad_header = valid_compressed_sig_bytes();
        bad_header[0] = 0x00;
        assert!(matches!(
            CompressedSignature::from_bytes(&bad_header),
            Err(Error::Signature(SignatureError::InvalidHeader))
        ));

        // Unknown salt version.
        let mut bad_salt = valid_compressed_sig_bytes();
        bad_salt[1] = 0xFF;
        assert!(matches!(
            CompressedSignature::from_bytes(&bad_salt),
            Err(Error::Signature(SignatureError::UnsupportedSaltVersion))
        ));

        // Exceeds maximum encoded size.
        let mut too_long = vec![0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE + 1];
        too_long[0] = FALCON_DET1024_SIG_COMPRESSED_HEADER;
        too_long[1] = FALCON_DET1024_CURRENT_SALT_VERSION;
        assert!(matches!(
            CompressedSignature::from_bytes(&too_long),
            Err(Error::Signature(SignatureError::TooLong))
        ));
    }

    #[test]
    fn compressed_salt_version() {
        let sig = CompressedSignature::from_bytes(&valid_compressed_sig_bytes()).unwrap();
        assert_eq!(sig.salt_version(), FALCON_DET1024_CURRENT_SALT_VERSION);
    }

    #[test]
    fn compressed_to_ct() {
        let ct = make_compressed_sig().to_ct();

        assert!(ct.is_ok());
        assert_eq!(ct.unwrap().as_bytes()[0], FALCON_DET1024_SIG_CT_HEADER);
    }

    // --- CtSignature tests ---

    #[test]
    fn ct_from_bytes_and_as_bytes() {
        let bytes = valid_ct_sig_bytes();
        let sig = CtSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn ct_from_bytes_rejects_malformed() {
        // Wrong header byte.
        let mut bad_header = valid_ct_sig_bytes();
        bad_header[0] = 0x00;
        assert!(matches!(
            CtSignature::from_bytes(&bad_header),
            Err(Error::Signature(SignatureError::InvalidHeader))
        ));

        // Unknown salt version.
        let mut bad_salt = valid_ct_sig_bytes();
        bad_salt[1] = 0xFF;
        assert!(matches!(
            CtSignature::from_bytes(&bad_salt),
            Err(Error::Signature(SignatureError::UnsupportedSaltVersion))
        ));
    }

    #[test]
    fn ct_salt_version() {
        let sig = CtSignature::from_bytes(&valid_ct_sig_bytes()).unwrap();
        assert_eq!(sig.salt_version(), FALCON_DET1024_CURRENT_SALT_VERSION);
    }
}
