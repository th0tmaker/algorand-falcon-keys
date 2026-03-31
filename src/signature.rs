// src/signature.rs

use crate::{
    constants::{FALCON_DET1024_SIG_COMPRESSED_HEADER, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE},
    error::Error,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompressedSignature(Vec<u8>);

impl CompressedSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::SignatureTooShort);
        }
        if bytes.len() > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE {
            return Err(Error::SignatureTooLong);
        }
        if bytes[0] != FALCON_DET1024_SIG_COMPRESSED_HEADER {
            return Err(Error::InvalidSignatureHeader);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
