// src/error.rs

#[derive(Debug)]
pub enum Error {
    InvalidPublicKey,
    InvalidSignatureHeader,
    SignatureTooShort,
    SignatureTooLong,
}
