// src/error.rs

#[derive(Debug)]
pub enum Error {
    InvalidPublicKey,
    Signature(SignatureError),
    Falcon(i32),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey => f.write_str("invalid public key"),
            Self::Signature(e) => write!(f, "invalid signature: {e}"),
            Self::Falcon(code) => write!(f, "falcon error: {code}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Signature(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SignatureError> for Error {
    fn from(e: SignatureError) -> Self {
        Self::Signature(e)
    }
}

#[derive(Debug)]
pub enum SignatureError {
    InvalidHeader,
    UnsupportedSaltVersion,
    TooShort,
    TooLong,
    MalformedEncoding,
    VerificationFailed,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader => f.write_str("invalid header"),
            Self::UnsupportedSaltVersion => f.write_str("unsupported salt version"),
            Self::TooShort => f.write_str("too short"),
            Self::TooLong => f.write_str("too long"),
            Self::MalformedEncoding => f.write_str("malformed encoding"),
            Self::VerificationFailed => f.write_str("verification failed"),
        }
    }
}

impl std::error::Error for SignatureError {}
