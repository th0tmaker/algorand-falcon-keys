// src/error.rs

#[derive(Debug)]
pub enum Error {
    InvalidPublicKey,
    Signature(SignatureError),
    Falcon(i32),
    #[cfg(feature = "mnemonic")]
    Mnemonic(MnemonicError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKey => f.write_str("invalid public key"),
            Self::Signature(e) => write!(f, "invalid signature: {e}"),
            Self::Falcon(code) => write!(f, "falcon error: {code}"),
            #[cfg(feature = "mnemonic")]
            Self::Mnemonic(e) => write!(f, "mnemonic error: {e}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Signature(e) => Some(e),
            #[cfg(feature = "mnemonic")]
            Self::Mnemonic(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SignatureError> for Error {
    fn from(e: SignatureError) -> Self {
        Self::Signature(e)
    }
}

#[cfg(feature = "mnemonic")]
impl From<MnemonicError> for Error {
    fn from(e: MnemonicError) -> Self {
        Self::Mnemonic(e)
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

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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

impl core::error::Error for SignatureError {}

#[cfg(feature = "mnemonic")]
#[derive(Debug)]
pub enum MnemonicError {
    InvalidEntropyLength,
    InvalidPhraseLength,
    UnknownWord,
    ChecksumMismatch,
    SeedDerivation,
}

#[cfg(feature = "mnemonic")]
impl core::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEntropyLength => f.write_str("entropy must be 32 bytes"),
            Self::InvalidPhraseLength  => f.write_str("phrase must contain 24 words"),
            Self::UnknownWord          => f.write_str("word not in BIP-39 list"),
            Self::ChecksumMismatch     => f.write_str("checksum mismatch"),
            Self::SeedDerivation       => f.write_str("seed derivation failed"),
        }
    }
}

#[cfg(feature = "mnemonic")]
impl core::error::Error for MnemonicError {}