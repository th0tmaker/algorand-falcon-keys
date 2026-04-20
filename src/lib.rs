// src/lib.rs

mod constants;
mod ffi;
mod keygen;
mod signature;
mod zeroize;

pub mod error;
#[cfg(feature = "mnemonic")]
pub mod mnemonic;

pub use {
    constants::{
        FALCON_DET1024_PUBKEY_SIZE,
        FALCON_DET1024_PRIVKEY_SIZE,
        FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
        FALCON_DET1024_SIG_CT_SIZE,
        FALCON_DET1024_SIG_COMPRESSED_HEADER,
        FALCON_DET1024_SIG_CT_HEADER,
        FALCON_DET1024_CURRENT_SALT_VERSION,
    },
    error::{Error, SignatureError},
    keygen::{derive_keypair, PrivateKey, PublicKey},
    signature::{CompressedSignature, CtSignature},
};

#[cfg(feature = "mnemonic")]
pub use keygen::derive_keypair_from_mnemonic;
#[cfg(feature = "mnemonic")]
pub use mnemonic::{
    entropy_to_mnemonic, mnemonic_to_entropy, seed_from_mnemonic,
    FALCON_SEED_SIZE, MNEMONIC_LEN,
};

