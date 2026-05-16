// src/lib.rs

#![no_std]

extern crate alloc;

mod constants;
mod error;
mod ffi;
mod keygen;
mod signature;

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
    zeroize::Zeroize,
};

#[cfg(feature = "mnemonic")]
pub use error::MnemonicError;
#[cfg(feature = "mnemonic")]
pub use keygen::derive_keypair_from_mnemonic;
#[cfg(feature = "mnemonic")]
pub use mnemonic::{
    entropy_to_mnemonic, mnemonic_to_entropy, seed_from_mnemonic,
    FALCON_SEED_SIZE, MNEMONIC_LEN,
};

