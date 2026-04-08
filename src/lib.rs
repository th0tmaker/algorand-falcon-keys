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

