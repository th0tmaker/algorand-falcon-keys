// src/lib.rs

mod constants;
pub mod error;
mod ffi;
mod keygen;
mod signature;

pub use error::{Error, SignatureError};
pub use keygen::{derive_keypair, PrivateKey, PublicKey};
pub use signature::{CompressedSignature, CtSignature};
