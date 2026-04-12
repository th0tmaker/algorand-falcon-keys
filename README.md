# algorand-falcon-keys

Rust bindings for deterministic Falcon-1024 post-quantum key generation, signing, and verification. As of this moment in time, this **`Falcon-det1024`** variant is the only post-quantum signing scheme supported by the Algorand blockchain.

## Disclaimer

**WARNING: This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API and internal derivation parameters are subject to potentially breaking changes.

## Installation

Add the crate to your `Cargo.toml` directly from GitHub. Pinning to a specific commit with `rev` is recommended — the API is subject to potentially breaking changes:

```toml
# Default (keygen, signing, verification only)
[dependencies]
algorand-falcon-keys = { git = "https://github.com/th0tmaker/algorand-falcon-keys", rev = "<commit-sha>" }

# With optional mnemonic support (BIP-39 encode/decode + Falcon seed derivation)
algorand-falcon-keys = { git = "https://github.com/th0tmaker/algorand-falcon-keys", rev = "<commit-sha>", features = ["mnemonic"] }
```

Replace `<commit-sha>` with the full commit hash you want to target, e.g. `rev = "a1b2c3d"`.

## Overview

This crate wraps the [`falcon-det`](vendor/falcon/) C library. This **`Falcon-det1024`** variant diverges from standard Falcon by replacing the 40-byte random salt generated per signature with a 1-byte deterministic version field, so the same private key and message always produce the same signature.

The crate currently covers:

- **Keypair derivation** — deterministic `(PrivateKey, PublicKey)` generation from an arbitrary-length seed via SHAKE-256 PRNG
- **Signing** — produces a `CompressedSignature` (Huffman-coded, variable length up to 1423 bytes); can be converted to a `CtSignature` (fixed 1538 bytes) via `.to_ct()`
- **Verification** — supports both compressed and constant-time (`CtSignature`) formats
- **Mnemonic derivation** — BIP-39 encode/decode and a Falcon-specific seed derivation chain (optional, see [mnemonic feature](#optional-mnemonic-feature))

Raw polynomial coefficients (`f`, `g`, `F`, `G`) are intentionally not exposed at this time. Accessing them is not required for the core keygen, signing, and verification workflow, and exposing them would significantly widen the API surface — adding complexity and maintenance burden before the fundamentals are stable.

## Core API

### Keypair derivation

```rust
use algorand_falcon_keys::{derive_keypair, PrivateKey, PublicKey};

// Any byte sequence is a valid seed. The caller is responsible for
// providing a seed with sufficient entropy.
let seed: &[u8] = /* ... */;
let (privkey, pubkey) = derive_keypair(seed)?;
```

The seed is absorbed into a SHAKE-256 PRNG which drives key generation. The same seed always produces the same keypair.

> **Algorand note:** Algorand uses 48 bytes of entropy as its standard seed size for Falcon key generation. If you are integrating this crate with Algorand, ensure your seed is exactly 48 bytes to match that convention and maintain adequate security margins.

### Signing

```rust
// Returns a CompressedSignature (Huffman-coded, variable length up to 1423 bytes).
let sig = privkey.sign(message)?;
```

### Verification

```rust
// Compressed format — variable-length, more compact.
pubkey.verify_compressed(&sig, message)?;

// Constant-time (CT) format — fixed 1538 bytes, suitable for
// side-channel-sensitive contexts.
let ct_sig = sig.to_ct()?;
pubkey.verify_ct(&ct_sig, message)?;
```

### Deserializing keys and signatures

```rust
// PublicKey::from_bytes validates by decoding NTT coefficients.
let pubkey = PublicKey::from_bytes(&pubkey_bytes)?;

// PrivateKey::from_bytes does NOT validate — errors surface at sign time.
// The caller's buffer is consumed and zeroized after the copy.
let privkey = PrivateKey::from_bytes(privkey_bytes);

// Signatures validate their header byte and salt version on construction.
let sig = CompressedSignature::from_bytes(&sig_bytes)?;
let ct  = CtSignature::from_bytes(&ct_bytes)?;
```

> **Caution:** `PrivateKey::from_bytes` skips structural validation by design. If you serialize a private key, store it, and reload it later, any corruption in the bytes will not be caught at deserialization — it will only surface as `Err(Error::Falcon(...))` when `sign` is called. Validate storage and transport integrity independently if this matters for your use case.

### Error handling

All fallible functions return `Result<_, Error>`. The top-level error type and its variants:

```rust
use algorand_falcon_keys::{Error, SignatureError};

match result {
    Err(Error::InvalidPublicKey) => { /* public key bytes failed NTT decode */ }
    Err(Error::Signature(e)) => match e {
        SignatureError::InvalidHeader => { /* wrong header byte */ }
        SignatureError::UnsupportedSaltVersion => { /* unrecognised salt version */ }
        SignatureError::TooShort => { /* fewer than 2 bytes */ }
        SignatureError::TooLong => { /* exceeds max compressed size */ }
        SignatureError::MalformedEncoding => { /* compressed → CT conversion failed */ }
        SignatureError::VerificationFailed => { /* signature did not verify */ }
    }
    Err(Error::Falcon(code)) => { /* error code propagated from the C library */ }
    Ok(_) => { /* success */ }
}
```

With the `mnemonic` feature enabled, `Error::Mnemonic(MnemonicError)` is also available:

```rust
use algorand_falcon_keys::error::MnemonicError;

// MnemonicError variants:
// UnknownWord        — a word was not found in the BIP-39 wordlist
// ChecksumMismatch   — the recovered checksum did not match
// SeedDerivation     — HKDF expand step failed
```

## Key and signature sizes

| Item | Size |
|---|---|
| Public key | 1793 bytes |
| Private key | 2305 bytes |
| Compressed signature (max) | 1423 bytes |
| CT signature (fixed) | 1538 bytes |

## Optional: mnemonic feature

The `mnemonic` feature is **not enabled by default**. Enabling it pulls in additional dependencies (`sha2`, `pbkdf2`, `hkdf`, `unicode-normalization`) and exposes BIP-39 mnemonic encode/decode and Falcon seed derivation. See [Installation](#installation) for how to enable it.

### What it provides

**Entropy ↔ mnemonic:**

```rust
use algorand_falcon_keys::{entropy_to_mnemonic, mnemonic_to_entropy};

let entropy = [/* 32 bytes */];
let mnemonic: [&str; 24] = entropy_to_mnemonic(&entropy);
let recovered = mnemonic_to_entropy(&mnemonic)?; // validates checksum
```

**Keypair from mnemonic:**

```rust
use algorand_falcon_keys::derive_keypair_from_mnemonic;

let (privkey, pubkey) = derive_keypair_from_mnemonic(&mnemonic, "passphrase")?;
// Pass "" for no passphrase.
```

### Derivation chain

The mnemonic-to-keypair path is non-standard relative to typical BIP-39 usage and is specific to this crate:

```
mnemonic derivation workflow:

1. PBKDF2-HMAC-SHA512 (2048 iterations, salt = "mnemonic" || passphrase)
2. 64-byte BIP-39 seed
3. HKDF-SHA512 (Falcon-specific salt + info strings)
4. 48-byte Falcon seed
5. derive_keypair(seed)
6. (PrivateKey, PublicKey)
```

The intermediate 64-byte BIP-39 seed is zeroized before the function returns.

## Memory and security properties

- `PrivateKey` does not implement `Clone`. Its bytes are zeroized on drop.
- `PrivateKey::from_bytes` consumes the caller's array and zeroizes it after copying the key material in.
- `derive_keypair` zeroizes its stack-allocated key buffer after constructing `PrivateKey`, even on error paths.
- Signatures are structurally validated (header byte, salt version, length) on construction, but cryptographic validity requires a separate verification call.
- The scheme is fully deterministic — the same seed and message always produce the same signature. Applications must account for this if signature uniqueness or unlinkability is a requirement.

## Building

Requires a C compiler (GCC, Clang, or MSVC). The vendor C library is compiled at build time via `build.rs` using the `cc` crate. The crate has been tested on Windows (MSVC), Linux (GCC/Clang), and macOS (Clang).

```sh
cargo build
cargo test
cargo test --features mnemonic
```

The minimum supported Rust edition is **2024**.

For performance benchmarks, consult the vendored C code directly. The [`vendor/falcon/`](vendor/falcon/) directory includes a `speed` binary (see its `Makefile`) that benchmarks key generation, signing, and verification across Falcon parameter sets.

## License and attribution

This crate is MIT licensed.

The vendored [`falcon-det`](vendor/falcon/) C library is also distributed under the MIT license:

> Copyright (c) 2017-2020 Falcon Project
>
> The main implementation was written by **Thomas Pornin** (NCC Group).
> The deterministic signing mode was written by **David Lazar** (MIT CSAIL),
> with input from **Chris Peikert** and others at Algorand, Inc.

Full license text: [`vendor/falcon/README.txt`](vendor/falcon/README.txt)
