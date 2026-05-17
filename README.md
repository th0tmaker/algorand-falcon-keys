# algorand-falcon-keys

Rust bindings for deterministic Falcon-1024 post-quantum key generation, signing, and verification. **`Falcon-DET1024`** is currently the only post-quantum signing scheme supported by the Algorand blockchain.

## Disclaimer

> [!CAUTION]
> **This crate is exploratory and has not been audited.** It is not the work of a credentialed cryptographer. Anyone using it should understand the potential risks and liabilities involved, and use it at their own discretion. The API and internal derivation parameters are subject to potentially breaking changes.

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

This crate wraps the [`falcon`](vendor/falcon/) C library — specifically **`Falcon-DET1024`**, a variant that replaces the 40-byte random salt in standard Falcon with a 1-byte version field, making every signature fully reproducible from the same private key and message.

The crate currently covers:

- **Keypair derivation** — deterministic `(PrivateKey, PublicKey)` generation from an arbitrary-length seed via SHAKE-256 PRNG
- **Signing** — produces a `CompressedSignature` (Huffman-coded, variable length up to 1423 bytes); can be converted to a `CtSignature` (fixed 1538 bytes) via `.to_ct()`
- **Verification** — supports both compressed and constant-time (`CtSignature`) formats
- **Mnemonic derivation** — BIP-39 encode/decode and a Falcon-specific seed derivation chain (optional, see [mnemonic feature](#optional-mnemonic-feature))

## Core API

### Keypair derivation

```rust
use algorand_falcon_keys::{derive_keypair, PrivateKey, PublicKey};

// Any byte sequence is a valid seed. The caller is responsible for
// providing a seed with sufficient entropy.
let seed: &[u8] = /* ... */;
let (privkey, pubkey) = derive_keypair(seed)?;
```

The same seed always produces the same keypair.

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
use algorand_falcon_keys::{CompressedSignature, CtSignature, PrivateKey, PublicKey};

// PublicKey::from_bytes validates by decoding NTT coefficients.
let pubkey = PublicKey::from_bytes(&pubkey_bytes)?;

// PrivateKey::from_bytes does not validate — errors surface at sign time.
// Zeroize your copy of the bytes when done.
let privkey = PrivateKey::from_bytes(&privkey_bytes);

// Signatures validate their header byte and salt version on construction.
let sig = CompressedSignature::from_bytes(&sig_bytes)?;
let ct  = CtSignature::from_bytes(&ct_bytes)?;
```

> [!NOTE]
> `PrivateKey::from_bytes` defers validation by design — invalid bytes are only caught at sign time, not on construction. If you deserialize stored keys, validate storage integrity independently.

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
use algorand_falcon_keys::MnemonicError;

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

The mnemonic-to-keypair path is non-standard relative to typical BIP-39 usage and is specific to this crate.

Entropy and mnemonic are a lossless two-way encoding of each other — derivation starts from the mnemonic phrase itself, not the raw entropy bytes. The 64-byte intermediate is the canonical BIP-39 seed produced by PBKDF2-HMAC-SHA512 (one SHA-512 block, fixed by the BIP-39 spec). HKDF then domain-separates and compresses it to the 48-byte seed Falcon actually needs.

```text
entropy (32 bytes) ↔ mnemonic (24 words)   [lossless encoding, not derivation]

1. validate mnemonic (BIP-39 word list membership + checksum)
2. NFKD-normalize mnemonic sentence and passphrase (BIP-39 requirement)
3. PBKDF2-HMAC-SHA512 (2048 iterations, password = sentence, salt = "mnemonic" || passphrase)
4. 64-byte BIP-39 seed  [BIP-39 standard: one HMAC-SHA512 block]
5. HKDF-SHA512 (salt = "bip39-falcon-seed-salt-v1", info = "Falcon1024 seed v1")
6. 48-byte Falcon seed  [domain-separated from other BIP-39 uses of the same mnemonic]
7. derive_keypair(seed)
8. (PrivateKey, PublicKey)
```

The intermediate 64-byte BIP-39 seed is zeroized before the function returns.

> [!WARNING]
> The mnemonic path always derives a **48-byte** Falcon seed, matching Algorand's unofficial seed length convention. If your Falcon keypair was originally generated by passing a seed of any other length directly to `derive_keypair`, it **cannot** be recovered via a mnemonic — the mnemonic faithfully encodes your 32-byte entropy, but the Falcon seed derived from it will always be 48 bytes regardless.

## Memory and security properties

- `PrivateKey` does not implement `Clone`. Its bytes are zeroized on drop.
- `PrivateKey` implements the [`Zeroize`](https://docs.rs/zeroize) trait. Both `Zeroize` and `Zeroizing` are re-exported from the crate root, so downstream users do not need a direct `zeroize` dependency. This allows wrapping `PrivateKey` in `Zeroizing<PrivateKey>` for panic-safe early erasure, or composing it into a larger `#[derive(Zeroize)]` struct.
- `PrivateKey::from_bytes` takes a `&[u8; N]` reference. The caller is responsible for zeroizing their copy — `Zeroize` and `Zeroizing` are re-exported from the crate root for convenience.
- `derive_keypair` uses `Zeroizing<[u8; N]>` for its stack key buffer, so the buffer is erased on both the success and panic paths — not just on explicit returns.
- `derive_keypair_from_mnemonic` wraps the intermediate 48-byte Falcon seed in `Zeroizing`, ensuring it is erased even if the downstream `derive_keypair` call panics.
- `seed_from_mnemonic` zeroizes all sensitive heap-allocated intermediates (the NFKD-normalised mnemonic sentence, the passphrase salt string, and the 64-byte BIP-39 seed) before returning.
- Signatures are structurally validated (header byte, salt version, length) on construction, but cryptographic validity requires a separate verification call.
- The scheme is fully deterministic — the same key and message always produce the same signature bytes. This is by design for SNARK-friendliness in compact certificates, but it means the signing implementation must be functionally equivalent across all devices. Using the same private key across implementations with differing floating-point behaviour is a security concern; the vendored C library enforces integer FP emulation (`FALCON_FPEMU=1`) to mitigate this.

## Building

Requires a C compiler (GCC, Clang, or MSVC). The vendor C library is compiled at build time via `build.rs` using the `cc` crate. The crate has been tested on Windows (MSVC), Linux (GCC/Clang), and macOS (Clang).

The crate is `#![no_std]` on the Rust side (using `alloc` for heap types). The vendored C library links against `libc` for `memset`/`memcpy`, which is standard for FFI crates and does not conflict with `no_std` on the Rust layer.

```sh
cargo build
cargo test
cargo test --features mnemonic
```

The minimum supported Rust edition is **2024**.

For performance benchmarks, consult the vendored C code directly. The [`vendor/falcon/`](vendor/falcon/) directory includes a `speed` binary (see its `Makefile`) that benchmarks key generation, signing, and verification across Falcon parameter sets.

## License and attribution

This crate is MIT licensed.

The vendored [`falcon`](vendor/falcon/) C library is also distributed under the MIT license:

> Copyright (c) 2017-2020 Falcon Project
>
> The main implementation was written by **Thomas Pornin** (NCC Group).
> The deterministic signing mode was written by **David Lazar** (MIT CSAIL),
> with input from **Chris Peikert** and others at Algorand, Inc.

Full license text: [`vendor/falcon/README.txt`](vendor/falcon/README.txt)
