// src/mnemonic/mod.rs

mod words;

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;

use crate::{error::{Error, MnemonicError}, zeroize::Zeroize};

pub const ENTROPY_LEN: usize = 32;
pub const CHECKSUM_BITS: usize = 8; // entropy_bits / 32
pub const BITS_PER_WORD: usize = 11;
pub const MNEMONIC_LEN: usize = 24; // (ENTROPY_BITS + CHECKSUM_BITS) / BITS_PER_WORD
pub const FALCON_SEED_SIZE: usize = 48;

const PBKDF2_ITERATIONS: u32 = 2048;
const BIP39_SEED_SIZE: usize = 64;
const HKDF_SALT: &str = "bip39-falcon-seed-salt-v1";
const HKDF_INFO: &str = "Falcon1024 seed v1";

// HKDF-SHA512 can output at most 255 × 64 = 16,320 bytes.
// HKDF spec: 255 blocks × 64 (SHA-512 has 512-bit/64-byte block size).
// This assert fires at compile time in case FALCON_SEED_SIZE ever exceeds that.
const _: () = assert!(
    FALCON_SEED_SIZE <= 255 * 64,
    "FALCON_SEED_SIZE exceeds HKDF-SHA512 maximum output length"
);

/// Converts 32 bytes of entropy into a 24-word BIP-39 mnemonic phrase.
///
/// ### BIP-39 encoding process
///
/// 1. Hash the entropy with SHA-256 and take the first `entropy_bits / 32` bits
///    as a checksum (8 bits for 256-bit entropy).
/// 2. Append those checksum bits to the entropy → 264 bits total.
/// 3. Split into 24 groups of 11 bits. Each 11-bit value (0–2047) is an index
///    into the 2048-word BIP-39 wordlist.
///
/// ### Why SHA-256 for the checksum?
///
/// The checksum must be *unpredictable* without knowing the full entropy. A simple
/// XOR or CRC would let anyone craft an arbitrary mnemonic that passes validation.
/// SHA-256 being one-way means the only way to produce a valid final word is to
/// know all preceding entropy bits — brute-forcing a "valid" mnemonic is no easier
/// than random chance.
///
/// ### The last word
///
/// For 256-bit entropy the last word carries only 3 bits of true entropy (11 − 8
/// checksum bits), so it is not freely chosen — it is fully determined by the
/// other 23 words. Mistyping any word produces a checksum mismatch on decode.
pub fn entropy_to_mnemonic(entropy: &[u8; ENTROPY_LEN]) -> [&'static str; MNEMONIC_LEN] {
    // SHA-256(entropy); the first {CHECKSUM_BITS} bits become the checksum
    let h = Sha256::digest(entropy);
    // Shift right by (8 - CHECKSUM_BITS) to align the top bits to the LSB
    let checksum = (h[0] >> (8 - CHECKSUM_BITS)) as u32;

    // `acc` is a sliding bit buffer filled 8 bits at a time (one entropy byte)
    // and drained 11 bits at a time (one word index)
    let mut acc: u32 = 0;
    let mut bits: usize = 0;
    let mut word_idx: usize = 0;
    let mut out = [""; MNEMONIC_LEN];

    for &byte in entropy {
        // Shift `acc` left by 8 and load the next entropy byte into the low bits
        acc = (acc << 8) | byte as u32;
        bits += 8;

        // Adding 8 bits to a remainder that is always < 11 gives at most 18 bits,
        // which is never enough for two extractions, hence no need for a `while` loop
        if bits >= BITS_PER_WORD {
            bits -= BITS_PER_WORD;
            // Shift `acc` right to bring the next 11 bits to the LSB position,
            // then mask to exactly 11 bits (0x7FF = 0b11111111111 = 2047)
            let index = ((acc >> bits) & 0x7FF) as usize;
            out[word_idx] = words::WORDS[index];
            word_idx += 1;
            // Clear the consumed bits, keeping only the remainder
            acc &= (1 << bits) - 1;
        }
    }

    // After processing all entropy bytes, `bits` holds the leftover count (3 for
    // 256-bit entropy: 256 % 11 = 3). Shift `acc` left to make room, then OR in
    // the 8-bit checksum. This gives exactly 11 bits for the final word
    acc = (acc << CHECKSUM_BITS) | checksum;
    bits += CHECKSUM_BITS;
    debug_assert_eq!(bits, BITS_PER_WORD); // must be exactly 11 bits here
    out[word_idx] = words::WORDS[acc as usize];

    // Return the output mnemonic phrase
    out
}

/// Decodes a 24-word BIP-39 mnemonic phrase back into the original 32 bytes of entropy.
///
/// Each word is looked up in the BIP-39 wordlist (via binary search, since the list is
/// sorted alphabetically) to recover its 11-bit index. The 24 × 11 = 264 bits are split
/// into 256 bits of entropy and 8 bits of checksum. The checksum is verified against
/// `SHA-256(entropy)[0]` before returning.
///
/// Returns `Err` if any word is not in the BIP-39 wordlist or the checksum does not match.
pub fn mnemonic_to_entropy(mnemonic: &[&str; MNEMONIC_LEN]) -> Result<[u8; ENTROPY_LEN], Error> {
    // Create a mutable buffer of zeroed bytes to store the entropy
    let mut entropy = [0u8; ENTROPY_LEN];

    // `acc` is a sliding bit buffer filled 11 bits at a time (one word index)
    // and drained 8 bits at a time (one entropy byte)
    let mut acc: u32 = 0;
    let mut bits: usize = 0;
    let mut out_idx: usize = 0;

    for &word in mnemonic {
        // Binary search is valid because the BIP-39 wordlist is sorted alphabetically
        let index = words::WORDS
            .binary_search_by(|&w| w.cmp(word))
            .map_err(|_| MnemonicError::UnknownWord)? as u32;

        // Shift `acc` left by 11 and load the word index into the low bits
        acc = (acc << BITS_PER_WORD) | index;
        bits += BITS_PER_WORD;

        // Adding 11 bits to a remainder that is always < 8 gives at most 18 bits,
        // which can amount to 1 or 2 byte extractions, hence `while` loop needed
        while bits >= 8 && out_idx < ENTROPY_LEN {
            bits -= 8;
            entropy[out_idx] = (acc >> bits) as u8;
            acc &= (1 << bits) - 1;
            out_idx += 1;
        }
    }

    // After all 24 words: 
    // 24 × 11 − 32 × 8 = 264 − 256 = 8 bits remain — the checksum.
    debug_assert_eq!(bits, CHECKSUM_BITS);
    debug_assert_eq!(out_idx, ENTROPY_LEN);
    let checksum = acc as u8;

    // Recompute the expected checksum from the recovered entropy and compare.
    if checksum != Sha256::digest(&entropy)[0] >> (8 - CHECKSUM_BITS) {
        return Err(MnemonicError::ChecksumMismatch.into());
    }

    // Return the entropy
    Ok(entropy)
}

/// Derives a 48-byte Falcon seed from a BIP-39 mnemonic and an optional passphrase.
///
/// ### Derivation process
///
/// 1. Validate the mnemonic (word list membership + checksum) via [mnemonic_to_entropy].
/// 2. NFKD-normalize both the mnemonic sentence and the passphrase (required by BIP-39
///    so that visually identical Unicode strings always produce the same seed).
/// 3. Run `PBKDF2-HMAC-SHA512` with 2048 iterations and the salt `"mnemonic" || passphrase`
///    to obtain the canonical 64-byte BIP-39 seed.
/// 4. Collapse to 48 bytes via `HKDF-SHA512` using Falcon-specific salt and info strings.
///    The 48-byte output is what gets passed directly to [derive_keypair].
///
/// The intermediate 64-byte BIP-39 seed is zeroed in memory before this function returns.
///
/// Pass an empty string for `passphrase` to use no passphrase.
pub fn seed_from_mnemonic(
    mnemonic: &[&str; MNEMONIC_LEN],
    passphrase: &str,
) -> Result<[u8; FALCON_SEED_SIZE], Error> {
    // Validate structure and checksum before deriving any secrets
    mnemonic_to_entropy(mnemonic)?;

    // NFKD-normalize the mnemonic sentence and passphrase as required by BIP-39
    let sentence: String = mnemonic.join(" ").nfkd().collect();
    let salt = format!("mnemonic{}", passphrase.nfkd().collect::<String>());

    // PBKDF2-HMAC-SHA512: canonical BIP-39 seed derivation
    let mut bip39_seed = [0u8; BIP39_SEED_SIZE];
    pbkdf2_hmac::<Sha512>(
        sentence.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ITERATIONS,
        &mut bip39_seed,
    );

    // HKDF-SHA512: collapse the 64-byte BIP-39 seed to the 48-byte Falcon seed.
    // Domain-separated with a Falcon-specific salt and info string so the output
    // is independent from any other BIP-39 key derivation use of the same seed
    let hkdf = Hkdf::<Sha512>::new(Some(HKDF_SALT.as_bytes()), &bip39_seed);
    let mut out = [0u8; FALCON_SEED_SIZE];
    hkdf.expand(HKDF_INFO.as_bytes(), &mut out)
        .map_err(|_| MnemonicError::SeedDerivation)?;

    // Zeroize the intermediate BIP-39 seed — it must not outlive this stack frame
    bip39_seed.zeroize();

    // Return the output 48-byte Falcon seed
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MnemonicError;

    // Official BIP-39 test vectors for 256-bit entropy.
    // Source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json

    fn hex_to_entropy(hex: &str) -> [u8; ENTROPY_LEN] {
        let mut out = [0u8; ENTROPY_LEN];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    fn split_mnemonic(s: &str) -> [&str; MNEMONIC_LEN] {
        let words: Vec<&str> = s.split(' ').collect();
        words.try_into().unwrap()
    }

    // ── BIP-39 official test vectors ─────────────────────────────────────────

    #[test]
    fn bip39_vectors_encode() {
        let vectors: &[(&str, &str)] = &[
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            ),
            (
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            ),
            (
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            ),
            (
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            ),
            (
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            ),
        ];

        for (entropy_hex, expected_mnemonic) in vectors {
            let entropy = hex_to_entropy(entropy_hex);
            let mnemonic = entropy_to_mnemonic(&entropy);
            assert_eq!(mnemonic, split_mnemonic(expected_mnemonic), "encode failed for entropy {entropy_hex}");
        }
    }

    #[test]
    fn bip39_vectors_decode() {
        let vectors: &[(&str, &str)] = &[
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            ),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            ),
            (
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            ),
            (
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            ),
            (
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            ),
            (
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            ),
        ];

        for (entropy_hex, mnemonic_str) in vectors {
            let expected_entropy = hex_to_entropy(entropy_hex);
            let mnemonic = split_mnemonic(mnemonic_str);
            let recovered = mnemonic_to_entropy(&mnemonic).unwrap();
            assert_eq!(recovered, expected_entropy, "decode failed for mnemonic: {mnemonic_str}");
        }
    }

    // ── entropy_to_mnemonic ──────────────────────────────────────────────────

    #[test]
    fn encode_all_zero_entropy() {
        let mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        assert!(mnemonic[..23].iter().all(|&w| w == "abandon")); // 23 × "abandon"
        assert_eq!(mnemonic[23], "art");                          // checksum word
    }

    #[test]
    fn encode_all_ff_entropy() {
        let mnemonic = entropy_to_mnemonic(&[0xFFu8; ENTROPY_LEN]);
        assert!(mnemonic[..23].iter().all(|&w| w == "zoo")); // 23 × "zoo"
        assert_eq!(mnemonic[23], "vote");                     // checksum word
    }

    #[test]
    fn encode_single_bit_flip_changes_mnemonic() {
        let mut entropy = [0x00u8; ENTROPY_LEN];
        let base = entropy_to_mnemonic(&entropy);
        entropy[0] ^= 0x01;
        assert_ne!(base, entropy_to_mnemonic(&entropy));
    }

    // ── mnemonic_to_entropy ──────────────────────────────────────────────────

    #[test]
    fn decode_roundtrip_all_zeros() {
        let entropy = [0x00u8; ENTROPY_LEN];
        let mnemonic = entropy_to_mnemonic(&entropy);
        assert_eq!(mnemonic_to_entropy(&mnemonic).unwrap(), entropy);
    }

    #[test]
    fn decode_roundtrip_all_ff() {
        let entropy = [0xFFu8; ENTROPY_LEN];
        let mnemonic = entropy_to_mnemonic(&entropy);
        assert_eq!(mnemonic_to_entropy(&mnemonic).unwrap(), entropy);
    }

    #[test]
    fn decode_rejects_unknown_word() {
        let mut mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        mnemonic[0] = "notaword";
        assert!(matches!(
            mnemonic_to_entropy(&mnemonic),
            Err(Error::Mnemonic(MnemonicError::UnknownWord))
        ));
    }

    #[test]
    fn decode_rejects_checksum_mismatch() {
        let mut mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        // Swap the last word for a different valid BIP-39 word to corrupt the checksum.
        mnemonic[23] = "zoo";
        assert!(matches!(
            mnemonic_to_entropy(&mnemonic),
            Err(Error::Mnemonic(MnemonicError::ChecksumMismatch))
        ));
    }

    // ── seed_from_mnemonic ───────────────────────────────────────────────────

    #[test]
    fn seed_is_48_bytes() {
        let mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        let seed = seed_from_mnemonic(&mnemonic, "").unwrap();
        assert_eq!(seed.len(), FALCON_SEED_SIZE);
    }

    #[test]
    fn seed_is_deterministic() {
        let mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        assert_eq!(
            seed_from_mnemonic(&mnemonic, "").unwrap(),
            seed_from_mnemonic(&mnemonic, "").unwrap()
        );
    }

    #[test]
    fn seed_differs_with_passphrase() {
        let mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        let without = seed_from_mnemonic(&mnemonic, "").unwrap();
        let with = seed_from_mnemonic(&mnemonic, "falcon").unwrap();
        assert_ne!(without, with);
    }

    #[test]
    fn seed_differs_with_different_mnemonic() {
        let mnemonic_a = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        let mnemonic_b = entropy_to_mnemonic(&[0xFFu8; ENTROPY_LEN]);
        assert_ne!(
            seed_from_mnemonic(&mnemonic_a, "").unwrap(),
            seed_from_mnemonic(&mnemonic_b, "").unwrap()
        );
    }

    #[test]
    fn seed_rejects_invalid_mnemonic() {
        let mut mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        mnemonic[0] = "notaword";
        assert!(seed_from_mnemonic(&mnemonic, "").is_err());
    }

    // ── derive_keypair_from_mnemonic ─────────────────────────────────────────

    #[test]
    fn keypair_from_mnemonic_is_deterministic() {
        let mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        let (privkey1, pubkey1) = crate::keygen::derive_keypair_from_mnemonic(&mnemonic, "").unwrap();
        let (privkey2, pubkey2) = crate::keygen::derive_keypair_from_mnemonic(&mnemonic, "").unwrap();
        assert_eq!(privkey1.as_bytes(), privkey2.as_bytes());
        assert_eq!(pubkey1.as_bytes(), pubkey2.as_bytes());
    }

    #[test]
    fn keypair_from_mnemonic_differs_with_passphrase() {
        let mnemonic = entropy_to_mnemonic(&[0x00u8; ENTROPY_LEN]);
        let (_, pubkey1) = crate::keygen::derive_keypair_from_mnemonic(&mnemonic, "").unwrap();
        let (_, pubkey2) = crate::keygen::derive_keypair_from_mnemonic(&mnemonic, "falcon").unwrap();
        assert_ne!(pubkey1.as_bytes(), pubkey2.as_bytes());
    }
}
