// src/mnemonic/mod.rs

mod words;

// pub fn

pub fn entropy_to_mnemonic() {
    todo!()
}

// use sha2::{Digest, Sha256};
// use crate::error::{Error, MnemonicError};

// const ENTROPY_LEN: usize = 32;
// const PHRASE_LEN: usize = 24;
// const BITS_PER_WORD: usize = 11;
// const CHECKSUM_BITS: usize = 8; // entropy_len / 4 = 256 / 4

// /// Converts 32 bytes of entropy into a 24-word BIP-39 mnemonic phrase.
// pub fn entropy_to_mnemonic(entropy: &[u8; ENTROPY_LEN]) -> Result<[&'static str; PHRASE_LEN], Error> {
//     let hash = Sha256::digest(entropy);
//     let checksum = (hash[0] >> (8 - CHECKSUM_BITS)) as u32;

//     let mut out = [""; PHRASE_LEN];
//     let mut acc: u32 = 0;
//     let mut bits: usize = 0;
//     let mut word_idx: usize = 0;

//     for &byte in entropy {
//         acc = (acc << 8) | byte as u32;
//         bits += 8;

//         while bits >= BITS_PER_WORD {
//             bits -= BITS_PER_WORD;
//             let index = ((acc >> bits) & 0x7FF) as usize;
//             out[word_idx] = words::WORDS[index];
//             word_idx += 1;
//             acc &= (1 << bits) - 1;
//         }
//     }

//     // append checksum word
//     acc = (acc << CHECKSUM_BITS) | checksum;
//     bits += CHECKSUM_BITS;
//     debug_assert_eq!(bits, BITS_PER_WORD);
//     out[word_idx] = words::WORDS[acc as usize];

//     Ok(out)
// }

// /// Decodes a 24-word BIP-39 mnemonic phrase back into the original 32 bytes of entropy.
// /// Validates the checksum.
// pub fn mnemonic_to_entropy(phrase: &[&str; PHRASE_LEN]) -> Result<[u8; ENTROPY_LEN], Error> {
//     let word_to_index = |w: &str| -> Result<u32, Error> {
//         words::WORDS
//             .iter()
//             .position(|&x| x == w)
//             .map(|i| i as u32)
//             .ok_or(MnemonicError::UnknownWord.into())
//     };

//     let mut entropy = [0u8; ENTROPY_LEN];
//     let mut acc: u32 = 0;
//     let mut bits: usize = 0;
//     let mut out_idx: usize = 0;

//     for &word in phrase {
//         let index = word_to_index(word)?;
//         acc = (acc << BITS_PER_WORD) | index;
//         bits += BITS_PER_WORD;

//         while bits >= 8 && out_idx < ENTROPY_LEN {
//             bits -= 8;
//             entropy[out_idx] = (acc >> bits) as u8;
//             acc &= (1 << bits) - 1;
//             out_idx += 1;
//         }
//     }

//     // remaining bits are the checksum
//     debug_assert_eq!(bits, CHECKSUM_BITS);
//     let checksum = acc as u8;
//     let expected = Sha256::digest(&entropy);
//     let expected_checksum = expected[0] >> (8 - CHECKSUM_BITS);

//     if checksum != expected_checksum {
//         return Err(MnemonicError::ChecksumMismatch.into());
//     }

//     Ok(entropy)
// }