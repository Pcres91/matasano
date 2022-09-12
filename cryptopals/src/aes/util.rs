use std::convert::TryInto;

use crate::{
    aes::*,
    common::{errors::AesResult, util::until_err},
};
use itertools::FoldWhile::{Continue, Done};
use itertools::Itertools;
use rayon::prelude::*;

pub type Result<T> = AesResult<T>;

pub const KNOWN_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

pub trait Cipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub fn generate_rnd_key() -> [u8; 16] {
    extern crate rand;
    use rand::prelude::*;

    let mut rng = rand::thread_rng();

    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);

    key
}

#[derive(Debug, PartialEq)]
pub enum EncryptionType {
    Ecb128,
    Cbc128,
}

/// Takes the plaintext, adds 0-5bytes prefix, adds 0-5bytes suffix, and then
/// randomly encrypts with either ecb128 or cbc128. Returned is the ciphertext
/// with a boolean: true = ecb128 encrypted, false = cbc128 encrypted
pub fn encryption_oracle(plaintext: &[u8]) -> Result<(Vec<u8>, EncryptionType)> {
    let key = generate_rnd_key();

    extern crate rand;
    use rand::prelude::*;
    let mut rng = rand::thread_rng();

    // extend plain text with 5-10 bytes at the start and end
    let num_prefix_bytes: usize = rng.gen_range(5..=10);
    let mut prefix = vec![0u8; num_prefix_bytes];
    rng.fill_bytes(&mut prefix);

    let num_suffix_bytes: usize = rng.gen_range(5..=10);
    let mut suffix = vec![0u8; num_suffix_bytes];
    rng.fill_bytes(&mut suffix);

    let mut new_plaintext: Vec<u8> = Vec::new();
    new_plaintext.extend_from_slice(&prefix);
    new_plaintext.extend_from_slice(plaintext);
    new_plaintext.extend_from_slice(&suffix);

    pkcs7::pad_inplace(&mut new_plaintext, 16)?;

    // select to either encrypt ecb/cbc
    let ecb_encrypt: bool = rng.gen();

    // println!("ecb encryption: {}", ecb_encrypt);

    if ecb_encrypt {
        Ok((
            ecb::encrypt_128(&new_plaintext, &key)?,
            EncryptionType::Ecb128,
        ))
    } else {
        let iv: [u8; 16] = rng.gen();
        Ok((
            cbc::encrypt_128(&new_plaintext, &key, &iv)?,
            EncryptionType::Cbc128,
        ))
    }
}

/// ECB128 is stateless and deterministic. That is, the cipher will always be the same for a block
/// of 16 bytes. So, this test finds if there are any blocks that are identical to each other in a
/// text. If so, odds are it has been ECB 128 encrypted
pub fn is_data_ecb128_encrypted(data: &[u8]) -> bool {
    use std::collections::hash_set::HashSet;

    let set: HashSet<[u8; 16]> = data
        .par_chunks_exact(16)
        .map(|x| x.try_into().unwrap()) // we know the op will succeed
        .collect();
    let num_unique_blocks = set.len();

    let num_blocks = data.len() / 16;

    num_blocks - num_unique_blocks > 1
}

pub fn detect_encryption_mode(ciphertext: &[u8]) -> EncryptionType {
    match is_data_ecb128_encrypted(ciphertext) {
        true => EncryptionType::Ecb128,
        false => EncryptionType::Cbc128,
    }
}

/// prefix some plaintext with a single character. Encrypt. Continue, adding another instance of the character each time,
/// until Pkcs7 padding has increased the length of the ciphertext - the difference in the lengths of the two ciphers is
/// the block length
pub fn find_block_length(oracle: &impl Cipher) -> Result<usize> {
    let original_length = oracle.encrypt(&vec![b'a'; 0])?.len();

    let mut err = Ok(());
    let block_length = (0..0xff)
        .into_iter()
        .map(|i| oracle.encrypt(&vec![b'a'; i]))
        .scan(&mut err, until_err)
        .fold_while(0usize, |_, ciphertext| {
            if ciphertext.len() == original_length {
                Continue(0)
            } else {
                Done(ciphertext.len() - original_length)
            }
        })
        .into_inner();
    err?;
    Ok(block_length)
}

#[cfg(test)]
mod aes_tests {
    use super::*;
    use crate::{aes::*, base64, common::expectations::expect_eq};

    #[test]
    fn test_finding_block_length() {
        let unknown_text = base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();

        struct ConcattorEcbCipher {
            key: [u8; 16],
            unknown_text: Vec<u8>,
        }

        impl Cipher for ConcattorEcbCipher {
            fn encrypt(&self, plaintext: &[u8]) -> AesResult<Vec<u8>> {
                let mut concatted = plaintext.to_vec();
                concatted.extend_from_slice(&self.unknown_text);
                ecb::encrypt_128(&concatted, &self.key)
            }
            fn decrypt(&self, plaintext: &[u8]) -> AesResult<Vec<u8>> {
                ecb::decrypt_128(plaintext, &self.key)
            }
        }

        let oracle = ConcattorEcbCipher {
            key: generate_rnd_key(),
            unknown_text: unknown_text.to_vec(),
        };

        expect_eq(
            16,
            find_block_length(&oracle).unwrap(),
            "Finding block length",
        )
        .unwrap();
    }
}
