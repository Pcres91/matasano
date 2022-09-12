use std::convert::TryInto;

use crate::{
    aes::{
        aes128::{decrypt_block_128_inplace, encrypt_block_128, expand_key},
        pkcs7::{pkcs7_pad, validate_and_remove_pkcs7_padding},
        util::{Cipher, Result},
    },
    common::errors::AesError,
};
use rayon::prelude::*;

pub struct EcbCipher {
    pub key: [u8; 16],
}

impl Cipher for EcbCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt_ecb_128(plaintext, &self.key)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_ecb_128(ciphertext, &self.key)
    }
}

pub fn encrypt_ecb_128(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let expanded_key = expand_key(key)?;

    let block_byte_length = 16usize;

    let blocks = pkcs7_pad(plaintext, block_byte_length)?;

    Ok((blocks)
        .chunks_exact(16)
        .flat_map(|block| encrypt_block_128(block, &expanded_key))
        .flatten()
        .collect())
}

pub fn decrypt_ecb_128(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() % 16 != 0 {
        return Err(AesError::CipherTextLengthError);
    }

    if key.len() != 16 {
        return Err(AesError::KeyLengthError);
    }

    let expanded_key = expand_key(key)?;

    let mut blocks: Vec<u8> = ciphertext.to_vec();
    for idx in (0..blocks.len()).step_by(16) {
        decrypt_block_128_inplace(&mut blocks[idx..idx + 16], &expanded_key)?;
    }

    validate_and_remove_pkcs7_padding(&blocks)
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

pub fn find_ecb_128_padded_block_cipher(oracle: &impl Cipher) -> Result<Vec<u8>> {
    let padding = vec![16u8; 32 + 15];

    let ciphertext = oracle.encrypt(&padding)?;

    let mut prev_block = &ciphertext[0..16];
    for idx in (16..ciphertext.len()).step_by(16) {
        if prev_block == &ciphertext[idx..idx + 16] {
            return Ok(prev_block.to_vec());
        }

        prev_block = &ciphertext[idx..idx + 16];
    }

    Err(AesError::Ecb128Error(format!(
        "Could not find padding ciphertext"
    )))
}

#[cfg(test)]
pub mod ecb_tests {
    use super::*;
    use crate::aes::util::KNOWN_KEY;

    #[test]
    fn test_ecb_128_encryption() {
        let plaintext = b"hello world";

        let ciphertext = encrypt_ecb_128(plaintext, &KNOWN_KEY).unwrap();

        let decrypted = decrypt_ecb_128(&ciphertext, &KNOWN_KEY).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
