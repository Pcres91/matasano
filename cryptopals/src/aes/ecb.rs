use crate::{
    aes,
    aes::{
        pkcs7::{pad, validate_and_remove_padding},
        util::{Cipher, Result},
        *,
    },
    common::errors::AesError,
};

pub struct EcbCipher {
    pub key: [u8; aes::BLOCK_SIZE],
}

impl Cipher for EcbCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt_128(plaintext, &self.key)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_128(ciphertext, &self.key)
    }
}

pub fn encrypt_128(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let expanded_key = aes128::expand_key(key)?;

    let block_byte_length = aes::BLOCK_SIZE;

    let blocks = pad(plaintext, block_byte_length)?;

    Ok((blocks)
        .chunks_exact(aes::BLOCK_SIZE)
        .flat_map(|block| aes128::encrypt_block(block, &expanded_key))
        .flatten()
        .collect())
}

pub fn decrypt_128(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() % aes::BLOCK_SIZE != 0 {
        return Err(AesError::CipherTextLengthError);
    }

    if key.len() != aes::BLOCK_SIZE {
        return Err(AesError::KeyLengthError);
    }

    let expanded_key = aes128::expand_key(key)?;

    let mut blocks: Vec<u8> = ciphertext.to_vec();
    for idx in (0..blocks.len()).step_by(aes::BLOCK_SIZE) {
        aes128::decrypt_block_inplace(&mut blocks[idx..idx + aes::BLOCK_SIZE], &expanded_key)?;
    }

    validate_and_remove_padding(&blocks)
}

pub fn find_ecb_128_padded_block_cipher(oracle: &impl Cipher) -> Result<Vec<u8>> {
    let padding = vec![aes::BLOCK_SIZE as u8; 32 + 15];

    let ciphertext = oracle.encrypt(&padding)?;

    let mut prev_block = &ciphertext[0..aes::BLOCK_SIZE];
    for idx in (aes::BLOCK_SIZE..ciphertext.len()).step_by(aes::BLOCK_SIZE) {
        if prev_block == &ciphertext[idx..idx + aes::BLOCK_SIZE] {
            return Ok(prev_block.to_vec());
        }

        prev_block = &ciphertext[idx..idx + aes::BLOCK_SIZE];
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

        let ciphertext = encrypt_128(plaintext, &KNOWN_KEY).unwrap();

        let decrypted = decrypt_128(&ciphertext, &KNOWN_KEY).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
