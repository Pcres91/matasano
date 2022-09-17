use crate::{aes, common::bit_ops::xor_bytes};

use super::{
    aes128::{encrypt_block, expand_key},
    util::{Cipher, Result},
};

pub struct CtrCipher {
    pub key: [u8; aes::BLOCK_SIZE],
    /// also known as iv
    pub nonce: u64,
}

impl Cipher for CtrCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // let iv = [self.nonce.to_le_bytes(), self.counter.to_le_bytes()].concat();
        encrypt_128(plaintext, &self.key, self.nonce)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        encrypt_128(ciphertext, &self.key, self.nonce)
    }
}

/// Encrypt and Decrypt for CTR is identical
pub fn encrypt_128(data: &[u8], key: &[u8; aes::BLOCK_SIZE], nonce: u64) -> Result<Vec<u8>> {
    let expanded_key = expand_key(key)?;

    // not bothered about exact length, just need more than total num blocks
    let counter = (0..data.len() as u64)
        .map(|counter| [nonce.to_le_bytes(), counter.to_le_bytes()].concat())
        .map(|iv| encrypt_block(&iv, &expanded_key).unwrap())
        .into_iter();

    Ok((data)
        .chunks(aes::BLOCK_SIZE)
        .zip(counter) // counter production
        .flat_map(|(pt, keyblock)| xor_bytes(pt, &keyblock[0..pt.len()]).unwrap())
        .collect())
}
