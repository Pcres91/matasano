use super::{
    aes128::{encrypt_block, expand_key},
    util::{Cipher, Result},
};
use crate::{
    aes,
    common::{bit_ops::xor_bytes, expectations::expect_true, util::Wrap},
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

impl CtrCipher {
    /// seek to the offset in ciphertext, decrypt, and replace the plaintext there with
    /// new_text. Returns the ciphertext
    pub fn edit(&self, ciphertext: &[u8], offset: usize, new_text: &[u8]) -> Result<Vec<u8>> {
        expect_true(
            ciphertext.len() - 1 > offset,
            &format!(
                "offset ({offset}) is past ciphertext length ({}).",
                ciphertext.len()
            ),
        )?;
        expect_true(
            new_text.len() + offset <= ciphertext.len(),
            &format!(
                "not enough space for the new text ({}), offset {offset}, total length ({})",
                new_text.len(),
                ciphertext.len()
            ),
        )?;

        let mut plaintext = self.decrypt(&ciphertext)?;

        println!("{}", Wrap(plaintext.clone()));

        plaintext.splice(offset..offset + new_text.len(), new_text.iter().map(|c| *c));

        println!("{}", Wrap(plaintext.clone()));

        self.encrypt(&plaintext)
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
