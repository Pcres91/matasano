use crate::{
    aes::{
        aes128::{decrypt_block_128, encrypt_block_128, expand_key},
        util::{Cipher, Result},
        pkcs7::{get_pkcs7_padding_for, validate_and_remove_pkcs7_padding},
    },
    common::{bit_ops::xor_16_bytes, expectations::expect_true},
};

pub struct CbcCipher {
    pub key: [u8; 16],
    pub iv: Option<[u8; 16]>,
}

impl Cipher for CbcCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self.iv {
            Some(x) => encrypt_cbc_128(plaintext, &self.key, &x),
            None => encrypt_cbc_128_zero_iv(plaintext, &self.key),
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self.iv {
            Some(x) => decrypt_cbc_128(ciphertext, &self.key, &x),
            None => decrypt_cbc_128_zero_iv(ciphertext, &self.key),
        }
    }
}

pub fn encrypt_cbc_128_zero_iv(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let iv = vec![0u8; 16];
    encrypt_cbc_128(plaintext, key, &iv)
}

pub fn encrypt_cbc_128(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let expanded_key = expand_key(key)?;

    let padding = get_pkcs7_padding_for(plaintext, 16)?;

    let plaintext_blocks = [plaintext, &padding].concat();

    expect_true(
        plaintext_blocks.len() % 16 == 0,
        format!(
            "plaintext must be composed of 16 byte blocks, got length {}",
            plaintext_blocks.len()
        )
        .as_str(),
    )?;

    let mut ciphertext = vec![0u8; 0];

    // for each plaintext block...
    for idx in (0..plaintext_blocks.len()).step_by(16) {
        // XOR with previous block...
        let block = if idx == 0 {
            xor_16_bytes(&plaintext_blocks[idx..idx + 16], &iv)
        } else {
            xor_16_bytes(&plaintext_blocks[idx..idx + 16], &ciphertext[idx - 16..idx])
        };
        // and encrypt the block
        ciphertext.extend_from_slice(&encrypt_block_128(&block, &expanded_key)?);
    }
    Ok(ciphertext)
}

pub fn decrypt_cbc_128_zero_iv(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let iv = [0u8; 16];
    decrypt_cbc_128(ciphertext, key, &iv)
}

pub fn decrypt_cbc_128(ciphertext: &[u8], key: &[u8], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let expanded_key = expand_key(key)?;

    let mut plaintext = vec![0u8; 0];

    // for each block...
    for idx in (0..ciphertext.len()).step_by(16) {
        // decrypt the block...
        let block = decrypt_block_128(&ciphertext[idx..idx + 16], &expanded_key)?;

        // XOR with previous block...
        plaintext.extend(if idx == 0 {
            xor_16_bytes(&block, iv).to_vec()
        } else {
            xor_16_bytes(&block, &ciphertext[idx - 16..idx]).to_vec()
        })
    }

    // and remove the padding
    plaintext = validate_and_remove_pkcs7_padding(&plaintext)?;

    Ok(plaintext)
}

#[cfg(test)]
pub mod cbc_tests {
    use super::*;
    use crate::aes::util::KNOWN_KEY;
    use crate::common::expectations::expect_eq;

    #[test]
    fn test_cbc_128_encryption() {
        let plaintext = b"Hello World!";

        let ciphertext = encrypt_cbc_128_zero_iv(plaintext, &KNOWN_KEY).unwrap();

        let decrypted = decrypt_cbc_128_zero_iv(&ciphertext, &KNOWN_KEY).unwrap();

        assert_eq!(
            String::from_utf8(plaintext.to_vec()),
            String::from_utf8(decrypted)
        );
    }

    #[test]
    fn test_cbc_against_known_values() {
        // values taken from https://docs.rs/cbc/latest/cbc/#
        use hex_literal::hex;
        let key = [0x42; 16];
        let iv = [0x24; 16];
        let plaintext_expected = *b"hello world! this is my plaintext.";
        let ciphertext_expected = hex!(
            "c7fe247ef97b21f07cbdd26cb5d346bf"
            "d27867cb00d9486723e159978fb9a5f9"
            "14cfb228a710de4171e396e7b6cf859e"
        );

        let ciphertext = encrypt_cbc_128(&plaintext_expected, &key, &iv).unwrap();
        expect_eq(
            ciphertext_expected.len(),
            ciphertext.len(),
            "ciphertext length",
        )
        .unwrap();

        for idx in 0..ciphertext.len() {
            if ciphertext_expected[idx] != ciphertext[idx] {
                println!(
                    "Failure at idx {}.\nexpected: {:?}\ngot: {:?}",
                    idx,
                    &ciphertext_expected[idx..],
                    &ciphertext[idx..]
                );
                assert!(false);
            }
        }

        let plaintext = decrypt_cbc_128(&ciphertext, &key, &iv).unwrap();
        expect_eq(&plaintext_expected[..], &plaintext, "decrypting").unwrap();
    }
}
