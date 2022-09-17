#[allow(unused_imports)]
use crate::{
    aes,
    aes::{
        pkcs7::*,
        util::{generate_rnd_key, Cipher},
        *,
    },
    base64,
    challenges::print_challenge_result,
    common::{
        bit_ops::xor_with_single_byte,
        errors::{AesError, Result},
        expectations::*,
        util::{until_err, Wrap},
    },
};
use crate::{
    aes::pkcs7::{is_padding_valid_for, validate_and_remove_padding},
    mt19937::*,
};
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use std::convert::TryInto;
use std::fs::File;
use std::io::{prelude::*, BufReader};

pub fn set3() {
    print_challenge_result(17, &challenge17);
    print_challenge_result(18, &challenge18);
    print_challenge_result(21, &challenge21);
}

/// CBC padding oracle best explained here https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
pub fn challenge17() -> Result<()> {
    let mut err = Ok(());
    let reader = BufReader::new(File::open("17.txt")?);

    let lines: Vec<Vec<u8>> = reader
        .lines()
        .map(|line| base64::decode(line?.as_bytes()))
        .scan(&mut err, until_err)
        .collect();
    err?;
    expect_eq(10, lines.len(), "10 messages in file")?;

    struct CbcOracleMutIv {
        key: [u8; aes::BLOCK_SIZE],
        iv: [u8; aes::BLOCK_SIZE],
    }

    let oracle = CbcOracleMutIv {
        // key: generate_rnd_key(),
        // iv: generate_rnd_key(),
        key: (0..aes::BLOCK_SIZE as u8)
            .into_iter()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
        iv: (aes::BLOCK_SIZE as u8..32u8)
            .into_iter()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
    };

    let plaintext_real = lines[thread_rng().gen_range(0..lines.len())].clone();

    let encryptor = || -> Result<(Vec<u8>, [u8; aes::BLOCK_SIZE])> {
        let ciphertext = cbc::encrypt_128(&plaintext_real[..], &oracle.key, &oracle.iv)?;
        Ok((ciphertext, oracle.iv.clone()))
    };

    let decryptor = |ciphertext_in: &[u8], iv_in: &[u8]| -> bool {
        let tmp =
            cbc::decrypt_128(&ciphertext_in, &oracle.key, iv_in.try_into().unwrap(), true).unwrap();
        is_padding_valid_for(&tmp, aes::BLOCK_SIZE).unwrap()
    };

    let (ciphertext, _) = encryptor()?;

    let create_forced_iv = |iv: &[u8; aes::BLOCK_SIZE],
                            guessed_byte: u8,
                            padding_len: usize,
                            found_plaintext: &[u8]|
     -> Vec<u8> {
        let index_of_forced_char = iv.len() - padding_len;

        let mut forced_character = iv[index_of_forced_char] ^ guessed_byte ^ padding_len as u8;

        let mut output = [&iv[..index_of_forced_char], &[forced_character][..]].concat();

        for k in aes::BLOCK_SIZE - padding_len + 1..aes::BLOCK_SIZE {
            forced_character = iv[k] ^ found_plaintext[k] ^ padding_len as u8;
            output.push(forced_character);
        }
        output
    };

    let candidate_is_the_plaintext_byte =
        |candidate_idx: usize, ct_block: &[u8], padding_iv: &mut [u8]| -> bool {
            if decryptor(ct_block.try_into().unwrap(), padding_iv) {
                if candidate_idx == aes::BLOCK_SIZE - 1 {
                    padding_iv[candidate_idx - 1] ^= 1;
                    if !decryptor(ct_block, &padding_iv) {
                        return false;
                    }
                }
                true
            } else {
                false
            }
        };

    // for each block, decrypt using the padded oracle attack
    let single_block_attack =
        |ct_block: &[u8; aes::BLOCK_SIZE], previous_block: &[u8; aes::BLOCK_SIZE]| -> Vec<u8> {
            let mut decrypted = vec![0u8; 16];

            (1..=aes::BLOCK_SIZE).for_each(|pad_val| {
                let candidate_idx = aes::BLOCK_SIZE - pad_val as usize;

                decrypted[candidate_idx] = (0..=0xffu8)
                    .par_bridge()
                    .map(|candidate| {
                        (
                            candidate,
                            create_forced_iv(&previous_block, candidate, pad_val, &decrypted),
                        )
                    })
                    .fold(
                        || 0u8,
                        |acc, (candidate, mut forced_iv)| {
                            acc + if candidate_is_the_plaintext_byte(
                                candidate_idx,
                                ct_block,
                                &mut forced_iv,
                            ) {
                                candidate
                            } else {
                                0
                            }
                        },
                    )
                    .sum::<u8>();
            });
            decrypted
        };

    let ciphertext_blocks = [oracle.iv.to_vec(), ciphertext].concat();
    let mut ct_iter = ciphertext_blocks.chunks_exact(aes::BLOCK_SIZE);
    ct_iter.next();

    let mut plaintext: Vec<u8> = ct_iter
        .zip(ciphertext_blocks.chunks_exact(aes::BLOCK_SIZE))
        .flat_map(|(block, prev_block)| {
            single_block_attack(block.try_into().unwrap(), prev_block.try_into().unwrap())
        })
        .collect();

    if is_padding_valid_for(&plaintext, aes::BLOCK_SIZE)? {
        plaintext = validate_and_remove_padding(&plaintext)?;
    }

    expect_eq(
        plaintext_real,
        plaintext,
        "Implementing padding oracle attack",
    )?;
    Ok(())
}

pub fn challenge18() -> Result<()> {
    let ciphertext = base64::decode(
        b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    )?;
    let expected = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";

    let cipher = ctr::CtrCipher {
        key: b"YELLOW SUBMARINE".to_owned(),
        nonce: 0,
    };

    let plaintext = cipher.decrypt(&ciphertext)?;

    expect_eq(expected.to_vec(), plaintext, "decrypting CTR")?;

    let pt2 = b"hello hi hi I'm so fly like a pie high in sky don't say why?";

    let cipher2 = ctr::CtrCipher {
        key: generate_rnd_key(),
        nonce: 0xaabbccddeeff0011,
    };

    let ct = cipher2.encrypt(pt2)?;
    expect_eq(
        pt2.to_vec(),
        cipher2.decrypt(&ct)?,
        "Own message CTR cipher",
    )?;

    Ok(())
}

/// implement MS19937 Mersenne Twister
fn challenge21() -> Result<()> {
    let mut gen32 = Mt19937::new();

    let reader32 = BufReader::new(File::open("21_32bit_test.txt").unwrap());

    let mut err = Ok(());

    reader32
        .lines()
        .map(|line| line.unwrap().parse::<u32>())
        .scan(&mut err, until_err)
        .enumerate()
        .try_for_each(|(i, expected)| {
            expect_eq(expected, gen32.next(), &format!("testing {i}th value"))
        })?;

    let mut gen_64 = Mt19937_64::new();

    let reader = BufReader::new(File::open("21_test.txt")?);

    reader
        .lines()
        .map(|line| line.unwrap().parse::<u64>())
        .scan(&mut err, until_err)
        .enumerate()
        .try_for_each(|(i, expected)| {
            expect_eq(expected, gen_64.next(), &format!("testing {i}th value"))
        })?;

    Ok(())
}

#[cfg(test)]
mod set3_tests {
    use super::*;
    #[test]
    fn test_challenge17() {
        challenge17().unwrap();
    }
    #[test]
    fn test_challenge18() {
        challenge18().unwrap();
    }
    #[test]
    fn test_challenge21() {
        challenge21().unwrap();
    }
}
