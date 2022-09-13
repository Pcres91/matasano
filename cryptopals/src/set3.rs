use crate::{
    aes::pkcs7::{is_padding_valid_for, validate_and_remove_padding},
    mt19937::*,
};
#[allow(unused_imports)]
use crate::{
    aes::{
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
use rand::{thread_rng, Rng};
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
        key: [u8; 16],
        iv: [u8; 16],
    }

    let oracle = CbcOracleMutIv {
        // key: generate_rnd_key(),
        // iv: generate_rnd_key(),
        key: (0..16u8)
            .into_iter()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
        iv: (16..32u8)
            .into_iter()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap(),
    };

    let plaintext_real = lines[thread_rng().gen_range(0..lines.len())].clone();

    let encryptor = || -> Result<(Vec<u8>, [u8; 16])> {
        let ciphertext = cbc::encrypt_128(&plaintext_real[0..16], &oracle.key, &oracle.iv)?;
        Ok((ciphertext, oracle.iv.clone()))
    };

    let decryptor = |ciphertext_in: &[u8], iv_in: &[u8; 16]| -> (bool, Vec<u8>) {
        let tmp = cbc::decrypt_128(&ciphertext_in, &oracle.key, iv_in, true).unwrap();
        match is_padding_valid_for(&tmp, 16).unwrap() {
            true => (true, validate_and_remove_padding(&tmp).unwrap()),
            false => (false, tmp),
        }
    };

    let (ciphertext, _) = encryptor()?;

    // for each block, decrypt using the padded block cipher
    let single_block_attack = |block: &[u8; 16], previous_block: &[u8; 16]| -> Result<Vec<u8>> {
        let mut zeroing_iv = previous_block.clone();

        for pad_val in 1..=16 {
            let mut padding_iv: [u8; 16] = xor_with_single_byte(block, pad_val).try_into().unwrap();

            for candidate in 0..=0xffu8 {
                // print!("j: {:3} ", candidate);
                padding_iv[padding_iv.len() - pad_val as usize] = candidate;

                if decryptor(block, &padding_iv).0 {
                    if pad_val == 1 {
                        padding_iv[padding_iv.len() - pad_val as usize - 1] ^= 1;
                        if !decryptor(block, &padding_iv).0 {
                            println!("false positive, continuing...");
                            continue;
                        }
                    }

                    zeroing_iv[padding_iv.len() - pad_val as usize] = candidate ^ pad_val;
                    break;
                } else if candidate == 0xffu8 {
                    return Err(AesError::Cbc128Error(
                        "Unable to find a suitable candidate".into(),
                    )
                    .into());
                }
            }
        }

        Ok(zeroing_iv.to_vec())
    };

    // let block: &[u8; 16] = &ciphertext[ciphertext.len() - 16..].try_into().unwrap();
    // let plaintext_block = single_block_attack(block, &oracle.iv)?;

    let plaintext: Vec<u8> = ciphertext
        .chunks_exact(16)
        .rev()
        .flat_map(|block| single_block_attack(&block.try_into().unwrap(), &oracle.iv))
        .flatten()
        .collect();

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
    let mut gen_64 = Mt19937_64::new();

    let reader = BufReader::new(File::open("21_test.txt")?);

    let mut err = Ok(());

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
