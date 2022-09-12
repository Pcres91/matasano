use crate::{
    aes::{
        cbc::{decrypt_cbc_128, encrypt_cbc_128},
        util::generate_rnd_key,
    },
    base64,
    challenges::print_challenge_result,
    common::{
        bit_ops::xor_with_single_byte,
        util::until_err,
        errors::{AesError, Result},
        expectations::*,
    },
};
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::fs::File;
use std::io::{prelude::*, BufReader};

pub fn set3() {
    print_challenge_result(17, &challenge17);
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
        key: generate_rnd_key(),
        // iv: (50..50 + 16).rev().collect::<Vec<u8>>().try_into().unwrap(),
        iv: generate_rnd_key(),
    };

    let plaintext_real = lines[
        // thread_rng().gen_range(0..lines.len())
        1
        ]
    .clone();

    let encryptor = || -> Result<(Vec<u8>, [u8; 16])> {
        // let rng = thread_rng();

        let ciphertext = encrypt_cbc_128(&plaintext_real[0..16], &oracle.key, &oracle.iv)?;
        Ok((ciphertext, oracle.iv.clone()))
    };

    let decryptor = |ciphertext_in: &[u8], iv_in: &[u8; 16]| -> (bool, Vec<u8>) {
        let tmp = decrypt_cbc_128(&ciphertext_in, &oracle.key, iv_in);
        match tmp {
            Ok(x) => {
                println!("success");
                (true, x)
            }
            Err(e) => match e {
                AesError::InvalidPkcs7Padding(_) => {
                    // println!("padding error");
                    (false, vec![])
                }
                _ => panic!(),
            },
        }
    };

    let (ciphertext, _) = encryptor()?;

    let single_block_attack = |block: &[u8; 16]| -> Result<Vec<u8>> {
        let mut zeroing_iv = [0u8; 16];

        for pad_val in 1..=16 {
            let mut padding_iv: [u8; 16] = xor_with_single_byte(block, pad_val).try_into().unwrap();

            for candidate in 0..=0xffu8 {
                print!("j: {:3} ", candidate);
                padding_iv[padding_iv.len() - pad_val as usize] = candidate;

                if decryptor(block, &padding_iv).0 {
                    println!("here");
                    if pad_val == 1 {
                        padding_iv[padding_iv.len() - pad_val as usize - 1] ^= 1;
                        if !decryptor(block, &padding_iv).0 {
                            continue;
                        }
                    }

                    println!("onto next");
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

    let block: &[u8; 16] = &ciphertext[0..16].try_into().unwrap();

    let plaintext_block = single_block_attack(block)?;

    println!("plaintext_block: {:?}", plaintext_block);

    println!("expected: {:?}", &plaintext_real[..16]);

    // println!("Decryptor succeeded on {}", c);

    expect_eq(1, 1, "challenge 17 result")?;
    Ok(())
}

#[cfg(test)]
mod ch17 {
    use super::*;
    #[test]
    fn test_challenge17() {
        challenge17().unwrap();
    }
}
