#[allow(unused_imports)]
use crate::{
    aes,
    aes::{
        pkcs7::{is_padding_valid_for, validate_and_remove_padding},
        util::{generate_rnd_key, Cipher},
        *,
    },
    base64,
    challenges::print_challenge_result,
    common::{
        bit_ops::{xor_bytes, xor_with_single_byte},
        errors::{AesError, Result},
        expectations::*,
        util::{find_best_character_key, get_slice, try_display, until_err, Wrap},
    },
    mt19937::*,
};
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use std::io::{prelude::*, BufReader};
use std::{convert::TryInto, slice::Iter};
use std::{fs::File, iter::Peekable};

pub fn set3() {
    print_challenge_result(17, &challenge17);
    print_challenge_result(18, &challenge18);
    print_challenge_result(19, &challenge19);
    print_challenge_result(20, &challenge20);
    print_challenge_result(21, &challenge21);
}

/// CBC padding oracle attack best explained here https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/
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

    struct PaddingOracle {
        key: [u8; aes::BLOCK_SIZE],
        iv: [u8; aes::BLOCK_SIZE],
    }

    let padding_oracle = PaddingOracle {
        key: generate_rnd_key(),
        iv: generate_rnd_key(),
    };

    let plaintext_real = lines[thread_rng().gen_range(0..lines.len())].clone();

    let encryptor = || -> Result<(Vec<u8>, [u8; aes::BLOCK_SIZE])> {
        let ciphertext =
            cbc::encrypt_128(&plaintext_real[..], &padding_oracle.key, &padding_oracle.iv)?;
        Ok((ciphertext, padding_oracle.iv.clone()))
    };

    let decryptor = |ciphertext_in: &[u8], iv_in: &[u8]| -> bool {
        let tmp = cbc::decrypt_128(
            &ciphertext_in,
            &padding_oracle.key,
            iv_in.try_into().unwrap(),
            true,
        )
        .unwrap();
        is_padding_valid_for(&tmp, aes::BLOCK_SIZE).unwrap()
    };

    let (ciphertext, _) = encryptor()?;

    let create_forcing_iv = |iv: &[u8; aes::BLOCK_SIZE],
                             candidate: u8,
                             padding_len: usize,
                             found_plaintext: &[u8]|
     -> Vec<u8> {
        let candidate_idx = iv.len() - padding_len;

        // decryption is XOR then decrypt_block. Perform the XOR now, so that our decrypt will
        // return the padding_len when the candidate == plaintext byte
        let mut forced_character = iv[candidate_idx] ^ candidate ^ padding_len as u8;

        let mut output = [&iv[..candidate_idx], &[forced_character][..]].concat();

        for k in aes::BLOCK_SIZE - padding_len + 1..aes::BLOCK_SIZE {
            forced_character = iv[k] ^ found_plaintext[k] ^ padding_len as u8;
            output.push(forced_character);
        }
        output
    };

    let candidate_is_the_plaintext_byte =
        |candidate_idx: usize, ct_block: &[u8], padding_iv: &mut [u8]| -> bool {
            if decryptor(ct_block.try_into().unwrap(), padding_iv) {
                // edge case: 2 possible cases when trying to find the final byte in the block:
                // 1) correct case [...,  0xN, 0x1],
                // 2) false positive [..., 0x2, 0x2]. In this case, our candidate did not return the padding
                //    we expect, and the whole thing will be off for the next candidate.
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

    let single_block_attack =
        |ct_block: &[u8; aes::BLOCK_SIZE], ct_prev_block: &[u8; aes::BLOCK_SIZE]| -> Vec<u8> {
            let mut decrypted = vec![0u8; 16];

            // CTR encryption: ENCRYPT -> XOR. decryption: DECRYPT -> XOR.
            // for the final byte in the block len, find a candidate byte that returns valid padding when run through the oracle.
            // This means that we have constructed a final IV byte that is identical to the plaintext byte!
            // Once done, the knowledge of that byte's real value allows us to construct a padding
            // that gets us the previous byte as the final padding value, etc etc
            (1..=aes::BLOCK_SIZE).for_each(|pad_val| {
                let candidate_idx = aes::BLOCK_SIZE - pad_val as usize;

                decrypted[candidate_idx] = (0..=0xffu8)
                    .par_bridge()
                    .map(|candidate| {
                        (
                            candidate,
                            create_forcing_iv(&ct_prev_block, candidate, pad_val, &decrypted),
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

    let ciphertext_blocks = [padding_oracle.iv.to_vec(), ciphertext].concat();
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

pub fn challenge19() -> Result<()> {
    let mut err = Ok(());
    let reader = BufReader::new(File::open("19.txt")?);
    let lines = reader
        .lines()
        .map(|line| base64::decode(line?.as_bytes()))
        .scan(&mut err, until_err)
        .collect::<Vec<Vec<u8>>>();
    err?;

    let cipher = ctr::CtrCipher {
        key: generate_rnd_key(),
        nonce: 0,
    };

    let encrypted_lines = lines
        .par_iter()
        .map(|line| cipher.encrypt(&line).unwrap())
        .collect::<Vec<Vec<u8>>>();
    expect_eq(40, encrypted_lines.len(), "no encryptions failed")?;

    // using a similar attack to ch6, we know that for each ciphertext, byte 0 for each ciphertext has been
    // encrypted against the same byte of the keystream. This allows us to score against a single byte for all, to find a
    // most reasonable byte.
    let mut iters = encrypted_lines
        .iter()
        .map(|line| line.iter().peekable())
        .collect::<Vec<Peekable<Iter<u8>>>>();

    let data_available = |iters: &mut Vec<Peekable<Iter<u8>>>| -> bool {
        iters.iter_mut().any(|it| it.peek() != None)
    };

    // take 1st byte of each vec and bunch, 2nd byte and bunch, etc
    let mut sliced_data: Vec<Vec<u8>> = Vec::new();
    while data_available(&mut iters) {
        sliced_data.push(
            iters
                .iter_mut()
                .filter_map(|it| it.next())
                .map(|c| *c)
                .collect(),
        );
    }

    let keystream = sliced_data
        .iter()
        .map(|v| find_best_character_key(&v))
        .collect::<Vec<u8>>();

    // https://www.poetryfoundation.org/poems/43289/easter-1916
    // Easter, by William Yeats
    let plaintext_lines = encrypted_lines
        .iter()
        .map(|v| {
            xor_bytes(v, &keystream[..v.len()]).unwrap()
            // these will actually never fail because we'll always try find a char key
            // it'll just have a couple funny characters towards the end of the longer lines
            // println!("{}", try_display(&res));
        })
        .collect::<Vec<Vec<u8>>>();

    expect_eq(
        "coming with vivid faces".as_bytes(),
        &plaintext_lines[1],
        "The second line is short enough that statistically we should get a perfect output",
    )?;

    Ok(())
}

/// identical to challenge 19
pub fn challenge20() -> Result<()> {
    let mut err = Ok(());
    let reader = BufReader::new(File::open("20.txt")?);
    let lines = reader
        .lines()
        .map(|line| base64::decode(line?.as_bytes()))
        .scan(&mut err, until_err)
        .collect::<Vec<Vec<u8>>>();
    err?;

    let cipher = ctr::CtrCipher {
        key: generate_rnd_key(),
        nonce: 0,
    };

    let encrypted_lines = lines
        .par_iter()
        .map(|line| cipher.encrypt(&line).unwrap())
        .collect::<Vec<Vec<u8>>>();
    expect_eq(60, encrypted_lines.len(), "no encryptions failed")?;

    // using a similar attack to ch6, we know that for each ciphertext, byte 0 for each ciphertext has been
    // encrypted against the same byte of the keystream. This allows us to score against a single byte for all, to find a
    // most reasonable byte.
    let mut iters = encrypted_lines
        .iter()
        .map(|line| line.iter().peekable())
        .collect::<Vec<Peekable<Iter<u8>>>>();

    let data_available = |iters: &mut Vec<Peekable<Iter<u8>>>| -> bool {
        iters.iter_mut().any(|it| it.peek() != None)
    };

    // take 1st byte of each vec and bunch, 2nd byte and bunch, etc
    let mut sliced_data: Vec<Vec<u8>> = Vec::new();
    while data_available(&mut iters) {
        sliced_data.push(
            iters
                .iter_mut()
                .filter_map(|it| it.next())
                .map(|c| *c)
                .collect(),
        );
    }

    let keystream = sliced_data
        .iter()
        .map(|v| find_best_character_key(&v))
        .collect::<Vec<u8>>();

    // https://www.poetryfoundation.org/poems/43289/easter-1916
    // Easter, by William Yeats
    let plaintext_lines = encrypted_lines
        .iter()
        .map(|v| {
            let res = xor_bytes(v, &keystream[..v.len()]).unwrap();
            // these will actually never fail because we'll always try find a char key
            // it'll just have a couple funny characters towards the end of the longer lines
            // println!("{}", try_display(&res));
            res
        })
        .collect::<Vec<Vec<u8>>>();

    let expected_10th_line =
        b"terror in the styles, never error-files / Indeed I'm known-your exiled!".to_vec();

    let num_chars_same = expected_10th_line
        .iter()
        .zip(plaintext_lines[10].iter())
        .filter(|(l, r)| l == r)
        .count();

    let pct_correct = num_chars_same as f32 / expected_10th_line.len() as f32;

    expect_true(
        pct_correct > 0.95,
        &format!(
            "The 11th line is short enough that statistically we should get >95% correct. Got {pct_correct}"
        ),
    )?;

    Ok(())
}

/// implement MS19937 Mersenne Twister
pub fn challenge21() -> Result<()> {
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
    fn test_challenge19() {
        challenge19().unwrap();
    }
    #[test]
    fn test_challenge20() {
        challenge20().unwrap();
    }
    #[test]
    fn test_challenge21() {
        challenge21().unwrap();
    }
}
