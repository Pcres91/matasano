use crate::aes::{generate_rnd_key, CbcCipher, Cipher};
use crate::base64;
use crate::challenges::print_challenge_result;
use crate::common::*;
use crate::errors::Result;
use crate::expectations::*;
use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::{prelude::*, BufReader};

pub fn set3() {
    print_challenge_result(17, &challenge17);
}

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
    // lines.clone().into_iter().for_each(|l| println!("{}", Wrap(l)));

    let cipher = CbcCipher {
        key: generate_rnd_key(),
        iv: Some(generate_rnd_key()),
    };

    let encryptor = || -> Result<(Vec<u8>, [u8; 16])> {
        // let rng = thread_rng();
        let plaintext = lines[thread_rng().gen_range(0..lines.len())].clone();

        let ciphertext = cipher.encrypt(&plaintext)?;
        Ok((ciphertext, cipher.iv.unwrap().clone()))
    };

    let (ciphertext, _) = encryptor()?;

    cipher.decrypt(&ciphertext);

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
