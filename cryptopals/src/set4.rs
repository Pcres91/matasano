use itertools::{Itertools, FoldWhile};

use crate::{
    aes::{
        self, ctr, ecb,
        util::{generate_rnd_key, Cipher},
    },
    base64,
    challenges::print_challenge_result,
    common::{
        errors::Result,
        util::{until_err, Wrap}, expectations::expect_eq, bit_ops::xor_bytes,
    },
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

pub fn set4() {
    print_challenge_result(25, &challenge25);
}

/// Break "random access read/write" AES CTR
pub fn challenge25() -> Result<()> {
    let mut err = Ok(());
    let reader = BufReader::new(File::open("25.txt")?);
    let lines = reader
        .lines()
        .map(|line| base64::decode(line?.as_bytes()))
        .scan(&mut err, until_err)
        .flatten()
        .collect::<Vec<u8>>();
    err?;
    let plaintext = ecb::decrypt_128(&lines, b"YELLOW SUBMARINE")?;

    let cipher = ctr::CtrCipher {
        key: generate_rnd_key(),
        nonce: 0,
    };

    let ciphertext = cipher.encrypt(&plaintext)?;
    
    let attacking_pt = vec![1u8;ciphertext.len()];

    let new_ct = cipher.edit(&ciphertext, 0, &attacking_pt)?;
    expect_eq(ciphertext.len(), new_ct.len(), "checking edit fn works as expected")?;

    let keystream = xor_bytes(&attacking_pt, &new_ct)?;

    let discovered_plaintext = xor_bytes(&keystream, &ciphertext)?;

    expect_eq(plaintext, discovered_plaintext, "easiest attack of my life")?;

    Ok(())
}
