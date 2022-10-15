use crate::{
    aes::{
        ctr, ecb,
        util::{generate_rnd_key, Cipher},
    },
    base64,
    challenges::print_challenge_result,
    common::{bit_ops::xor_bytes, errors::Result, expectations::*, util::until_err},
    sha1::*,
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

pub fn set4() {
    // print_challenge_result(25, &challenge25);
    // print_challenge_result(26, &challenge28);
    print_challenge_result(29, &challenge29);
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

    let attacking_pt = vec![1u8; ciphertext.len()];

    let new_ct = cipher.edit(&ciphertext, 0, &attacking_pt)?;
    expect_eq(
        ciphertext.len(),
        new_ct.len(),
        "checking edit fn works as expected",
    )?;

    let keystream = xor_bytes(&attacking_pt, &new_ct)?;

    let discovered_plaintext = xor_bytes(&keystream, &ciphertext)?;

    expect_eq(plaintext, discovered_plaintext, "easiest attack of my life")?;

    Ok(())
}

pub fn challenge28() -> Result<()> {
    let secret_prefix_mac = &generate_key(32);

    let sender = Messenger::new(secret_prefix_mac);
    let receiver = Messenger::new(secret_prefix_mac);

    let my_message = b"hello how lovely to meet you I hope you are well regards me";

    let message = sender.send(my_message);

    expect_eq(
        AuthenticationResult::Successful,
        receiver.authenticate_with_prefix_mac(&message),
        "Typical send/receive",
    )?;

    let bad_actor = Messenger::new(&generate_key(32));

    let bad_actor_message = bad_actor.send(my_message);

    // Because the bad actor doesn't know the shared key between send and receiver,
    // they will never be able to produce a MAC that authenticates the message
    expect_eq(
        AuthenticationResult::Failed,
        receiver.authenticate_with_prefix_mac(&bad_actor_message),
        "Typical send/receive",
    )?;

    Ok(())
}

pub fn challenge29() -> Result<()> {
    let message = b"count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo";

    println!("\n\nmessage len: {}", message.len());

    let secret_key = generate_key(14);
    let client = Messenger::new(&secret_key);
    let receiver = Messenger::new(&secret_key);

    let cl_message = client.send(message);
    println!("receiver authenticating...");
    dbg!(&cl_message.mac);
    expect_eq(
        AuthenticationResult::Successful,
        receiver.authenticate_with_prefix_mac(&cl_message),
        "original message",
    )?;

    let attacker = Messenger::new(&generate_key(14));

    let mut new_message = message.to_vec();

    new_message.push(0x80);
    new_message.extend(vec![0u8; 26]);
    new_message.extend([0x02, 0x28]);
    new_message.extend(b"&waffle=liege");

    println!("len: {}", new_message.len());

    println!("attacker sending...");
    let bad_message = attacker.send(&new_message);
    dbg!(&bad_message.mac);
    // expect_eq(
    //     AuthenticationResult::Successful,
    //     receiver.authenticate_with_prefix_mac(&bad_message),
    //     "Attacker trying to pwn",
    // )?;

    Ok(())
}
