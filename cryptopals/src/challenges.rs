use crate::aes;
use crate::base64;
use crate::common;
use crate::user_storage;
use common::Wrap;
use std::io::Error;

pub fn set1() -> Result<(), Error> {
    challenge1();
    challenge2();
    challenge3();
    challenge4()?;
    challenge5();
    challenge6()?;
    challenge7()?;
    challenge8()?;

    Ok(())
}

pub fn set2() -> Result<(), Error> {
    challenge9()?;
    challenge10()?;
    challenge11()?;
    challenge12()?;
    challenge13()?;

    Ok(())
}

fn print_challenge_result(challenge_num: u32, success: bool, message: Option<&str>) {
    let mut msg = String::new();
    if let Some(m) = message {
        msg = ": ".to_string() + m
    }

    if success {
        println!("SUCCESSFUL: Challenge {}{}", challenge_num, msg)
    } else {
        println!("FAILED: Challenge {}", challenge_num)
    }
}

pub fn challenge1() {
    use common::hex_decode_bytes;
    let n = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes = hex_decode_bytes(n); // vec![0x49, 0x27, 0x6d, 0x20, ...]

    let encoded = base64::pretty_print(&bytes);

    let expected_result =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();

    print_challenge_result(1, encoded == expected_result, None)
}

pub fn challenge2() {
    use common::{hex_decode_bytes, xor_bytes};
    let a = hex_decode_bytes(b"1c0111001f010100061a024b53535009181c");

    let b = hex_decode_bytes(b"686974207468652062756c6c277320657965");

    let result = xor_bytes(&a, &b);

    let expected_result = hex_decode_bytes(b"746865206b696420646f6e277420706c6179");

    print_challenge_result(2, result == expected_result, None);
}

pub fn challenge3() {
    use common::{find_single_char_key, hex_decode_bytes, single_byte_xor};
    let expected_result = "Cooking MC's like a pound of bacon";
    let cipher =
        hex_decode_bytes(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    // let expected_result = "I'm killing your brain like a poisonous mushroom".to_string();
    // let cipher = hex_decode_bytes(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec());

    let key = find_single_char_key(&cipher);

    let result = Wrap(single_byte_xor(&cipher, key)).to_string();

    print_challenge_result(3, result == expected_result, None);
}

pub fn challenge4() -> Result<(), Error> {
    use common::{
        find_single_char_key, get_common_letter_frequencies, hex_decode_string, single_byte_xor,
    };
    use std::fs::File;
    use std::io::{prelude::*, BufReader};

    let file = File::open("4.txt").unwrap();
    let reader = BufReader::new(file);

    let mut found_message: (i32, u8, Vec<u8>, usize) = (0, 0, vec![], 0);
    for (line_num, line) in reader.lines().enumerate() {
        let bytes = hex_decode_string(&line?);
        let key = find_single_char_key(&bytes);
        let msg = single_byte_xor(&bytes, key);
        let freq_count = get_common_letter_frequencies(&msg);
        if freq_count > found_message.0 {
            found_message = (freq_count, key, msg, line_num);
        }
    }

    let result = format!("line {}: {}", found_message.3, &Wrap(found_message.2));
    print_challenge_result(4, true, Some(&result));

    Ok(())
}

pub fn challenge5() {
    let plain_text = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    use common::repeated_xor;
    let cipher = repeated_xor(plain_text, key);

    use common::hex_decode_bytes;
    let expected_result = hex_decode_bytes(b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

    print_challenge_result(5, cipher == expected_result, None);
}

pub fn challenge6() -> Result<(), Error> {
    use common::{find_key_size, find_single_char_key, slice_by_byte};

    let cipher = base64::read_encoded_file("6.txt")?;

    let key_size = find_key_size(&cipher, (2, 40), 20)?;

    let sliced_data = slice_by_byte(&cipher, key_size);

    let key: Vec<u8> = sliced_data
        .iter()
        .map(|x| find_single_char_key(x))
        .collect();

    let _result = Wrap(common::repeated_xor(&cipher, &key)).to_string();
    print_challenge_result(6, true, Some(&Wrap(key).to_string()));

    Ok(())
}

pub fn challenge7() -> Result<(), Error> {
    let cipher = base64::read_encoded_file("7.txt").unwrap();

    let key = b"YELLOW SUBMARINE";

    let _plain_text = aes::decrypt_ecb_128(&cipher, key)?;

    // println!("{}", Wrap(_plain_text));

    print_challenge_result(7, true, Some("Implementing aes-ecb-128"));
    Ok(())
}

pub fn challenge8() -> Result<(), Error> {
    use std::fs::File;
    use std::io::{prelude::*, BufReader};

    let file = File::open("8.txt").unwrap();
    let reader = BufReader::new(file);

    let mut lines_in_ecb_mode: Vec<usize> = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let cipher_text = common::hex_decode_string(&line?);

        let ecb_mode = aes::detect_cipher_in_ecb_128_mode(&cipher_text);

        if ecb_mode {
            lines_in_ecb_mode.push(line_num);
        }
    }

    print_challenge_result(
        8,
        !lines_in_ecb_mode.is_empty(),
        Some("detecting aes-ecb-128"),
    );

    Ok(())
}

pub fn challenge9() -> Result<(), Error> {
    let mut msg = b"YELLO".to_vec();
    let key_len = 16;

    aes::pkcs7_pad(&mut msg, key_len)?;

    // println!("{:2x?}", msg);
    print_challenge_result(9, true, Some("Implementing pkcs#7 padding"));
    Ok(())
}

pub fn challenge10() -> Result<(), Error> {
    let cipher_text = base64::read_encoded_file("10.txt")?;
    let key = b"YELLOW SUBMARINE";

    let plain_text = aes::decrypt_cbc_128(&cipher_text, key)?;

    // println!("{}", Wrap(plain_text));

    let cipher_again = aes::encrypt_cbc_128(&plain_text, key)?;

    print_challenge_result(
        10,
        cipher_text == cipher_again,
        Some("Implementing aes-cbc-128"),
    );

    Ok(())
}

pub fn challenge11() -> Result<(), Error> {
    let num_tests = 1000;
    let mut successful_detections = 0;
    for _ in 0..num_tests {
        if aes::decryption_oracle(&aes::rnd_encryption_oracle)? {
            successful_detections += 1;
        }
    }

    print_challenge_result(
        11,
        num_tests == successful_detections,
        Some("Detecting aes-ecb-128 with pkcs padding and random data"),
    );

    Ok(())
}

pub fn challenge12() -> Result<(), Error> {
    let unknown_text = base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")?;

    let oracle = aes::Oracle {
        key: aes::generate_key(),
        encryptor: Box::new(aes::encrypt_ecb_128),
    };
    let _plain_text = aes::break_ecb_128_ciphertext(&unknown_text, &oracle)?;
    println!("{}", Wrap(_plain_text));
    print_challenge_result(12, true, Some("Breaking  aes-ecb-128 message"));
    Ok(())
}

pub fn challenge13() -> Result<(), Error> {
    use user_storage::*;

    unsafe {
        // explanation:
        // payload ensures there are 4 distinct blocks to build after ciphered
        // 1) user=......
        // 2) <email contd>
        // 3) Admin with pkcs7 padding to mimic end of message
        // 4) <last four chars of email>&uid=0&role=
        // note: 4 must end on "role=" so Admin block can be stitched to the end of it

        // another note: unsure how to possibly deal with variably-sized uid. Just send through
        // text with different padding accounting for its length until one hits I suppose. Would
        // only be a few so I don't think it's an unreasonable way to hit a successful payload.
        let mut payload = b"foo0123456789@bar123456789Admin".to_vec();
        payload.extend_from_slice(&[11u8; 11]); // need the rest of block after admin to look like pkcs7 padding
        payload.extend_from_slice(b".com"); // need to place "&uid=0&role=" at the end of a block, so extend email

        use std::str::from_utf8;
        let cipher_text = profile_for(from_utf8(&payload).unwrap())?;

        // for i in 0..cipher_text.len() / 16 {
        //     println!(
        //         "{}||",
        //         Wrap(aes::decrypt_ecb_128(
        //             &cipher_text[i * 16..i * 16 + 16],
        //             &RND_KEY
        //         )?)
        //     );
        // }
        let mut payload_cipher = cipher_text[..32].to_vec();
        payload_cipher.extend_from_slice(&cipher_text[48..64]);
        payload_cipher.extend_from_slice(&cipher_text[32..48]);
        PROFILE_STORAGE.add_from_hash(&payload_cipher)?;

        print_challenge_result(
            13,
            PROFILE_STORAGE.profiles.len() == 1,
            Some("Sent payload without knowing key"),
        );
    }

    Ok(())
}

pub fn challenge14() -> Result<(), Error> {
    let string_to_find = b"Let's see if we can decipher this";

    let encrypt_with_rnd_prefix = |plain_text: &[u8], key: &[u8]| -> Result<Vec<u8>, Error> {
        use common::prefix_with_rnd_bytes;
        let rnd_bytes_range = (0, 50);
        let text = prefix_with_rnd_bytes(rnd_bytes_range, &plain_text);
        aes::encrypt_ecb_128(&text, &key)
    };

    let oracle = aes::Oracle {
        key: aes::generate_key(),
        encryptor: Box::new(encrypt_with_rnd_prefix),
    };

    let padding_cipher_block = aes::find_ecb_128_padded_block_cipher(&oracle)?;

    let mut found_text_length = false;
    let mut text_length = 0;

    let mut num_pad = 0usize;
    while !found_text_length {
        let mut padding = vec![16u8; 16];
        padding.extend_from_slice(&vec![b'A'; num_pad]);
        padding.extend_from_slice(&string_to_find[..]);
        let cipher = oracle.encrypt(&padding)?;

        if cipher[cipher.len() - 16..cipher.len()] == padding_cipher_block[..] {
            for i in 0..cipher.len() / 16 - 1 {
                let idx = i * 16;
                if &cipher[idx..idx + 16] == &padding_cipher_block[..] {
                    found_text_length = true;
                    text_length = cipher.len() - (idx + 16 + num_pad) - 16;
                    println!("text length: {}", text_length);
                }
            }
            num_pad += 1;
        }
    }

    let mut found_chars: Vec<u8> = Vec::new();

    // this doesn't work: padding length can't be guaranteed of course XD
    // need to get cipher with my known padding, find my input block, then the next
    // block must be the payload with which we decrypt.
    while found_chars.len() != 16 {
        let mut payload = vec![16u8; 16];

        let num_known_bytes = 15 - found_chars.len();
        payload.extend_from_slice(&vec![b'A'; num_known_bytes]);
        // payload.extend_from_slice(&found_chars);

        payload.extend_from_slice(&string_to_find[..]);
        println!("{}", Wrap(payload[16..32].to_vec()));

        let cipher = oracle.encrypt(&payload)?;

        for i in 0..cipher.len() / 16 - 1 {
            let idx = i * 16;

            if cipher[idx..idx + 16] == padding_cipher_block[..] {
                println!("{}", payload.len());
                let mut input_block: Vec<u8> = payload[16..31].to_vec();
                println!("{}", input_block.len());
                input_block.push(b'A');
                println!("{}", Wrap(input_block.to_vec()));
                println!(
                    "{}",
                    Wrap(aes::decrypt_ecb_128(
                        &cipher[idx + 16..idx + 32].to_vec(),
                        &oracle.key
                    )?)
                );
                for i in aes::SMART_ASCII.iter() {
                    input_block[15] = *i;
                    let new_output = aes::encrypt_ecb_128(&input_block, &oracle.key)?;
                    if new_output[..16] == cipher[idx + 16..idx + 32] {
                        println!("{}", *i);
                        found_chars.push(*i);
                    }
                }
            }
        }
    }
    Ok(())
}
