use crate::aes;
use crate::base64;
use crate::common;
use crate::user_storage;
use common::Wrap;
use crate::expectations::*;

pub fn set1() {
    print_challenge_result(1, &challenge1);
    print_challenge_result(2, &challenge2);
    print_challenge_result(3, &challenge3);
    print_challenge_result(4, &challenge4);
    print_challenge_result(5, &challenge5);
    print_challenge_result(6, &challenge6);
    print_challenge_result(7, &challenge7);
    print_challenge_result(8, &challenge8);
}

pub fn set2() {
    print_challenge_result(9, &challenge9);
    print_challenge_result(10, &challenge10);
    print_challenge_result(11, &challenge11);
    print_challenge_result(12, &challenge12);
    print_challenge_result(13, &challenge13);
    print_challenge_result(14, &challenge14);
    print_challenge_result(15, &challenge15);
    print_challenge_result(16, &challenge16);
}

fn print_challenge_result(challenge_number: i32, challenge: &dyn Fn() -> Result<()>) {

    match challenge() {
        Ok(_) => println!("SUCCESSFUL: Challenge {challenge_number}"),
        Err(error) => {
            println!("FAILED:     Challenge {challenge_number}, {error}");
        },
    }
}

pub fn challenge1() -> Result<()> {
    use common::hex_decode_bytes;

    let hex_values_as_string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let exp_encoding =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();

    let bytes = hex_decode_bytes(hex_values_as_string)?;

    let encoded = base64::pretty_print(&bytes)?;

    expect_eq(exp_encoding, encoded)
}

pub fn challenge2() -> Result<()> {
    use common::{hex_decode_bytes, xor_bytes};

    let a = hex_decode_bytes(b"1c0111001f010100061a024b53535009181c")?;
    let b = hex_decode_bytes(b"686974207468652062756c6c277320657965")?;

    let result = xor_bytes(&a, &b)?;

    let expected_result = hex_decode_bytes(b"746865206b696420646f6e277420706c6179")?;

    expect_eq(expected_result, result)
}

pub fn challenge3() -> Result<()> {
    use common::{find_single_char_key, hex_decode_bytes, single_byte_xor};

    let expected_result = "Cooking MC's like a pound of bacon";
    let cipher =
        hex_decode_bytes(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;

    // let expected_result = "I'm killing your brain like a poisonous mushroom".to_string();
    // let cipher = hex_decode_bytes(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec());

    let key = find_single_char_key(&cipher);

    let tmp = single_byte_xor(&cipher, key);
    let result = std::str::from_utf8(&tmp)?;

    expect_eq(expected_result, result)
}

pub fn challenge4() -> Result<()> {
    use common::{
        find_single_char_key, get_common_letter_frequencies, hex_decode_bytes, single_byte_xor,
    };
    use std::fs::File;
    use std::io::{prelude::*, BufReader};

    let file = File::open("4.txt")?;
    let reader = BufReader::new(file);

    struct Message {
        frequency_count: i32,
        message: String,
        line_number: usize
    }

    let mut found_message: Option<Message> = None;

    for (line_num, line) in reader.lines().enumerate() {
        let bytes = hex_decode_bytes(line?.as_bytes())?;
        let key = find_single_char_key(&bytes);

        let tmp = single_byte_xor(&bytes, key);
        let msg = String::from_utf8(tmp)?;

        let freq_count = get_common_letter_frequencies(msg.as_bytes());

        match &found_message {
            Some(x) => {
                if freq_count > x.frequency_count {
                    found_message = Some(Message { frequency_count: freq_count, message: msg, line_number: line_num});
                }
            }
            None => found_message = Some(Message { frequency_count: freq_count, message: msg, line_number: line_num})
        }
    }

    match found_message {
        None => expect_true(false),
        Some(x) => {
            expect_eq(170, x.line_number)?;
            expect_eq("Now that the party is jumping", &x.message)
        }
    }

}

pub fn challenge5() -> Result<()> {
    let plain_text = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    use common::repeated_xor;
    let cipher = repeated_xor(plain_text, key);

    use common::hex_decode_bytes;
    let expected_result = hex_decode_bytes(b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")?;

    expect_eq(expected_result, cipher)
}

pub fn challenge6() -> Result<()> {
    use common::{find_key_size, find_single_char_key, repeated_xor, slice_by_byte};

    let cipher = base64::read_encoded_file("6.txt")?;

    let key_size = find_key_size(&cipher, (2, 40), 20)?;

    let sliced_data = slice_by_byte(&cipher, key_size);

    let key: Vec<u8> = sliced_data
        .iter()
        .map(|x| find_single_char_key(x))
        .collect();

    let tmp = repeated_xor(&cipher, &key);
    let result = std::str::from_utf8(&tmp)?;

    expect_eq("Terminator X: Bring the noise", result)
}

pub fn challenge7() -> Result<()> {
    let cipher = base64::read_encoded_file("7.txt")?;

    let key = b"YELLOW SUBMARINE";

    let plain_text_as_bytes = aes::decrypt_ecb_128(&cipher, key)?;

    let _plain_text = std::str::from_utf8(&plain_text_as_bytes)?;

    // println!("{_plain_text}");

    expect_eq("hi", _plain_text)
}

pub fn challenge8() -> Result<()> {
    use std::fs::File;
    use std::io::{prelude::*, BufReader};

    let file = File::open("8.txt")?;
    let reader = BufReader::new(file);

    let mut lines_in_ecb_mode: Vec<usize> = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let cipher_text = common::hex_decode_bytes(line?.as_bytes())?;

        let ecb_mode = aes::is_cipher_in_ecb_128_mode(&cipher_text);

        if ecb_mode {
            lines_in_ecb_mode.push(line_num);
        }
    }

    expect_false(lines_in_ecb_mode.is_empty())
}

pub fn challenge9() -> Result<()> {
    let mut msg = b"YELLO".to_vec();
    let key_len = 16;

    aes::pkcs7_pad(&mut msg, key_len)?;

    // println!("{:2x?}", msg);
    // print_challenge_result(9, true, Some("Implementing pkcs#7 padding"));
    Ok(())
}

pub fn challenge10() -> Result<()> {
    let cipher_text = base64::read_encoded_file("10.txt")?;
    let key = b"YELLOW SUBMARINE";

    let plain_text = aes::decrypt_cbc_128(&cipher_text, key)?;

    // println!("{}", Wrap(plain_text));

    let cipher_again = aes::encrypt_cbc_128(&plain_text, key)?;

    // print_challenge_result(
    //     10,
    //     cipher_text == cipher_again,
    //     Some("Implementing aes-cbc-128"),
    // );

    expect_eq(cipher_text, cipher_again)
}

pub fn challenge11() -> Result<()> {
    let num_tests = 1000;
    let mut successful_detections = 0;
    for _ in 0..num_tests {
        if aes::decryption_oracle(&aes::rnd_encryption_oracle)? {
            successful_detections += 1;
        }
    }

    // print_challenge_result(
    //     11,
    //     num_tests == successful_detections,
    //     Some("Detecting aes-ecb-128 with pkcs padding and random data"),
    // );

    expect_eq(num_tests, successful_detections)
}

pub fn challenge12() -> Result<()> {
    let unknown_text = base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")?;

    struct ConcattorEcbOracle {
        key: Vec<u8>,
        text_to_append: Vec<u8>,
    }

    impl ConcattorEcbOracle {
        pub fn set_text(&mut self, text: &[u8]) {
            self.text_to_append = text.to_vec()
        }
    }

    use aes::Encryptor;
    impl Encryptor for ConcattorEcbOracle {
        fn encrypt(&self, plain_text: &[u8]) -> aes::Result<Vec<u8>> {
            let mut concatted = plain_text.to_vec();
            concatted.extend_from_slice(&self.text_to_append);
            aes::encrypt_ecb_128(&concatted, &self.key)
        }
        fn decrypt(&self, plain_text: &[u8]) -> aes::Result<Vec<u8>> {
            aes::decrypt_ecb_128(plain_text, &self.key)
        }
    }

    let mut oracle = ConcattorEcbOracle {
        key: aes::generate_key(),
        text_to_append: unknown_text.to_vec(),
    };

    // find block size
    let block_size = aes::find_block_length(&oracle)?;
    if block_size != 16 {
        return Err(aes::AesError {
            kind: aes::ErrorKind::InvalidData,
            message: Some("Breaking aes-ecb-128: Block size not found to be size 16.".to_string()),
        }
        .into());
    }

    // find whether it's in ecb 128 mode
    let in_ecb_mode = aes::is_cipher_in_ecb_128_mode(&oracle.encrypt(&vec![b'a'; block_size * 5])?);

    if !in_ecb_mode {
        return Err(aes::AesError {
            kind: aes::ErrorKind::InvalidData,
            message: Some("Could not assert that the data is aes-ecb-128 encrypted".to_string()),
        }
        .into());
    }

    // decrypt the text
    let mut result: Vec<u8> = Vec::new();

    for idx in (0..unknown_text.len()).step_by(16) {
        let end_idx = if idx + 16 < unknown_text.len() {
            idx + 16
        } else {
            unknown_text.len()
        };

        let mut new_input_block = vec![b'A'; 16];

        let num_chars_to_find = end_idx - idx;
        for char_idx in 0..num_chars_to_find {
            let input_block = vec![b'A'; 16 - char_idx - 1];

            oracle.set_text(&unknown_text[idx..end_idx]);

            let ecb_input_block_with_unkown = oracle.encrypt(&input_block)?;
            let expected_block = ecb_input_block_with_unkown[..16].to_vec();

            for i in aes::SMART_ASCII.iter() {
                new_input_block[15] = *i;
                let new_output = oracle.encrypt(&new_input_block)?;
                if new_output[..16] == expected_block[..] {
                    result.push(*i);

                    new_input_block.remove(0);
                    new_input_block.push(*i);
                }
            }
        }
    }
    println!("{}", Wrap(result));

    // print_challenge_result(12, true, Some("Breaking  aes-ecb-128 message"));
    Ok(())
}

pub fn challenge13() -> Result<()> {
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

        // print_challenge_result(
        //     13,
        //     PROFILE_STORAGE.profiles.len() == 1,
        //     Some("Sent payload without knowing key"),
        // );
    }

    Ok(())
}

pub fn challenge14() -> Result<()> {
    let string_to_find = b"Let's see if we can decipher this";

    let encrypt_with_rnd_prefix = |plain_text: &[u8], key: &[u8]| -> aes::Result<Vec<u8>> {
        use common::prefix_with_rnd_bytes;
        let rnd_bytes_range = (0, 50);
        let text = prefix_with_rnd_bytes(rnd_bytes_range, &plain_text);
        aes::encrypt_ecb_128(&text, &key)
    };

    let oracle = aes::Oracle {
        key: aes::generate_key(),
        encryptor: Box::new(encrypt_with_rnd_prefix),
        decryptor: Box::new(&aes::decrypt_ecb_128),
    };
    use aes::Encryptor;

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
            for idx in (0..cipher.len() / 16 - 1).step_by(16) {
                if &cipher[idx..idx + 16] == &padding_cipher_block[..] {
                    found_text_length = true;
                    text_length = cipher.len() - (idx + 16 + num_pad) - 16;
                    // println!("text length: {}", text_length);
                }
            }
            num_pad += 1;
        }
    }

    let mut result: Vec<u8> = Vec::new();

    let mut found_chars: Vec<u8> = Vec::new();

    for block_idx in (0..text_length).step_by(16) {
        let end_block_idx = if block_idx + 16 > text_length {
            text_length
        } else {
            block_idx + 16
        };

        let num_chars_to_find = end_block_idx - block_idx;
        while found_chars.len() != num_chars_to_find {
            let mut payload = vec![16u8; 16];

            let num_known_bytes = 15 - found_chars.len();
            payload.extend_from_slice(&vec![b'A'; num_known_bytes]);

            payload.extend_from_slice(&string_to_find[block_idx..end_block_idx]);

            let cipher = oracle.encrypt(&payload)?;

            for idx in (0..cipher.len() / 16 - 1).step_by(16) {
                if cipher[idx..idx + 16] == padding_cipher_block[..] {
                    let mut char_decryptor_block: Vec<u8> = payload[16..31].to_vec();
                    char_decryptor_block.push(b'A');

                    for i in aes::SMART_ASCII.iter() {
                        char_decryptor_block[15] = *i;

                        let mut char_decrypt_cipher = oracle.encrypt(&char_decryptor_block)?;
                        while false {
                            if char_decrypt_cipher
                                [char_decrypt_cipher.len() - 16..char_decrypt_cipher.len()]
                                == padding_cipher_block[..]
                            {
                                break;
                            }

                            char_decrypt_cipher = oracle.encrypt(&char_decryptor_block)?;
                        }

                        if char_decrypt_cipher
                            [char_decrypt_cipher.len() - 32..char_decrypt_cipher.len() - 16]
                            == cipher[idx + 16..idx + 32]
                        {
                            found_chars.push(*i);
                        }
                    }
                }
            }
        }
        // println!("deciphered block: \"{}\"", Wrap(found_chars.clone()));
        result.extend_from_slice(&found_chars);
        found_chars.clear();
    }

    if std::str::from_utf8(&result) != std::str::from_utf8(string_to_find) {
        println!(
            "Incorrect Result. Expected\n{result:?}\nReturned\n{:?}",
            string_to_find.to_vec()
        );
    }

    // print_challenge_result(
    //     14,
    //     std::str::from_utf8(&result) == std::str::from_utf8(string_to_find),
    //     Some("Deciphered text with random prefix"),
    // );
    Ok(())
}

#[allow(unused_assignments)]
pub fn challenge15() -> Result<()> {
    let mut message = vec![0u8; 12];
    message.extend_from_slice(&[4u8; 4]);

    let res = aes::remove_pkcs7_padding(&message)?;

    match expect_eq(message.len() - 4, res.len()) {
        Ok(()) => (),
        Err(err) => return Err(err),
    }

    let mut message2 = vec![0u8; 12];
    message2.extend_from_slice(&[4u8; 2]);

    let original_length2 = message2.len();

    match aes::remove_pkcs7_padding(&message2) {
        Ok(_) => Err(ExpectationFailure.into()),
        Err(_) => expect_eq(original_length2, message2.len()),
    }

    // print_challenge_result(15, challenge_success, Some("Testing Function to remove padding"));
}

pub fn challenge16() -> Result<()> {
    fn baconise(user_data: &[u8]) -> aes::Result<Vec<u8>> {
        let mut res = b"comment1=cooking%20MCs;userdata=".to_vec();

        let mut safe_data = match std::str::from_utf8(user_data) {
            Ok(text) => String::from(text),
            Err(_) => return Err(aes::AesError::new(aes::ErrorKind::InvalidData)),
        };
        safe_data = safe_data.replace(';', " ");
        safe_data = safe_data.replace('=', " ");

        res.extend_from_slice(&safe_data.as_bytes());
        res.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
        Ok(res)
    }

    fn encrypt_bacon(plain_text: &[u8], key: &[u8]) -> aes::Result<Vec<u8>> {
        let baconised_text = baconise(plain_text)?;
        aes::encrypt_cbc_128(&baconised_text, key)
    }

    fn decrypt_bacon(cipher_text: &[u8], key: &[u8]) -> aes::Result<Vec<u8>> {
        aes::decrypt_cbc_128(cipher_text, key)
    }

    impl aes::Oracle {
        pub fn find_bacon(&self, cipher_text: &[u8]) -> aes::Result<bool> {
            let res = &self.decrypt(cipher_text)?;
            let decrypted = std::str::from_utf8(&res);
            let plain_text = match decrypted {
                Ok(text) => String::from(text),
                Err(_) => return Err(aes::AesError::new(aes::ErrorKind::InvalidData)),
            };

            Ok(plain_text.contains(";admin=true;"))
        }
    }

    let bacon_oracle = aes::Oracle {
        key: aes::generate_key(),
        encryptor: Box::new(&encrypt_bacon),
        decryptor: Box::new(&decrypt_bacon),
    };
    use aes::Encryptor;

    let user_data = b"Hello my name is Paul";
    let cipher_text = bacon_oracle.encrypt(&user_data[..])?;

    println!("{}", Wrap(bacon_oracle.decrypt(&cipher_text)?));
    println!("{}", bacon_oracle.find_bacon(&cipher_text)?);

    Ok(())
}
