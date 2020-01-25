#![allow(dead_code)]
use std::io::Error;

mod common;
use common::{print_challenge_result, Wrap};

mod aes;
mod base64;

fn challenge1() {
    use common::hex_decode_bytes;
    let n = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes = hex_decode_bytes(n); // vec![0x49, 0x27, 0x6d, 0x20, ...]

    let encoded = base64::pretty_print(&bytes);

    let expected_result =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();

    print_challenge_result(1, encoded == expected_result, None)
}

fn challenge2() {
    use common::{hex_decode_bytes, xor_bytes};
    let a = hex_decode_bytes(b"1c0111001f010100061a024b53535009181c");

    let b = hex_decode_bytes(b"686974207468652062756c6c277320657965");

    let result = xor_bytes(&a, &b);

    let expected_result = hex_decode_bytes(b"746865206b696420646f6e277420706c6179");

    print_challenge_result(2, result == expected_result, None);
}

fn challenge3() {
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

fn challenge4() -> Result<(), Error> {
    use common::{
        find_single_char_key, get_common_letter_frequencies, hex_decode_string, single_byte_xor,
    };
    use std::fs::File;
    use std::io::{prelude::*, BufReader};

    let file = File::open("4.txt").unwrap();
    let reader = BufReader::new(file);

    let mut found_message: (i32, u8, Vec<u8>, u32) = (0, 0, vec![], 0);
    let mut line_num = 0;
    for line in reader.lines() {
        line_num += 1;
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

fn challenge5() {
    let plain_text = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    use common::repeated_xor;
    let cipher = repeated_xor(plain_text, key);

    use common::hex_decode_bytes;
    let expected_result = hex_decode_bytes(b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

    print_challenge_result(5, cipher == expected_result, None);
}

fn challenge6() -> Result<(), Error> {
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

fn challenge7() -> Result<(), Error> {
    let cipher = base64::read_encoded_file("7.txt").unwrap();

    let key = b"YELLOW SUBMARINE";

    let _plain_text = aes::decrypt_ecb_128(&cipher, key)?;

    // println!("{}", Wrap(_plain_text));

    print_challenge_result(7, true, Some("Print the text if you want"));
    Ok(())
}

fn challenge8() -> Result<(), Error> {
    use std::fs::File;
    use std::io::{prelude::*, BufReader};

    let file = File::open("8.txt").unwrap();
    let reader = BufReader::new(file);

    let mut num_matches: Vec<(u32, u32)> = Vec::new();

    let mut line_num = 0;
    for line in reader.lines() {
        let cipher_text = common::hex_decode_string(&line?);

        line_num += 1;
        let mut matches = 0;

        let blocks: Vec<u8> = cipher_text.to_vec();
        let num_blocks = blocks.len() / 16;
        for i in 0..num_blocks - 1 {
            let block = &blocks[i * 16..i * 16 + 16];
            for j in i + 1..num_blocks {
                let next_block = &blocks[j * 16..j * 16 + 16];
                if block == next_block {
                    matches += 1;
                }
            }
        }
        if matches > 0 {
            num_matches.push((matches, line_num));
        }
    }

    print_challenge_result(
        8,
        num_matches.len() == 1,
        Some(&format!(
            "line {} had {} identical blocks",
            num_matches[0].1, num_matches[0].0
        )),
    );

    Ok(())
}

fn challenge9() -> Result<(), Error> {
    let mut msg = b"YELLO".to_vec();
    let key_len = 16;

    aes::pad_message_pkcs7(&mut msg, key_len)?;

    println!("{:2x?}", msg);
    Ok(())
}

fn challenge10() -> Result<(), Error> {
    let cipher_text = base64::read_encoded_file("10.txt")?;
    let key = b"YELLOW SUBMARINE";

    let plain_text = aes::decrypt_cbc_128(&cipher_text, key)?;

    // println!("{}", Wrap(plain_text));

    let cipher_again = aes::encrypt_cbc_128(&plain_text, key)?;

    print_challenge_result(10, cipher_text == cipher_again, None);

    Ok(())
}

fn challenge11() -> Result<(), Error> {
    let cipher_text = base64::read_encoded_file("10.txt")?;
    let key = b"YELLOW SUBMARINE";

    let plain_text = aes::decrypt_cbc_128(&cipher_text, key)?;

    let cipher_text = aes::encryption_oracle(&plain_text)?;

    let mut matches = 0;
    let mut counter = 0;
    let blocks: Vec<u8> = cipher_text.to_vec();
    let num_blocks = blocks.len() / 16;
    for i in 0..num_blocks - 1 {
        let block = &blocks[i * 16..i * 16 + 16];
        for j in i + 1..num_blocks {
            counter += 1;
            let next_block = &blocks[j * 16..j * 16 + 16];
            if block == next_block {
                matches += 1;
            }
        }
    }
    println!("tests: {}", counter);
    println!("matches: {}", matches);
    Ok(())
}

fn main() -> Result<(), Error> {
    // challenge1();
    // challenge2();
    // challenge3();
    // challenge4()?;
    // challenge5();
    // challenge6()?;
    // challenge7()?;
    // challenge8()?;

    // challenge9()?;
    // challenge10()?;
    challenge11()?;

    Ok(())
}
