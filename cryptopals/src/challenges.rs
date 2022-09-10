use crate::aes;
use crate::aes::detect_encryption_mode;
use crate::aes::Cipher;
use crate::base64;
use crate::common;
// use crate::errors;
use crate::errors::{AesError, AesResult, Result};
#[allow(unused_imports)]
use crate::expectations::{expect_eq, expect_false, expect_true};
use crate::user_storage;
use common::Wrap;
use rayon::prelude::*;
use std::io::BufReader;

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

pub fn print_challenge_result(challenge_number: i32, challenge: &dyn Fn() -> Result<()>) {
    use std::time::Instant;
    let timer = Instant::now();
    match challenge() {
        Ok(_) => println!("SUCCESSFUL: Challenge {challenge_number}"),
        Err(error) => {
            println!("FAILED:     Challenge {challenge_number}, {error}\n\n{error:?}");
        }
    }
    println!("-----{:.2?}-----", timer.elapsed());
}

/// Converting a string of hex to bytes representing chars, then those chars to base64
pub fn challenge1() -> Result<()> {
    use common::hex_string_to_vec_u8;

    let hex_values_as_string = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let exp_encoding =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();

    // bytes are just chars showing "I'm killing your brain like a poisonous mushroom"
    let bytes = hex_string_to_vec_u8(hex_values_as_string)?;

    let encoded = base64::char_bytes_to_base64(&bytes)?;

    expect_eq(exp_encoding, encoded, "Encoding a hex string")?;

    Ok(())
}

/// take two buffers of equal length and produce their XOR combination
pub fn challenge2() -> Result<()> {
    use common::{hex_string_to_vec_u8, xor_bytes};

    let a = hex_string_to_vec_u8(b"1c0111001f010100061a024b53535009181c")?;
    let b = hex_string_to_vec_u8(b"686974207468652062756c6c277320657965")?;

    let result = xor_bytes(&a, &b)?;

    let expected_result = hex_string_to_vec_u8(b"746865206b696420646f6e277420706c6179")?;

    expect_eq(expected_result, result, "")?;

    Ok(())
}

/// Find the single character that a buffer has been XOR'd with.
pub fn challenge3() -> Result<()> {
    use common::{find_best_character_key, hex_string_to_vec_u8, single_byte_xor};

    let expected_result = "Cooking MC's like a pound of bacon";
    let cipher = hex_string_to_vec_u8(
        b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    )?;

    // let expected_result = "I'm killing your brain like a poisonous mushroom".to_string();
    // let cipher = hex_decode_bytes(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec());

    let key = find_best_character_key(&cipher);

    let tmp = single_byte_xor(&cipher, key);
    let result = std::str::from_utf8(&tmp)?;

    expect_eq(expected_result, result, "")?;

    Ok(())
}

/// Find the line in a file that has been XOR'd with a single character key.
pub fn challenge4() -> Result<()> {
    use common::{find_best_character_key_and_score, hex_string_to_vec_u8};
    use std::fs::File;
    use std::io::prelude::*;

    let file = File::open("4.txt")?;
    let reader = BufReader::new(file);

    let (line_number, result) = reader
        .lines()
        .filter_map(|line| line.ok())
        .enumerate()
        .par_bridge()
        .map(|(line_num, line)| (line_num, hex_string_to_vec_u8(&line.as_bytes())))
        .filter(|(_, cipher_result)| cipher_result.is_ok())
        .map(|(line_num, ciphertext)| {
            (
                line_num,
                find_best_character_key_and_score(&ciphertext.unwrap()),
            )
        })
        .max_by(|(_, left), (_, right)| left.score.cmp(&right.score))
        .unwrap();

    expect_eq(170, line_number, "expected line number of the encoded line")?;
    expect_eq(
        '1',
        base64::encode_byte(result.key)?,
        "key is '1' in base64",
    )?;
    expect_eq(
        "Now that the party is jumping\n",
        std::str::from_utf8(&result.plaintext)?,
        "",
    )?;

    Ok(())
}

pub fn challenge5() -> Result<()> {
    use common::{hex_string_to_vec_u8, repeated_xor};
    let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    let cipher = repeated_xor(plaintext, key);

    let expected_result = hex_string_to_vec_u8(b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")?;

    expect_eq(expected_result, cipher, "")?;

    Ok(())
}

pub fn challenge6() -> Result<()> {
    use common::{find_best_character_key, find_key_size, repeated_xor, slice_by_byte};

    let cipher = base64::read_encoded_file("6.txt")?;

    // iterate through key sizes, finding the one with the lowest average hamming distance over 20 blocks
    let key_size = find_key_size(&cipher, (2, 40), 20)?;

    // get all the first bytes of each block together, second bytes of each block together, etc
    let sliced_data = slice_by_byte(&cipher, key_size);

    // find the best character key for each slice
    let key: Vec<u8> = sliced_data
        .par_iter()
        .map(|x| find_best_character_key(x))
        .collect();

    let tmp = repeated_xor(&cipher, &key);
    let result = std::str::from_utf8(&tmp)?;

    let expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    expect_eq(expected, result, "")?;
    expect_eq(
        "Terminator X: Bring the noise",
        std::str::from_utf8(&key)?,
        "",
    )?;

    Ok(())
}

pub fn challenge7() -> Result<()> {
    let cipher = base64::read_encoded_file("7.txt")?;
    let expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    let ecb_cipher = aes::EcbCipher {
        key: *b"YELLOW SUBMARINE",
    };
    let plaintext_as_bytes = ecb_cipher.decrypt(&cipher)?;
    let _plaintext = std::str::from_utf8(&plaintext_as_bytes)?;

    expect_eq(expected, _plaintext, "")?;

    Ok(())
}

pub fn challenge8() -> Result<()> {
    use std::fs::File;
    use std::io::prelude::*;

    let file = File::open("8.txt")?;
    let reader = BufReader::new(file);

    let lines_in_ecb_mode: Vec<usize> = reader
        .lines()
        .filter_map(|line| line.ok())
        .enumerate()
        .par_bridge()
        .map(|(line_num, line)| (line_num, common::hex_string_to_vec_u8(line.as_bytes())))
        .filter(|(_, line)| line.is_ok())
        .filter(|(_, line)| aes::is_data_ecb128_encrypted(line.as_deref().unwrap()))
        .map(|(line_num, _)| line_num)
        .collect();

    expect_eq(
        1,
        lines_in_ecb_mode.len(),
        "Only one line is ecb128-encrypted",
    )?;
    expect_eq(
        132,
        lines_in_ecb_mode[0],
        "Detecting the line in a file that's ecb128-encrypted",
    )?;

    Ok(())
}

pub fn challenge9() -> Result<()> {
    let mut msg = b"YELLOW SUBMARINE".to_vec();
    let key_len = 20;

    let padded = aes::pkcs7_pad(&mut msg, key_len)?;

    let mut expected = msg.clone();
    expected.extend_from_slice(&vec![4; 4]);
    expect_eq(
        expected.len(),
        padded.len(),
        "PKCS7 padding to correct length",
    )?;
    expect_eq(expected, padded, "padding with correct bytes")?;

    Ok(())
}

pub fn challenge10() -> Result<()> {
    let ciphertext = base64::read_encoded_file("10.txt")?;
    let key = b"YELLOW SUBMARINE";

    let cbc_cipher = aes::CbcCipher {
        key: *key,
        iv: None,
    };

    let plaintext = cbc_cipher.decrypt(&ciphertext)?;

    let ciphertext_again = cbc_cipher.encrypt(&plaintext)?;

    expect_eq(
        ciphertext.len(),
        ciphertext_again.len(),
        "lengths of the ciphertexts",
    )?;
    expect_eq(ciphertext, ciphertext_again, "Implementing aes-cbc-128")?;

    Ok(())
}

pub fn challenge11() -> Result<()> {
    // the oracle itself is what we don't know - let's put enough text of the same type to ensure ecb encryption
    // will have at least 2 identical blocks
    let plaintext = &[b'a'; 256];

    let num_tests = 1000;
    let mut successful_detections = 0;
    for _ in 0..num_tests {
        let (ciphertext, encryption_type) = aes::encryption_oracle(plaintext)?;

        if detect_encryption_mode(&ciphertext) == encryption_type {
            successful_detections += 1;
        }
    }

    expect_eq(num_tests, successful_detections, "")?;

    Ok(())
}

pub fn challenge12() -> Result<()> {
    let unknown_text = base64::decode(b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")?;
    let expected = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";

    struct ConcattorEcbCipher {
        key: [u8; 16],
        unknown_text: Vec<u8>,
    }

    impl ConcattorEcbCipher {
        pub fn set_text(&mut self, text: &[u8]) {
            self.unknown_text = text.to_vec()
        }
    }

    impl Cipher for ConcattorEcbCipher {
        fn encrypt(&self, plaintext: &[u8]) -> AesResult<Vec<u8>> {
            let mut concatted = plaintext.to_vec();
            concatted.extend_from_slice(&self.unknown_text);
            aes::encrypt_ecb_128(&concatted, &self.key)
        }
        fn decrypt(&self, plaintext: &[u8]) -> AesResult<Vec<u8>> {
            aes::decrypt_ecb_128(plaintext, &self.key)
        }
    }

    let mut oracle = ConcattorEcbCipher {
        key: aes::generate_rnd_key(),
        unknown_text: unknown_text.to_vec(),
    };

    // find block size
    let block_size = aes::find_block_length(&oracle)?;

    expect_eq(16, block_size, "Finding block length of encryption oracle")?;

    // find whether it's in ecb 128 mode
    if !aes::is_data_ecb128_encrypted(&oracle.encrypt(&vec![b'a'; block_size * 5])?) {
        return Err(AesError::InvalidData(
            "Could not assert that the data is aes-ecb-128 encrypted".to_string(),
        )
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

    expect_eq(
        expected,
        std::str::from_utf8(&result)?,
        "aes-ecb-128 message",
    )?;

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
        let ciphertext = create_hash_profile_for(from_utf8(&payload)?)?;

        // for i in 0..ciphertext.len() / 16 {
        //     println!(
        //         "{}||",
        //         Wrap(aes::decrypt_ecb_128(
        //             &ciphertext[i * 16..i * 16 + 16],
        //             &RND_KEY
        //         )?)
        //     );
        // }
        let mut payload_cipher = ciphertext[..32].to_vec();
        payload_cipher.extend_from_slice(&ciphertext[48..64]);
        payload_cipher.extend_from_slice(&ciphertext[32..48]);

        // TODO: create an expect_ok! macro
        PROFILE_STORAGE.add_from_hash(&payload_cipher)?;

        Ok(())
    }
}

// TODO: This is the least performant code. Can most likely be parallelised in some form
pub fn challenge14() -> Result<()> {
    let string_to_find = "Let's see if we can decipher this";

    fn encrypt_with_rnd_prefix(plaintext: &[u8], key: &[u8]) -> AesResult<Vec<u8>> {
        use common::prefix_with_rnd_bytes;
        let rnd_bytes_range = (0, 50);
        let text = prefix_with_rnd_bytes(rnd_bytes_range, &plaintext);
        aes::encrypt_ecb_128(&text, &key)
    }

    struct Ch14Cipher {
        key: [u8; 16],
    }

    impl Cipher for Ch14Cipher {
        fn encrypt(&self, plaintext: &[u8]) -> AesResult<Vec<u8>> {
            encrypt_with_rnd_prefix(plaintext, &self.key)
        }
        fn decrypt(&self, ciphertext: &[u8]) -> AesResult<Vec<u8>> {
            aes::decrypt_ecb_128(ciphertext, &self.key)
        }
    }

    let cipher = Ch14Cipher {
        key: aes::generate_rnd_key(),
    };

    let padding_cipher_block = aes::find_ecb_128_padded_block_cipher(&cipher)?;

    let mut found_text_length = false;
    let mut text_length = 0;

    let mut num_pad = 0usize;

    while !found_text_length {
        let mut padding = vec![16u8; 16];
        padding.extend_from_slice(&vec![b'A'; num_pad]);
        padding.extend_from_slice(&string_to_find.as_bytes()[..]);
        let cipher = cipher.encrypt(&padding)?;

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

            payload.extend_from_slice(&string_to_find.as_bytes()[block_idx..end_block_idx]);

            let ciphertext = cipher.encrypt(&payload)?;

            for idx in (0..ciphertext.len() / 16 - 1).step_by(16) {
                if ciphertext[idx..idx + 16] == padding_cipher_block[..] {
                    let mut char_decryptor_block: Vec<u8> = payload[16..31].to_vec();
                    char_decryptor_block.push(b'A');

                    for i in aes::SMART_ASCII.iter() {
                        char_decryptor_block[15] = *i;

                        let mut char_decrypt_cipher = cipher.encrypt(&char_decryptor_block)?;
                        while false {
                            if char_decrypt_cipher
                                [char_decrypt_cipher.len() - 16..char_decrypt_cipher.len()]
                                == padding_cipher_block[..]
                            {
                                break;
                            }

                            char_decrypt_cipher = cipher.encrypt(&char_decryptor_block)?;
                        }

                        if char_decrypt_cipher
                            [char_decrypt_cipher.len() - 32..char_decrypt_cipher.len() - 16]
                            == ciphertext[idx + 16..idx + 32]
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

    expect_eq(
        string_to_find,
        std::str::from_utf8(&result)?,
        "Deciphering text with random prefix",
    )?;

    Ok(())
}

pub fn challenge15() -> Result<()> {
    let mut message = vec![0u8; 12];
    message.extend_from_slice(&[4u8; 4]);

    let res = aes::validate_and_remove_pkcs7_padding(&message)?;

    expect_eq(message.len() - 4, res.len(), "Message length")?;

    let mut message2 = vec![0u8; 12];
    message2.extend_from_slice(&[4u8; 2]);

    let original_length2 = message2.len();

    match aes::validate_and_remove_pkcs7_padding(&message2) {
        Ok(_) => Err(AesError::InvalidData(format!("Unexpected padding at end of message")).into()),
        Err(_) => match expect_eq(
            original_length2,
            message2.len(),
            "Testing Function to remove padding",
        ) {
            Ok(_) => Ok(()),
            Err(error) => Err(error.into()),
        },
    }
}

pub fn challenge16() -> Result<()> {
    use crate::errors::*;
    fn baconise(user_data: &[u8]) -> AesResult<Vec<u8>> {
        let mut res = b"comment1=cooking%20MCs;userdata=".to_vec();

        let safe_data: String = user_data
            .into_par_iter()
            .map(|c| match *c as char {
                ';' => ' ',
                '=' => ' ',
                _ => *c as char,
            })
            .collect();

        res.extend_from_slice(&safe_data.as_bytes());
        res.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
        Ok(res)
    }

    struct BackonCipher {
        key: [u8; 16],
    }

    impl Cipher for BackonCipher {
        fn encrypt(&self, plaintext: &[u8]) -> AesResult<Vec<u8>> {
            let baconised_text = baconise(plaintext)?;
            aes::encrypt_cbc_128_zero_iv(&baconised_text, &self.key)
        }
        fn decrypt(&self, ciphertext: &[u8]) -> AesResult<Vec<u8>> {
            aes::decrypt_cbc_128_zero_iv(ciphertext, &self.key)
        }
    }

    impl BackonCipher {
        pub fn find_bacon(&self, ciphertext: &[u8]) -> AesResult<bool> {
            let res = self.decrypt(ciphertext)?;
            let plaintext = String::from_utf8(res)?;

            Ok(plaintext.contains(";admin=true;"))
        }
    }

    let bacon_oracle = BackonCipher {
        key: aes::generate_rnd_key(),
    };

    let user_data = b"Hello my name is Paul";
    let ciphertext = bacon_oracle.encrypt(&user_data[..])?;

    println!("{}", Wrap(bacon_oracle.decrypt(&ciphertext)?));
    println!("{}", bacon_oracle.find_bacon(&ciphertext)?);

    Ok(())
}

#[cfg(test)]
mod challenge_tests {
    use super::*;

    #[test]
    fn test_challenge1() {
        challenge1().unwrap();
    }
    #[test]
    fn test_challenge2() {
        challenge2().unwrap();
    }
    #[test]
    fn test_challenge3() {
        challenge3().unwrap();
    }
    #[test]
    fn test_challenge4() {
        challenge4().unwrap();
    }
    #[test]
    fn test_challenge5() {
        challenge5().unwrap();
    }
    #[test]
    fn test_challenge6() {
        challenge6().unwrap();
    }
    #[test]
    fn test_challenge7() {
        challenge7().unwrap();
    }
    #[test]
    fn test_challenge8() {
        challenge8().unwrap();
    }
    #[test]
    fn test_challenge9() {
        challenge9().unwrap();
    }
    #[test]
    fn test_challenge10() {
        challenge10().unwrap();
    }
    #[test]
    fn test_challenge11() {
        challenge11().unwrap();
    }
    #[test]
    fn test_challenge12() {
        challenge12().unwrap();
    }
    #[test]
    fn test_challenge13() {
        challenge13().unwrap();
    }
    #[test]
    fn test_challenge14() {
        challenge14().unwrap();
    }
    #[test]
    fn test_challenge15() {
        challenge15().unwrap();
    }
    #[test]
    fn test_challenge16() {
        challenge16().unwrap();
    }
}
