mod common;

use common::{hex_decode_string, print_challenge_result};

use std::fmt;

pub struct Wrap(Vec<u8>);

impl fmt::Display for Wrap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{}", byte as char)?;
        }
        Ok(())
    }
}

fn challenge1() {
    let n = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec();
    let bytes = hex_decode_string(n); // vec![0x49, 0x27, 0x6d, 0x20, ...]

    let encoded = common::base64_pretty_print(bytes);

    let expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();

    print_challenge_result(1, encoded == expected_result);
}

fn challenge2() {
    let a = hex_decode_string(b"1c0111001f010100061a024b53535009181c".to_vec());

    let b = hex_decode_string(b"686974207468652062756c6c277320657965".to_vec());

    let result = common::xor_bytes(a, b);

    let expected_result = hex_decode_string(b"746865206b696420646f6e277420706c6179".to_vec());

    print_challenge_result(2, result == expected_result);
}

fn challenge3() {
    // Cooking MC's like a pound of bacon
    // let n = hex_decode_string(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_vec());
    let expected_result = "I'm killing your brain like a poisonous mushroom".to_string();
    let cipher = hex_decode_string(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec());

    let most_common_letters = vec!['e', 't', 'a', 'o', 'i', 'n'];
    
    let mut max_count: u8 = 0;
    let mut key: u8 = 0x0;

    for poss_key in 0..(0xffu32 + 1) {
        let decoded_msg = common::single_byte_xor(&cipher, poss_key as u8);
        let mut freq_count = 0;
        for &byte in &decoded_msg {
            let val = byte as char;
            if most_common_letters.contains(&val) {
                freq_count += 1;
            }
        }
        if freq_count > max_count {
            max_count = freq_count;
            key = poss_key as u8;
        }
    }

    let result = Wrap(common::single_byte_xor(&cipher, key)).to_string();

    print_challenge_result(3, result == expected_result);
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
}
