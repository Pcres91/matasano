mod common;

use common::{hex_decode_bytes, print_challenge_result, Wrap};

fn challenge1() {
    let n = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec();
    let bytes = hex_decode_bytes(n); // vec![0x49, 0x27, 0x6d, 0x20, ...]

    let encoded = common::base64_pretty_print(bytes);

    let expected_result =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();

    print_challenge_result(1, encoded == expected_result);
}

fn challenge2() {
    let a = hex_decode_bytes(b"1c0111001f010100061a024b53535009181c".to_vec());

    let b = hex_decode_bytes(b"686974207468652062756c6c277320657965".to_vec());

    let result = common::xor_bytes(a, b);

    let expected_result = hex_decode_bytes(b"746865206b696420646f6e277420706c6179".to_vec());

    print_challenge_result(2, result == expected_result);
}

fn challenge3() {
    // Cooking MC's like a pound of bacon
    // let n = hex_decode_string(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_vec());
    let expected_result = "I'm killing your brain like a poisonous mushroom".to_string();
    let cipher = hex_decode_bytes(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec());

    let key = common::find_single_char_key(&cipher);

    let result = Wrap(common::single_byte_xor(&cipher, key)).to_string();

    print_challenge_result(3, result == expected_result);
}

fn challenge4() {
    let _result = common::challenge4();
}

fn challenge5() {
    let _plain_text = "Burning 'em, if you ain't quick and nimble".to_string();
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
}
