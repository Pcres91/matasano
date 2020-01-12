mod common;
use common::{hex_decode_string, base64_pretty_print, XOR, print_challenge_result};

fn challenge1() {
    let n = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_vec();
    let bytes = hex_decode_string(n); // vec![0x49, 0x27, 0x6d, 0x20, ...]

    let encoded = base64_pretty_print(bytes);

    let expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string();

    print_challenge_result(1, encoded == expected_result);
}

fn challenge2() {
    let a = b"1c0111001f010100061a024b53535009181c".to_vec();
    let a_bytes = hex_decode_string(a);

    let b = b"686974207468652062756c6c277320657965".to_vec();
    let b_bytes = hex_decode_string(b);

    let result = XOR(a_bytes, b_bytes);

    for byte in result {
        print!("{:2x}", byte);
    }
    println!();
}

fn main() {
    challenge1();
    challenge2();
}
