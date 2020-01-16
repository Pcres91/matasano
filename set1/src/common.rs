#![allow(dead_code)]

use bitstream_io::{BigEndian, BitReader, BitWriter};
use std::io::{Cursor, Error};
use std::result::{Result};

extern crate num_bigint as bigint;
extern crate num_traits;

use bigint::BigUint;

use std::fmt;

pub struct Wrap(pub Vec<u8>);

impl fmt::Display for Wrap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{}", byte as char)?;
        }
        Ok(())
    }
}

pub fn print_challenge_result(challenge_num: u32, success: bool) {
    match success {
        true => println!("SUCCESSFUL: Challenge {}", challenge_num),
        false => println!("FAILED: Challenge {}", challenge_num),
    }
}

fn pretty_print(chars: Vec<char>) -> String {
    return chars.into_iter().collect();
}

pub fn base64_pretty_print(bytes: Vec<u8>) -> String {
    return pretty_print(base64_encode(bytes));
}

pub fn base64_encode(bytes: Vec<u8>) -> Vec<char> {
    let num_bits = bytes.len() * 8;
    let num_chars = num_bits / 6;

    let mut cursor = Cursor::new(&bytes);
    let mut reader = BitReader::endian(&mut cursor, BigEndian);
    let mut v = vec![];
    for _i in 0..num_chars {
        // must be a better way to loop through the length of reader.
        let c = get_base64_rep(reader.read::<u8>(6).unwrap()).unwrap();
        v.push(c);
    }
    return v;
}

// this converts u8 to base64. If topmost bits aren't 00, returns None
pub fn get_base64_rep(byte: u8) -> Option<char> {
    if byte > 63 {
        return None;
    }
    // capitals
    if byte <= 25 {
        return Some((0x41 + byte) as char);
    }
    // lowercase
    else if byte <= 51 {
        return Some((0x61 - 26 + byte) as char);
    }
    //digits
    else if byte <= 61 {
        return Some((0x30 + byte - 52) as char);
    } else if byte == 62 {
        return Some('+');
    } else {
        return Some('/');
    }
}

pub fn hex_decode_string(string: String) -> Vec<u8> {
    return hex_decode_bytes(string.into_bytes());
}

// converts the ascii chars for strings into their hex equivalents.
// eg: "abcd" -> vec![11, 12, 13, 14]
pub fn hex_decode_bytes(bytes: Vec<u8>) -> Vec<u8> {
    let n = BigUint::parse_bytes(bytes.as_slice(), 16).unwrap();
    return n.to_bytes_be();
}

#[allow(dead_code)]
fn biguint_to_base64(bytes: &BigUint) -> Vec<char> {
    // determine padding length
    let num_bits = bytes.bits();
    let padding: bool = num_bits % 6 != 0;
    let num_chars: usize = num_bits / 6;

    println!(
        "num_bits {}, padding {}, num_chars {}",
        num_bits, padding, num_chars
    );

    let bitmask: u8 = 0b0011_1111;

    let mut base64_chars: Vec<char> = Vec::new();

    let mut i = num_chars as i32;
    while i >= 0 {
        let shifted: BigUint = bytes >> (i as usize * 6);

        // println!("i = {}\nbytes: {:b}\nshifted: {:b}", i, bytes, shifted);

        // soooooo inefficient. gotta be a better way
        let c: u8 = shifted.to_bytes_le()[0];
        // println!("c: {:b}", c);

        base64_chars.push(get_base64_rep(c & bitmask).unwrap());
        // use num_traits::cast::ToPrimitive;
        // let c = shifted as u8;
        // print!("bytes: {:b}\nshifted: {:b}\n", bytes, shifted);
        // match c {
        //     Some(x) => base64_chars.push(common::get_base64_rep(bitmask & x)),
        //     None => println!("shifting didn't work :( {}", i)
        // }
        i = i - 1;
    }
    if padding {
        // TODO: need to implement adding the padding char '='
        println!("Warning: base64 padding not implemented\n");
    }

    return base64_chars;
}

pub fn xor_bytes(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();

    for i in 0..left.len() {
        res.push(left[i] ^ right[i]);
    }

    return res;
}

// performs a per-bit operation using bitstreams.Bit of overkill
#[allow(dead_code)]
pub fn xor_bits(left: Vec<u8>, right: Vec<u8>) -> Vec<u8> {
    let mut l_cur = Cursor::new(&left);
    let mut l_reader = BitReader::endian(&mut l_cur, BigEndian);

    let mut r_cur = Cursor::new(&right);
    let mut r_reader = BitReader::endian(&mut r_cur, BigEndian);

    let mut writer = BitWriter::endian(Vec::new(), BigEndian);

    let num_bits = left.len() * 8;

    for _i in 0..num_bits {
        let res: bool = l_reader.read_bit().unwrap() ^ r_reader.read_bit().unwrap();
        writer.write_bit(res).unwrap();
    }

    return writer.into_writer();
}

pub fn single_byte_xor(message: &Vec<u8>, byte: u8) -> Vec<u8> {
    let mut res = Vec::new();

    for message_byte in message {
        res.push(message_byte ^ byte);
    }

    return res;
}

pub fn get_common_letter_frequencies(msg: &Vec<u8>) -> u32 {
    let most_common_letters = vec!['e', 't', 'a', 'o', 'i', 'n'];

    let mut freq_count = 0;
    for &byte in msg {
        let val = byte as char;
        if most_common_letters.contains(&val) {
            freq_count += 1;
        }
    }

    return freq_count;
}

pub fn find_single_char_key(cryptogram: &Vec<u8>) -> u8 {
    let mut max_count: u32 = 0;
    let mut key: u8 = 0x0;

    for poss_key in 0..(0xffu32 + 1) {
        let decoded_msg = single_byte_xor(&cryptogram, poss_key as u8);
        let freq_count = get_common_letter_frequencies(&decoded_msg);
        if freq_count > max_count {
            max_count = freq_count;
            key = poss_key as u8;
        }
    }

    return key;
}

pub fn repeated_xor(text: Vec<u8>, key: Vec<u8>) -> Vec<u8> {

    let mut idx = 0;
    let mut cipher: Vec<u8> = vec![];
    for val in 0..text.len() {
        cipher.push(text[val] as u8 ^ key[idx]);

        idx += 1;
        if idx == key.len() {idx = 0};
    }
    return cipher;
}

pub fn hamming_distance(string_1: Vec<u8>, string_2: Vec<u8>) -> Result<u32, Error>
{
    let mut cur1 = Cursor::new(&string_1);
    let mut read1 = BitReader::endian(&mut cur1, BigEndian);
    let mut cur2 = Cursor::new(&string_2);
    let mut read2 = BitReader::endian(&mut cur2, BigEndian);

    let mut distance = 0;
    for _ in 0..(string_1.len() * 8) {
        let res = read1.read_bit()? ^ read2.read_bit()?;
        if res {distance += 1};
    }

    Ok(distance)
}
