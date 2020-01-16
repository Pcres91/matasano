#![allow(dead_code)]

use bitstream_io::{BigEndian, BitReader, BitWriter};
use std::io::{Cursor, Error};
use std::result::Result;

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
    if success {
        println!("SUCCESSFUL: Challenge {}", challenge_num)
    } else {
        println!("FAILED: Challenge {}", challenge_num)
    }
}

fn pretty_print(chars: Vec<char>) -> String {
    chars.into_iter().collect()
}

pub fn base64_pretty_print(bytes: &[u8]) -> String {
    pretty_print(base64_encode(bytes))
}

pub fn base64_encode(bytes: &[u8]) -> Vec<char> {
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

    v
}

// this converts u8 to base64. If topmost bits aren't 00, returns None
pub fn get_base64_rep(byte: u8) -> Option<char> {
    if byte > 63 {
        return None;
    }
    // capitals
    if byte <= 25 {
        Some((0x41 + byte) as char)
    }
    // lowercase
    else if byte <= 51 {
        Some((0x61 - 26 + byte) as char)
    }
    //digits
    else if byte <= 61 {
        Some((0x30 + byte - 52) as char)
    } else if byte == 62 {
        Some('+')
    } else {
        Some('/')
    }
}

pub fn hex_decode_string(string: &str) -> Vec<u8> {
    hex_decode_bytes(string.as_bytes())
}

// converts the ascii chars for strings into their hex equivalents.
// eg: "abcd" -> vec![11, 12, 13, 14]
pub fn hex_decode_bytes(bytes: &[u8]) -> Vec<u8> {
    let n = BigUint::parse_bytes(bytes, 16).unwrap();
    n.to_bytes_be()
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
        i -= i;
    }
    if padding {
        // TODO: need to implement adding the padding char '='
        println!("Warning: base64 padding not implemented\n");
    }

    base64_chars
}

pub fn xor_bytes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();

    for i in 0..left.len() {
        res.push(left[i] ^ right[i]);
    }

    res
}

// performs a per-bit operation using bitstreams.Bit of overkill
#[allow(dead_code)]
pub fn xor_bits(left: &[u8], right: &[u8]) -> Vec<u8> {
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

    writer.into_writer()
}

pub fn single_byte_xor(message: &[u8], byte: u8) -> Vec<u8> {
    let mut res = Vec::new();

    for message_byte in message {
        res.push(message_byte ^ byte);
    }

    res
}

pub fn get_common_letter_frequencies(msg: &[u8]) -> u32 {
    let most_common_letters = vec!['e', 't', 'a', 'o', 'i', 'n'];

    let mut freq_count = 0;
    for &byte in msg {
        let val = byte as char;
        if most_common_letters.contains(&val) {
            freq_count += 1;
        }
    }

    freq_count
}

pub fn find_single_char_key(cryptogram: &[u8]) -> u8 {
    let mut max_count: u32 = 0;
    let mut key: u8 = 0x0;

    for poss_key in 0..=0xffu32 {
        let decoded_msg = single_byte_xor(&cryptogram, poss_key as u8);
        let freq_count = get_common_letter_frequencies(&decoded_msg);
        if freq_count > max_count {
            max_count = freq_count;
            key = poss_key as u8;
        }
    }

    key
}

pub fn repeated_xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    let mut idx = 0;
    let mut cipher: Vec<u8> = vec![];
    for val in text {
        cipher.push(val ^ key[idx]);

        idx += 1;
        if idx == key.len() {
            idx = 0
        };
    }

    cipher
}

pub fn hamming_distance(string_1: &[u8], string_2: &[u8]) -> Result<u32, Error> {
    let mut cur1 = Cursor::new(&string_1);
    let mut read1 = BitReader::endian(&mut cur1, BigEndian);
    let mut cur2 = Cursor::new(&string_2);
    let mut read2 = BitReader::endian(&mut cur2, BigEndian);

    let mut distance = 0;
    for _ in 0..(string_1.len() * 8) {
        let res = read1.read_bit()? ^ read2.read_bit()?;
        if res {
            distance += 1
        };
    }

    Ok(distance)
}

pub fn read_file_into_buffer(filepath: &str) -> Result<Vec<u8>, Error> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(filepath)?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

pub fn get_average_distance(data: &[u8], key_length: u32, num_blocks: u32) -> u32 {
    0
}

pub fn find_key_size(data: &[u8], key_range: (u32, u32), num_blocks: u32) -> u32 {
    let mut min_distance = std::u32::MAX;
    let mut key_size = key_range.0;
    for key_length in key_range.0..=key_range.1 {
        let distance = get_average_distance(&data, key_length, num_blocks);

        if distance < min_distance {
            min_distance = distance;
            key_size = key_length;
        }
    }

    key_size
}
