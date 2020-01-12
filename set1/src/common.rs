use std::io::{Cursor, Read};
use bitstream_io::{BitReader, BitWriter, BigEndian};
use std::ops::BitXor;

extern crate num_bigint as bigint;
extern crate num_traits;

use bigint::BigUint;

pub fn print_challenge_result(challenge_num: u32, success: bool) {
    match success {
        true => println!("SUCCESSFUL: Challenge {}", challenge_num),
        false => println!("FAILED: Challenge {}", challenge_num)
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
    }
    else if byte == 62 {
        return Some('+');
    }
    else {
        return Some('/');
    }
}

// converts the ascii chars for strings into their hex equivalents.
// eg: "abcd" -> vec![11, 12, 13, 14]
pub fn hex_decode_string(bytes: Vec<u8>) -> Vec<u8> {
    let n = BigUint::parse_bytes(bytes.as_slice(), 16).unwrap();
    return n.to_bytes_be();
}

#[allow(dead_code)]
fn biguint_to_base64(bytes: &BigUint) -> Vec<char> {

    // determine padding length
    let num_bits = bytes.bits();
    let padding: bool = num_bits % 6 != 0;
    let num_chars: usize = num_bits / 6;

    println!("num_bits {}, padding {}, num_chars {}",
        num_bits, padding, num_chars);

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

pub fn XOR(left: Vec<u8>, right: Vec<u8>) -> Vec<u8>
{
    let mut res: Vec<u8> = Vec::new();

    let mut l_cur = Cursor::new(&left);
    let mut l_reader = BitReader::endian(&mut l_cur, BigEndian);

    let mut r_cur = Cursor::new(&right);
    let mut r_reader = BitReader::endian(&mut r_cur, BigEndian);

    let mut writer = BitWriter::endian(Vec::new(), BigEndian);

    let num_bits = left.len() * 8;

    for _i in 0..num_bits {
        let res:bool = l_reader.read_bit().unwrap() ^ r_reader.read_bit().unwrap();
        writer.write_bit(res).unwrap();
    }

    return writer.into_writer();
}

#[derive(Debug, PartialEq)]
struct Scalar(bool);

impl BitXor for Scalar {
    type Output = Self;

    // rhs is the "right-hand side" of the expression `a ^ b`
    fn bitxor(self, rhs: Self) -> Self::Output {
        Scalar(self.0 ^ rhs.0)
    }
}
