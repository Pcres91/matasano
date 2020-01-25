use bitstream_io::{BigEndian, BitReader, BitWriter};
use std::io::{Cursor, Error};

extern crate num_bigint as bigint;
use bigint::BigUint;

pub fn pretty_print(bytes: &[u8]) -> String {
    encode(bytes).into_iter().collect()
}

pub fn encode(bytes: &[u8]) -> Vec<char> {
    let num_bits = bytes.len() * 8;
    let num_chars = num_bits / 6;

    let mut cursor = Cursor::new(&bytes);
    let mut reader = BitReader::endian(&mut cursor, BigEndian);
    let mut encoded = vec![];
    for _i in 0..num_chars {
        // must be a better way to loop through the length of reader.
        let c = encode_byte(reader.read::<u8>(6).unwrap()).unwrap();
        encoded.push(c);
    }

    encoded
}

pub fn decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut writer = BitWriter::endian(Vec::new(), BigEndian);

    for &byte in data {
        if byte as char == '=' {
            break;
        } else {
            writer.write(6, decode_byte(byte).unwrap())?;
        }
    }

    // into_writer throws away any incomplete bytes.
    // So, by breaking when the padding '=' is reached,
    // the padded bits in the previous character are thrown
    // away. Neato
    Ok(writer.into_writer())
}

pub fn read_encoded_file(filepath: &str) -> Result<Vec<u8>, Error> {
    use std::fs::File;
    use std::io::{prelude::*, BufReader};

    let file = File::open(filepath)?;
    let reader = BufReader::new(file);

    let mut data: Vec<u8> = Vec::new();
    for line in reader.lines() {
        data.extend_from_slice(&decode(line?.as_bytes())?);
    }

    Ok(data)
}

// this converts u8 to base64. If topmost bits aren't 00, returns None
fn encode_byte(byte: u8) -> Option<char> {
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

// decodes a char into its base64 representation. If it doesn't have one, returns None
fn decode_byte(byte: u8) -> Option<u8> {
    // capitals
    if byte >= 65 && byte <= 90 {
        Some(byte - 65)
    }
    // lowercase
    else if byte >= 97 && byte <= 122 {
        Some(byte - 71)
    }
    // digits
    else if byte >= 48 && byte <= 57 {
        Some(byte + 4)
    }
    // +
    else if byte as char == '+' {
        Some(62)
    }
    // /
    else if byte as char == '/' {
        Some(63)
    }
    // padding returns none
    else {
        println!("Gonna panic on char {}: {}", byte as char, byte);
        None
    }
}

#[allow(dead_code)]
fn encode_biguint(bytes: &BigUint) -> Vec<char> {
    // determine padding length
    let num_bits = bytes.bits();
    let padding: bool = num_bits % 6 != 0;
    let num_chars: usize = num_bits / 6;

    println!(
        "num_bits {}, padding {}, num_chars {}",
        num_bits, padding, num_chars
    );

    let bitmask: u8 = 0b0011_1111;

    let mut encoded: Vec<char> = Vec::new();

    let mut i = num_chars as i32;
    while i >= 0 {
        let shifted: BigUint = bytes >> (i as usize * 6);

        // println!("i = {}\nbytes: {:b}\nshifted: {:b}", i, bytes, shifted);

        // soooooo inefficient. gotta be a better way
        let c: u8 = shifted.to_bytes_le()[0];
        // println!("c: {:b}", c);

        encoded.push(encode_byte(c & bitmask).unwrap());
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

    encoded
}
