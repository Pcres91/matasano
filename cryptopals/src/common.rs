use std::collections::BTreeMap;
use std::io::{Cursor, Error};
use std::result::Result;

extern crate num_bigint as bigint;
extern crate num_traits;

use bigint::BigUint;
use bitstream_io::{BigEndian, BitReader, BitWriter};

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

pub fn hex_decode_string(string: &str) -> Vec<u8> {
    hex_decode_bytes(string.as_bytes())
}

// converts the ascii chars for strings into their hex equivalents.
// eg: "abcd" -> vec![11, 12, 13, 14]
pub fn hex_decode_bytes(bytes: &[u8]) -> Vec<u8> {
    let n = BigUint::parse_bytes(bytes, 16).unwrap();
    n.to_bytes_be()
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

#[allow(dead_code)]
fn ascii_to_uppercase(chr: u8) -> u8 {
    if chr >= 97 && chr <= 122 {
        return chr - (97 - 65);
    };

    chr
}

pub fn get_common_letter_frequencies(msg: &[u8]) -> i32 {
    // list of the most frequent ASCII characters
    // without characters or punctuation. For long texts
    // this should be sufficient
    // shamelessly stolen from
    // http://www.fitaly.com/board/domper3/posts/136.html
    // [101, 32, 116, 111, 97, 110, 105, 115, 114, 108]     4
    // [104, 100, 99, 117, 109, 103, 112, 46, 45, 102]      3
    // [119, 121, 98, 118, 44, 107, 149, 48, 49, 58]        2
    // [83, 67, 77, 84, 73, 68, 65, 69, 80, 87]             1
    // [82, 39, 34, 72, 41, 40, 66, 78, 120, 76]            0
    // [71, 51, 79, 74, 53, 47, 63, 70, 52, 62]            -1
    // [60, 59, 95, 54, 56, 55, 57, 86, 106, 85]           -2
    // [113, 75, 42, 122, 36, 88, 81, 89, 61, 38]          -3
    // [43, 35, 37, 93, 91, 90, 64, 33, 9, 125]            -4
    // [92, 183, 96, 124, 126, 237]                        -5

    let mut freq_count = 0;
    for &byte in msg {
        if [101, 32, 116, 111, 97, 110, 105, 115, 114, 108].contains(&byte) {
            freq_count += 8;
        } else if [104, 100, 99, 117, 109, 103, 112, 46, 45, 102].contains(&byte) {
            freq_count += 4;
        } else if [119, 121, 98, 118, 44, 107, 149, 48, 49, 58].contains(&byte) {
            freq_count += 2;
        } else if [83, 67, 77, 84, 73, 68, 65, 69, 80, 87].contains(&byte) {
            freq_count += 1;
        } else if [43, 35, 37, 93, 91, 90, 64, 33, 9, 125].contains(&byte) {
            freq_count -= 4;
        } else if [92, 183, 96, 124, 126, 237].contains(&byte) {
            freq_count -= 8;
        } else if byte <= 12 {
            freq_count -= 20;
        }
    }

    freq_count
}

pub fn find_single_char_key(cipher: &[u8]) -> u8 {
    let mut possible_keys: Vec<(i32, u8)> = Vec::new();
    for possible_key in 0..=0xffu32 {
        let decoded_msg = single_byte_xor(&cipher, possible_key as u8);
        let freq_count = get_common_letter_frequencies(&decoded_msg);
        possible_keys.push((freq_count, possible_key as u8));
    }
    possible_keys.sort_by_key(|&k| std::cmp::Reverse(k.0));
    // println!("{:?}", &possible_keys[0..20]);
    possible_keys[0].1
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

pub fn hamming_distance(string_1: &[u8], string_2: &[u8]) -> Result<usize, Error> {
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

pub fn get_average_distance(
    data: &[u8],
    key_length: usize,
    num_blocks: usize,
) -> Result<f32, Error> {
    let mut sum_distances = 0usize;
    for i in 0..num_blocks {
        let idx = i * key_length;
        sum_distances += hamming_distance(
            &data[idx..(idx + key_length)],
            &data[(idx + key_length)..(idx + 2 * key_length)],
        )?;
    }

    let normalised_distance_sum = sum_distances as f32 / key_length as f32;
    let average_distance = normalised_distance_sum / num_blocks as f32;
    Ok(average_distance)
}

pub fn find_key_size(
    data: &[u8],
    key_range: (usize, usize),
    num_blocks: usize,
) -> Result<usize, Error> {
    let mut distances: Vec<(f32, usize)> = vec![];

    for key_length in key_range.0..=key_range.1 {
        let distance = get_average_distance(&data, key_length, num_blocks)?;

        distances.push((distance, key_length));
    }

    distances.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
    // println!("{:?}", distances);
    // let distances_only: Vec<usize> = distances.iter().map(|a| a.1).collect();
    Ok(distances[0].1)
}

fn get_slice(data: &[u8], start: usize, step: usize) -> Vec<u8> {
    let mut slice = vec![];
    let mut idx = start;
    while idx < data.len() {
        slice.push(data[idx]);
        idx += step;
    }

    slice
}

pub fn slice_by_byte(data: &[u8], key_size: usize) -> Vec<Vec<u8>> {
    let mut sliced_data = Vec::new();

    for key_idx in 0..key_size {
        sliced_data.push(get_slice(data, key_idx, key_size));
    }

    sliced_data
}

#[allow(dead_code)]
pub fn slice_by_byte_with_idx(data: &[u8], key_size: usize) -> BTreeMap<usize, Vec<u8>> {
    let mut sliced_data = BTreeMap::new();

    for key_idx in 0..key_size {
        sliced_data.insert(key_idx, get_slice(data, key_idx, key_size));
    }

    sliced_data
}
