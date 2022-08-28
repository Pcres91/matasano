use bitstream_io::{BigEndian, BitRead, BitReader, BitWrite, BitWriter};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::error;
use std::fmt;
use std::io::Cursor;

use crate::expect_eq;
use crate::expect_true;
use crate::expectations::{expect_eq_impl, expect_true_impl};

extern crate hex;
extern crate num_traits;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
pub struct InvalidData;

impl error::Error for InvalidData {}

impl fmt::Display for InvalidData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Data was invalid")
    }
}

pub struct Wrap(pub Vec<u8>);

impl fmt::Display for Wrap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &byte in &self.0 {
            write!(f, "{}", byte as char)?;
        }
        Ok(())
    }
}

/// converts a string of hex into bytes
/// ie, "0123afbe" -> vec![0x01, 0x23, 0xaf, 0xbe]
pub fn hex_string_to_vec_u8(bytes: &[u8]) -> Result<Vec<u8>> {
    match hex::decode(bytes) {
        Ok(res) => Ok(res),
        Err(hex_error) => Err(hex_error.into()),
    }
}

pub fn xor_bytes(left: &[u8], right: &[u8]) -> Result<Vec<u8>> {
    if left.len() != right.len() {
        return Err(InvalidData.into());
    }

    let mut res: Vec<u8> = Vec::new();

    for i in 0..left.len() {
        res.push(left[i] ^ right[i]);
    }

    Ok(res)
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

/// XOR each character in a buffer with a single character key.
pub fn single_byte_xor(cipher: &[u8], key: u8) -> Vec<u8> {
    let mut res = Vec::new();

    for message_byte in cipher {
        res.push(message_byte ^ key);
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

/// list of the most frequent ASCII characters
/// without characters or punctuation. For long texts
/// this should be sufficient.
/// Shamelessly stolen from
/// http://www.fitaly.com/board/domper3/posts/136.html
pub fn score_text(msg: &[u8]) -> i32 {
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

/// return the character with the highest character "score" when XOR'd with the buffer
pub fn find_best_character_key(cipher: &[u8]) -> u8 {
    find_best_character_key_and_score(cipher).key
}

pub struct ScoredText {
    pub key: u8,
    pub score: i32,
    pub plaintext: Vec<u8>,
}

impl From<(u8, i32, Vec<u8>)> for ScoredText {
    fn from(f: (u8, i32, Vec<u8>)) -> Self {
        ScoredText {
            key: f.0,
            score: f.1,
            plaintext: f.2,
        }
    }
}

/// same as find_best_character_key, but also return the score.
/// Returned as (key, score)
/// TODO use enumerate to store key value
pub fn find_best_character_key_and_score(cipher: &[u8]) -> ScoredText {
    (0..0xffu8)
        .into_par_iter()
        .map(|key| (key, single_byte_xor(&cipher, key)))
        .map(|(key, decoded_message)| (key, score_text(&decoded_message), decoded_message))
        .max_by(|left, right| left.1.cmp(&right.1))
        .unwrap()
        .into()
}

/// cycle through the key, XOR'ing the text with each subsequent character of the key
pub fn repeated_xor(text: &[u8], key: &[u8]) -> Vec<u8> {
    fn xor_with_key(chunk: &[u8], key: &[u8]) -> Vec<u8> {
        chunk
            .par_iter()
            .zip(key.par_iter())
            .map(|(c, key_char)| c ^ key_char)
            .collect()
    }

    text.par_chunks(key.len())
        .map(|chunk| xor_with_key(chunk, key))
        .flatten()
        .collect()
}

/// Computes the distance between two strings on a per-bit (not byte) basis
pub fn hamming_distance(string1: &[u8], string2: &[u8]) -> Result<usize> {
    expect_eq!(
        string1.len(),
        string2.len(),
        "Hamming Distance can only be calculated between two strings of equal length"
    )?;

    let mut cur1 = Cursor::new(&string1);
    let mut read1 = BitReader::endian(&mut cur1, BigEndian);
    let mut cur2 = Cursor::new(&string2);
    let mut read2 = BitReader::endian(&mut cur2, BigEndian);

    let mut distance = 0;
    for _ in 0..(string1.len() * 8/* per bit, not byte */) {
        let res = read1.read_bit()? ^ read2.read_bit()?;
        if res {
            distance += 1
        };
    }
    Ok(distance)
}

/// get the average hamming distance between blocks of key_length size, for num_blocks
pub fn get_average_distance(data: &[u8], key_length: usize, num_blocks: usize) -> Result<f32> {
    expect_true!(num_blocks * key_length <= data.len(), format!("Not enough data for the num blocks requested. Data length: {}, num_blocks: {}, key_length: {}",
        data.len(), num_blocks, key_length).as_str())?;

    let sum_distances = (0..(num_blocks - 1) * key_length)
        .step_by(key_length)
        .par_bridge()
        .fold(
            || 0usize,
            |acc, idx| {
                acc + hamming_distance(
                    &data[idx..(idx + key_length)],
                    &data[(idx + key_length)..(idx + 2 * key_length)],
                )
                .unwrap()
            },
        )
        .sum::<usize>();

    let normalised_distance_sum = sum_distances as f32 / key_length as f32;
    let average_distance = normalised_distance_sum / num_blocks as f32;
    Ok(average_distance)
}

/// Find the key size with the lowest average hamming distance between each block. Averaged over num_blocks blocks
pub fn find_key_size(data: &[u8], key_range: (usize, usize), num_blocks: usize) -> Result<usize> {
    Ok((key_range.0..key_range.1)
        .into_par_iter()
        .map(|key_length| {
            (
                key_length,
                get_average_distance(&data, key_length, num_blocks).unwrap(),
            )
        })
        .min_by(|left, right| left.1.partial_cmp(&right.1).unwrap())
        .unwrap()
        .0)
}

/// TODO: what is this? If necessary surely this can be simplified
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

pub fn prefix_with_rnd_bytes(range: (usize, usize), text: &[u8]) -> Vec<u8> {
    extern crate rand;
    use rand::prelude::*;

    let mut rng = rand::thread_rng();

    let num_random_bytes = rng.gen_range(range.0..range.1);

    // println!("rnd bytes: {}", num_random_bytes);

    let mut res = vec![0u8; num_random_bytes];
    rng.fill_bytes(&mut res);

    res.extend_from_slice(text);

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        let string1 = "this is a test";
        let string2 = "wokka wokka!!!";

        let res = hamming_distance(&string1.as_bytes(), &string2.as_bytes()).unwrap();

        assert_eq!(37, res);
    }
}
