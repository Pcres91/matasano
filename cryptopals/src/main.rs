#![allow(dead_code)]
use crypto::challenges::*;

fn main() {
    // match set1() {
    //     Ok(_) => (),
    //     Err(_) => println!("Errored in set1"),
    // }

    // match set2() {
    //     Ok(_) => (),
    //     Err(_) => println!("Errored in set2"),
    // }

    challenge7().expect("Didn't succeed");
}
