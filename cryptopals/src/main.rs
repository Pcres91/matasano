#![allow(dead_code)]
use std::io::Error;

use crypto::challenges::*;

fn main() -> Result<(), Error> {
    set1()?;

    set2()?;

    Ok(())
}
