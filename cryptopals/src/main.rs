#![allow(dead_code)]
use std::io::Error;

use crypto_challenges::challenges;

fn main() -> Result<(), Error> {
    // challenge1();
    // challenge2();
    // challenge3();
    // challenge4()?;
    // challenge5();
    // challenge6()?;
    // challenge7()?;
    // challenge8()?;

    challenges::challenge9()?;
    // challenge10()?;
    // challenge11()?;
    // challenges::challenge12()?;

    Ok(())
}
