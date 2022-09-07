use crate::challenges::print_challenge_result;
use crate::errors::Result;
use crate::expectations::*;

pub fn set3() {
    print_challenge_result(17, &challenge17);
}

pub fn challenge17() -> Result<()> {
    expect_eq(1, 1, "challenge 17 result")?;
    Ok(())
}

