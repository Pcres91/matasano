use crate::{
    aes,
    aes::ecb,
    common::{
        errors::{Result, UserStorageError},
        expectations::*,
    },
};

pub static mut PROFILE_STORAGE: ProfileStorage = ProfileStorage {
    profiles: Vec::new(),
};
pub static mut NEXT_UID: u32 = 0;
pub const RND_KEY: [u8; aes::BLOCK_SIZE] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

#[derive(Debug, Default)]
pub struct ProfileStorage {
    pub profiles: Vec<Profile>,
}

impl ProfileStorage {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }

    pub fn add_from_hash(&mut self, hash: &[u8]) -> Result<()> {
        let cookie = ecb::decrypt_128(hash, &RND_KEY)?;

        self.profiles
            .push(parse_cookie(std::str::from_utf8(&cookie)?)?);

        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProfileRole {
    User,
    Admin,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub email: String,
    pub uid: u32,
    pub role: ProfileRole,
    pub encoded_str: String,
    pub hash: Vec<u8>,
}

pub fn parse_cookie(cookie: &str) -> Result<Profile> {
    let tokens: Vec<&str> = cookie.split(&['=', '&'][..]).collect();

    expect_eq(6, tokens.len(), "token length")?;

    expect_eq("email", tokens[0], "token positional check")?;
    expect_true(tokens[1].contains('@'), "token positional check")?;
    expect_eq("uid", tokens[2], "token positional check")?;
    expect_eq("role", tokens[4], "token positional check")?;
    expect_true(
        tokens[5] == "Admin" || tokens[5] == "User",
        "token positional check",
    )?;

    let new_role = if tokens[5] == "Admin" {
        ProfileRole::Admin
    } else {
        ProfileRole::User
    };

    Ok(Profile {
        email: tokens[1].to_string(),
        uid: tokens[3].parse::<u32>().unwrap(),
        role: new_role,
        encoded_str: cookie.to_string(),
        hash: ecb::encrypt_128(&cookie.as_bytes(), &RND_KEY)?,
    })
}

/// TODO: Safety
pub unsafe fn create_hash_profile_for(email: &str) -> Result<Vec<u8>> {
    if email.contains('&') || email.contains('=') {
        return Err(UserStorageError::InvalidEmailFormat.into());
    }

    let output = format!(
        "email={}&uid={}&role={:?}",
        email,
        NEXT_UID,
        ProfileRole::User
    );

    match ecb::encrypt_128(&output[..].as_bytes(), &RND_KEY) {
        Ok(res) => Ok(res),
        Err(error) => Err(error.into()),
    }
}
