use crate::aes;
use std::io::{Error, ErrorKind};

pub static mut PROFILE_STORAGE: ProfileStorage = ProfileStorage {
    profiles: Vec::new(),
};
pub static mut NEXT_UID: u32 = 0;
pub const RND_KEY: [u8; 16] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

pub struct ProfileStorage {
    pub profiles: Vec<Profile>,
}

impl ProfileStorage {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ProfileRole {
    User,
    Admin,
}

pub struct Profile {
    pub email: String,
    pub uid: u32,
    pub role: ProfileRole,
    pub encoded_str: String,
    pub hash: Vec<u8>,
}

pub fn parse_cookie(cookie: &str) {
    assert!(cookie.contains("email"));
    assert!(cookie.contains("email"));
}

pub unsafe fn profile_for(email: &str) -> Result<String, Error> {
    if email.contains('@') || email.contains('=') {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Can't contain metacharacters in email",
        ));
    }

    let output = format!(
        "email={}&uid={}&role={:?}",
        email,
        NEXT_UID,
        ProfileRole::User
    );

    let new_profile = Profile {
        email: email.to_string(),
        uid: NEXT_UID,
        role: ProfileRole::User,
        encoded_str: output.to_string(),
        hash: aes::encrypt_ecb_128(&output[..].as_bytes(), &RND_KEY)?,
    };

    PROFILE_STORAGE.profiles.push(new_profile);
    NEXT_UID += 1;

    Ok(output)
}
