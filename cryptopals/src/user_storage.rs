use crate::aes;
use std::io::{Error, ErrorKind};

pub static mut PROFILE_STORAGE: ProfileStorage = ProfileStorage {
    profiles: Vec::new(),
};
pub static mut NEXT_UID: u32 = 0;
pub const RND_KEY: [u8; 16] = [
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

    pub fn add_from_hash(&mut self, hash: &[u8]) -> Result<(), Error> {
        let cookie = aes::decrypt_ecb_128(hash, &RND_KEY)?;

        self.profiles
            .push(parse_cookie(std::str::from_utf8(&cookie).unwrap())?);

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

pub fn parse_cookie(cookie: &str) -> Result<Profile, Error> {
    let tokens: Vec<&str> = cookie.split(&['=', '&'][..]).collect();

    // @TODO: change these all to return Error
    assert!(tokens.len() == 6);

    assert!(tokens[0] == "email");
    assert!(tokens[1].contains('@'));
    assert!(tokens[2] == "uid");
    assert!(tokens[4] == "role");
    assert!(tokens[5] == "Admin" || tokens[5] == "User");

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
        hash: aes::encrypt_ecb_128(&cookie.as_bytes(), &RND_KEY)?,
    })
}

/// # Safety
pub unsafe fn profile_for(email: &str) -> Result<Vec<u8>, Error> {
    if email.contains('&') || email.contains('=') {
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

    // let new_profile = Profile {
    //     email: email.to_string(),
    //     uid: NEXT_UID,
    //     role: ProfileRole::User,
    //     encoded_str: output.to_string(),
    //     hash: aes::encrypt_ecb_128(&output[..].as_bytes(), &RND_KEY)?,
    // };

    // PROFILE_STORAGE.profiles.push(new_profile.clone());
    // NEXT_UID += 1;

    Ok(aes::encrypt_ecb_128(&output[..].as_bytes(), &RND_KEY)?)
}
