pub static mut PROFILE_STORAGE: ProfileStorage = ProfileStorage {
    profiles: Vec::new(),
};

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
}

pub fn parse_cookie(cookie: &str) {
    assert!(cookie.contains("email"));
    assert!(cookie.contains("email"));
}

pub static mut NEXT_UID: u32 = 0;

pub unsafe fn profile_for(email: &str) -> String {
    let new_profile = Profile {
        email: email.to_string(),
        uid: NEXT_UID,
        role: ProfileRole::User,
    };

    let output = format!(
        "email={}&uid={}&role={:?}",
        new_profile.email, new_profile.uid, new_profile.role
    );

    PROFILE_STORAGE.profiles.push(new_profile);
    NEXT_UID += 1;

    output
}
