extern crate crypto;

use crypto::aes;
use crypto::user_storage::*;

#[test]
fn test_adding_a_profile() {
    unsafe {
        let out = profile_for("test@tester.com").unwrap();
        PROFILE_STORAGE.add_from_hash(&out).unwrap();
        assert_eq!(PROFILE_STORAGE.profiles.len(), 1);

        let user_prof = &PROFILE_STORAGE.profiles[0];
        assert_eq!(user_prof.email, "test@tester.com");
        assert_eq!(user_prof.uid, 0);
        assert_eq!(user_prof.role, ProfileRole::User);
    }
}

#[test]
fn test_return_from_profile_for() {
    unsafe {
        let out = profile_for("next@tester.com").unwrap();
        use std::str::from_utf8;
        assert_eq!(
            from_utf8(&aes::decrypt_ecb_128(&out, &RND_KEY).unwrap()).unwrap(),
            "email=next@tester.com&uid=0&role=User"
        );
    }
}
