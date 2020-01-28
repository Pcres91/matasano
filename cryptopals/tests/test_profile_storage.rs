extern crate crypto;

use crypto::user_storage::*;

#[test]
fn test_adding_a_profile() {
    unsafe {
        let _out = profile_for("test@tester.com");
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
        let out = profile_for("next@tester.com");
        assert_eq!(
            out,
            format!("email=next@tester.com&uid={}&role=User", NEXT_UID - 1)
        );
    }
}
