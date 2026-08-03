use sha2::{Digest, Sha256};

#[test]
fn committed_migration_checksums_are_stable() {
    let migrations: &[(&[u8], &str)] = &[
        (
            include_bytes!("../../migrations/20260730010000_policy_signing_safety.sql"),
            "fb13305cff774af1e65e321869c85afff990c59d8c1563dee0dc29368d71c54f",
        ),
        (
            include_bytes!("../../migrations/20260801010000_passwordless_email.sql"),
            "189f2627a586bd39195bda35bfb9830075ebf745efce1c48601a925195860f13",
        ),
        (
            include_bytes!("../../migrations/20260801020000_managed_provider_connections.sql"),
            "4ca7d36bd473573890986f21afc2e9a5b703620c0b7705a7d2bc474cd090963a",
        ),
        (
            include_bytes!("../../migrations/20260801030000_identity_lifecycle_and_projection.sql"),
            "fd4fcf440f3cb5ca31fbd64e2b3bab54b301a8121f40d9b4156813e33fef7957",
        ),
    ];

    for (bytes, expected) in migrations {
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            *expected,
            "released migration history must be extended with a later migration, never rewritten"
        );
    }
}
