use sha2::{Digest, Sha256};

#[test]
fn committed_policy_signing_safety_migration_checksum_is_stable() {
    let bytes = include_bytes!("../../migrations/20260730010000_policy_signing_safety.sql");
    let actual = format!("{:x}", Sha256::digest(bytes));
    assert_eq!(
        actual, "fb13305cff774af1e65e321869c85afff990c59d8c1563dee0dc29368d71c54f",
        "released migration history must be extended with a later migration, never rewritten"
    );
}
