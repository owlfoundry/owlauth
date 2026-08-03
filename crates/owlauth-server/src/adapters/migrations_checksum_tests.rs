use sha2::{Digest, Sha256};

#[test]
fn committed_initial_migration_checksum_is_stable() {
    let bytes = include_bytes!("../../migrations/20260803000000_initial.sql");
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        "80256fafc981565ae414e3ea3ab4cc0779d175dff96b5f546d6b5ba6b756fe5e",
        "the initial migration is frozen once the first server release is published"
    );
}
