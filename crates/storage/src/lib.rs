#![forbid(unsafe_code)]

use owlauth_domain::UserId;

/// Minimal storage boundary for server-side user records.
pub trait UserStore {
    /// Returns whether the user exists.
    fn contains(&self, user_id: &UserId) -> bool;
}
