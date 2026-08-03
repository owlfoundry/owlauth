use std::fmt;

use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

use super::DomainError;

pub(crate) const EMAIL_CANONICALIZATION_V1: i32 = 1;
pub(crate) const OTP_MIN_DIGITS: u8 = 6;
pub(crate) const OTP_MAX_DIGITS: u8 = 10;
pub(crate) const OTP_MAX_ATTEMPTS: u8 = 5;
pub(crate) const EMAIL_MAX_GENERATIONS: u8 = 5;
pub(crate) const EMAIL_MIN_RESEND_SECONDS: i64 = 30;
pub(crate) const EMAIL_MAX_VALIDITY_SECONDS: i64 = 600;
pub(crate) const MAGIC_MIN_ENTROPY_BYTES: usize = 16;
pub(crate) const EMAIL_MAX_BYTES: usize = 254;

/// A canonical mailbox is intentionally non-`Debug` and zeroizes its allocation.
///
/// Version 1 is deliberately conservative: only printable ASCII is admitted, the local part
/// is preserved byte-for-byte, and only the DNS domain is ASCII-lowercased. In particular it
/// performs no provider-specific dot/plus rewrite and no Unicode mailbox guessing.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CanonicalEmail(Zeroizing<String>);

impl CanonicalEmail {
    pub(crate) fn parse_v1(input: &str) -> Result<Self, EmailValidationError> {
        if input.is_empty()
            || input.len() > EMAIL_MAX_BYTES
            || !input.is_ascii()
            || input
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(EmailValidationError);
        }
        let (local, domain) = input.rsplit_once('@').ok_or(EmailValidationError)?;
        if local.is_empty()
            || local.len() > 64
            || domain.is_empty()
            || domain.len() > 253
            || local.contains('@')
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
            || domain.starts_with('.')
            || domain.ends_with('.')
            || domain.contains("..")
        {
            return Err(EmailValidationError);
        }
        let valid_local = local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'/'
                        | b'='
                        | b'?'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'{'
                        | b'|'
                        | b'}'
                        | b'~'
                        | b'.'
                )
        });
        let valid_domain = domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
        if !valid_local || !valid_domain || !domain.contains('.') {
            return Err(EmailValidationError);
        }
        Ok(Self(Zeroizing::new(format!(
            "{local}@{}",
            domain.to_ascii_lowercase()
        ))))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub(crate) const fn version() -> i32 {
        EMAIL_CANONICALIZATION_V1
    }
}

impl Drop for CanonicalEmail {
    fn drop(&mut self) {
        self.0.as_mut_str().zeroize();
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct EmailValidationError;

impl fmt::Debug for EmailValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid email address")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EmailProofPolicy {
    pub otp_enabled: bool,
    pub magic_link_enabled: bool,
    pub otp_digits: u8,
    pub otp_validity_seconds: i64,
    pub otp_max_attempts: u8,
    pub resend_after_seconds: i64,
    pub max_generations: u8,
    pub magic_validity_seconds: i64,
}

impl EmailProofPolicy {
    pub(crate) fn validate(self) -> Result<Self, DomainError> {
        if (!self.otp_enabled && !self.magic_link_enabled)
            || !(OTP_MIN_DIGITS..=OTP_MAX_DIGITS).contains(&self.otp_digits)
            || !(1..=OTP_MAX_ATTEMPTS).contains(&self.otp_max_attempts)
            || !(EMAIL_MIN_RESEND_SECONDS..=EMAIL_MAX_VALIDITY_SECONDS)
                .contains(&self.resend_after_seconds)
            || !(1..=EMAIL_MAX_GENERATIONS).contains(&self.max_generations)
            || !(30..=EMAIL_MAX_VALIDITY_SECONDS).contains(&self.otp_validity_seconds)
            || !(30..=EMAIL_MAX_VALIDITY_SECONDS).contains(&self.magic_validity_seconds)
        {
            return Err(DomainError::InvalidValue);
        }
        Ok(self)
    }

    pub(crate) fn effective_expiry(
        self,
        issued_at: OffsetDateTime,
        transaction_expires_at: OffsetDateTime,
    ) -> Result<OffsetDateTime, DomainError> {
        self.validate()?;
        if transaction_expires_at <= issued_at {
            return Err(DomainError::InvalidTransition);
        }
        let proof_seconds = if self.otp_enabled && self.magic_link_enabled {
            self.otp_validity_seconds.max(self.magic_validity_seconds)
        } else if self.otp_enabled {
            self.otp_validity_seconds
        } else {
            self.magic_validity_seconds
        };
        Ok(std::cmp::min(
            issued_at + Duration::seconds(proof_seconds),
            transaction_expires_at,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmailChallengeStatus {
    Pending,
    Consumed,
    Exhausted,
    Expired,
    Superseded,
    DeliveryUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EmailChallengeState {
    pub generation: u8,
    pub status: EmailChallengeStatus,
    pub otp_attempts: u8,
    pub otp_max_attempts: u8,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl EmailChallengeState {
    pub(crate) fn failed_otp(mut self, now: OffsetDateTime) -> Result<Self, DomainError> {
        self.require_pending(now)?;
        if self.otp_attempts >= self.otp_max_attempts {
            return Err(DomainError::InvalidTransition);
        }
        self.otp_attempts += 1;
        if self.otp_attempts == self.otp_max_attempts {
            self.status = EmailChallengeStatus::Exhausted;
        }
        Ok(self)
    }

    pub(crate) fn consume(mut self, now: OffsetDateTime) -> Result<Self, DomainError> {
        self.require_pending(now)?;
        self.status = EmailChallengeStatus::Consumed;
        Ok(self)
    }

    pub(crate) fn resend(
        mut self,
        now: OffsetDateTime,
        policy: EmailProofPolicy,
        transaction_expires_at: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        self.require_pending(now)?;
        policy.validate()?;
        if now < self.issued_at + Duration::seconds(policy.resend_after_seconds)
            || self.generation >= policy.max_generations
        {
            return Err(DomainError::InvalidTransition);
        }
        self.status = EmailChallengeStatus::Superseded;
        Ok(Self {
            generation: self.generation + 1,
            status: EmailChallengeStatus::Pending,
            otp_attempts: 0,
            otp_max_attempts: policy.otp_max_attempts,
            issued_at: now,
            expires_at: policy.effective_expiry(now, transaction_expires_at)?,
        })
    }

    fn require_pending(self, now: OffsetDateTime) -> Result<(), DomainError> {
        if self.status != EmailChallengeStatus::Pending || now >= self.expires_at {
            return Err(DomainError::InvalidTransition);
        }
        Ok(())
    }
}

pub(crate) fn generate_decimal_otp(digits: u8) -> Result<Zeroizing<String>, DomainError> {
    if !(OTP_MIN_DIGITS..=OTP_MAX_DIGITS).contains(&digits) {
        return Err(DomainError::InvalidValue);
    }
    // Rejection sampling avoids modulo bias while retaining leading zeroes.
    let mut result = Zeroizing::new(String::with_capacity(usize::from(digits)));
    while result.len() < usize::from(digits) {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| DomainError::InvalidValue)?;
        for value in random {
            if value < 250 && result.len() < usize::from(digits) {
                result.push(char::from(b'0' + value % 10));
            }
        }
        random.zeroize();
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EmailProofPolicy {
        EmailProofPolicy {
            otp_enabled: true,
            magic_link_enabled: true,
            otp_digits: 6,
            otp_validity_seconds: 600,
            otp_max_attempts: 5,
            resend_after_seconds: 30,
            max_generations: 5,
            magic_validity_seconds: 600,
        }
    }

    #[test]
    fn canonicalization_is_conservative_and_versioned() {
        let email = CanonicalEmail::parse_v1("User.Name+tag@EXAMPLE.COM").unwrap();
        assert_eq!(email.expose(), "User.Name+tag@example.com");
        assert_eq!(CanonicalEmail::version(), 1);
        for rejected in [
            " user@example.com",
            "user@example.com ",
            "user@@example.com",
            ".user@example.com",
            "user..name@example.com",
            "user@example",
            "user@-example.com",
            "usér@example.com",
        ] {
            assert!(CanonicalEmail::parse_v1(rejected).is_err());
        }
    }

    #[test]
    fn policy_can_only_tighten_v1_server_bounds() {
        assert!(policy().validate().is_ok());
        let mut invalid = policy();
        invalid.otp_digits = 5;
        assert_eq!(invalid.validate(), Err(DomainError::InvalidValue));
        invalid = policy();
        invalid.otp_max_attempts = 6;
        assert_eq!(invalid.validate(), Err(DomainError::InvalidValue));
        invalid = policy();
        invalid.max_generations = 6;
        assert_eq!(invalid.validate(), Err(DomainError::InvalidValue));
        invalid = policy();
        invalid.resend_after_seconds = 29;
        assert_eq!(invalid.validate(), Err(DomainError::InvalidValue));
    }

    #[test]
    fn expiry_never_outlives_fixed_transaction() {
        let issued = OffsetDateTime::UNIX_EPOCH + Duration::minutes(9);
        let transaction_end = OffsetDateTime::UNIX_EPOCH + Duration::minutes(10);
        assert_eq!(
            policy().effective_expiry(issued, transaction_end).unwrap(),
            transaction_end
        );
    }

    #[test]
    fn newest_generation_and_sibling_proofs_have_one_parent_winner() {
        let start = OffsetDateTime::UNIX_EPOCH;
        let parent = EmailChallengeState {
            generation: 1,
            status: EmailChallengeStatus::Pending,
            otp_attempts: 0,
            otp_max_attempts: 5,
            issued_at: start,
            expires_at: start + Duration::minutes(10),
        };
        let next = parent
            .resend(
                start + Duration::seconds(30),
                policy(),
                start + Duration::minutes(10),
            )
            .unwrap();
        assert_eq!(next.generation, 2);
        let consumed = next.consume(start + Duration::seconds(31)).unwrap();
        assert_eq!(
            consumed.consume(start + Duration::seconds(31)),
            Err(DomainError::InvalidTransition)
        );
    }

    #[test]
    fn fifth_failure_exhausts_and_fifth_generation_cannot_resend() {
        let start = OffsetDateTime::UNIX_EPOCH;
        let mut challenge = EmailChallengeState {
            generation: 5,
            status: EmailChallengeStatus::Pending,
            otp_attempts: 0,
            otp_max_attempts: 5,
            issued_at: start,
            expires_at: start + Duration::minutes(10),
        };
        for second in 1..=5 {
            challenge = challenge
                .failed_otp(start + Duration::seconds(second))
                .unwrap();
        }
        assert_eq!(challenge.status, EmailChallengeStatus::Exhausted);
        assert_eq!(
            EmailChallengeState {
                status: EmailChallengeStatus::Pending,
                ..challenge
            }
            .resend(
                start + Duration::seconds(31),
                policy(),
                start + Duration::minutes(10)
            ),
            Err(DomainError::InvalidTransition)
        );
    }

    #[test]
    fn generated_otp_is_fixed_decimal_with_leading_zero_space() {
        for digits in 6..=10 {
            let otp = generate_decimal_otp(digits).unwrap();
            assert_eq!(otp.len(), usize::from(digits));
            assert!(otp.bytes().all(|byte| byte.is_ascii_digit()));
        }
    }
}
