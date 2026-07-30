use super::DomainError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SigningKeyState {
    Provisioning,
    Published,
    Active,
    Retiring,
    Retired,
    Revoked,
    Abandoned,
}

impl SigningKeyState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Published => "published",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Abandoned => "abandoned",
        }
    }

    pub(crate) fn transition(&mut self, next: Self) -> Result<(), DomainError> {
        let allowed = matches!(
            (*self, next),
            (
                Self::Provisioning,
                Self::Published | Self::Abandoned | Self::Revoked
            ) | (
                Self::Published,
                Self::Active | Self::Abandoned | Self::Revoked
            ) | (Self::Active, Self::Retiring | Self::Revoked)
                | (Self::Retiring, Self::Retired | Self::Revoked)
        );
        if !allowed {
            return Err(DomainError::InvalidTransition);
        }
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_lifecycle_is_ordered_and_terminal_states_stay_terminal() {
        let mut state = SigningKeyState::Provisioning;
        state.transition(SigningKeyState::Published).unwrap();
        state.transition(SigningKeyState::Active).unwrap();
        state.transition(SigningKeyState::Retiring).unwrap();
        assert_eq!(state, SigningKeyState::Retiring);
        state.transition(SigningKeyState::Retired).unwrap();
        assert_eq!(state, SigningKeyState::Retired);
        assert_eq!(
            state.transition(SigningKeyState::Active),
            Err(DomainError::InvalidTransition)
        );

        let mut compromised = SigningKeyState::Active;
        compromised.transition(SigningKeyState::Revoked).unwrap();
        assert_eq!(compromised, SigningKeyState::Revoked);
    }
}
