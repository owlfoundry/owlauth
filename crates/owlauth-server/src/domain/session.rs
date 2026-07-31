use super::DomainError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrowserSessionStatus {
    Active,
    Terminated,
    Expired,
}

impl BrowserSessionStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Terminated => "terminated",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn terminate(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Terminated;
        Ok(())
    }

    pub(crate) fn expire(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Expired;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandoffStatus {
    Issued,
    Consumed,
    Expired,
}

impl HandoffStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn consume(&mut self) -> Result<(), DomainError> {
        if *self != Self::Issued {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Consumed;
        Ok(())
    }

    pub(crate) fn expire(&mut self) -> Result<(), DomainError> {
        if *self != Self::Issued {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Expired;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplicationSessionStatus {
    Active,
    Revoked,
    Expired,
}

impl ApplicationSessionStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn revoke(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Revoked;
        Ok(())
    }

    pub(crate) fn expire(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Expired;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshFamilyStatus {
    Active,
    Revoked,
    Expired,
}

impl RefreshFamilyStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn revoke(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Revoked;
        Ok(())
    }

    pub(crate) fn expire(&mut self) -> Result<(), DomainError> {
        if *self != Self::Active {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Expired;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshGenerationStatus {
    Current,
    Consumed,
}

impl RefreshGenerationStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Consumed => "consumed",
        }
    }

    pub(crate) fn present(&mut self) -> RefreshPresentationDecision {
        match self {
            Self::Current => {
                *self = Self::Consumed;
                RefreshPresentationDecision::RotateSuccessor
            }
            Self::Consumed => RefreshPresentationDecision::RevokeFamilyForReplay,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefreshPresentationDecision {
    RotateSuccessor,
    RevokeFamilyForReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrowserLogoutStatus {
    Prepared,
    CsrfBound,
    Consumed,
    Expired,
}

impl BrowserLogoutStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::CsrfBound => "csrf_bound",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn bind_csrf(&mut self) -> Result<(), DomainError> {
        if *self != Self::Prepared {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::CsrfBound;
        Ok(())
    }

    pub(crate) fn consume(&mut self) -> Result<(), DomainError> {
        if *self != Self::CsrfBound {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Consumed;
        Ok(())
    }

    pub(crate) fn expire(&mut self) -> Result<(), DomainError> {
        if !matches!(*self, Self::Prepared | Self::CsrfBound) {
            return Err(DomainError::InvalidTransition);
        }
        *self = Self::Expired;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_and_application_sessions_are_terminal_after_shutdown() {
        let mut browser = BrowserSessionStatus::Active;
        browser.terminate().unwrap();
        assert_eq!(browser.expire(), Err(DomainError::InvalidTransition));

        let mut application = ApplicationSessionStatus::Active;
        application.revoke().unwrap();
        assert_eq!(application.revoke(), Err(DomainError::InvalidTransition));

        let mut family = RefreshFamilyStatus::Active;
        family.expire().unwrap();
        assert_eq!(family.revoke(), Err(DomainError::InvalidTransition));
    }

    #[test]
    fn handoff_is_consumed_once() {
        let mut handoff = HandoffStatus::Issued;
        handoff.consume().unwrap();
        assert_eq!(handoff.consume(), Err(DomainError::InvalidTransition));
        assert_eq!(handoff.expire(), Err(DomainError::InvalidTransition));
    }

    #[test]
    fn consumed_refresh_generation_demands_family_revocation() {
        let mut generation = RefreshGenerationStatus::Current;
        assert_eq!(
            generation.present(),
            RefreshPresentationDecision::RotateSuccessor
        );
        assert_eq!(generation, RefreshGenerationStatus::Consumed);
        assert_eq!(
            generation.present(),
            RefreshPresentationDecision::RevokeFamilyForReplay
        );
    }

    #[test]
    fn browser_logout_requires_bound_csrf_and_is_one_use() {
        let mut logout = BrowserLogoutStatus::Prepared;
        assert_eq!(logout.consume(), Err(DomainError::InvalidTransition));
        logout.bind_csrf().unwrap();
        logout.consume().unwrap();
        assert_eq!(logout.consume(), Err(DomainError::InvalidTransition));
        assert_eq!(logout.expire(), Err(DomainError::InvalidTransition));
    }
}
