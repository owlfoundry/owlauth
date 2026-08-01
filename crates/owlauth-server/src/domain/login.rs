use super::DomainError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoginTransactionStatus {
    AwaitingBrowserBinding,
    AwaitingMethodSelection,
    EmailAddressEntry,
    EmailChallengePending,
    ProviderAuthorizationStarted,
    ProviderExchangeInProgress,
    ProviderExchangeFailed,
    Authenticated,
    HandoffIssued,
    Completed,
    Expired,
    Cancelled,
}

impl LoginTransactionStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingBrowserBinding => "awaiting_browser_binding",
            Self::AwaitingMethodSelection => "awaiting_method_selection",
            Self::EmailAddressEntry => "email_address_entry",
            Self::EmailChallengePending => "email_challenge_pending",
            Self::ProviderAuthorizationStarted => "provider_authorization_started",
            Self::ProviderExchangeInProgress => "provider_exchange_in_progress",
            Self::ProviderExchangeFailed => "provider_exchange_failed",
            Self::Authenticated => "authenticated",
            Self::HandoffIssued => "handoff_issued",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn bind_browser(&mut self) -> Result<(), DomainError> {
        self.transition(Self::AwaitingMethodSelection)
    }

    pub(crate) fn select_provider(&mut self) -> Result<(), DomainError> {
        self.transition(Self::ProviderAuthorizationStarted)
    }

    pub(crate) fn select_email(&mut self) -> Result<(), DomainError> {
        self.transition(Self::EmailAddressEntry)
    }

    pub(crate) fn begin_email_challenge(&mut self) -> Result<(), DomainError> {
        self.transition(Self::EmailChallengePending)
    }

    pub(crate) fn confirm_session_reuse(&mut self) -> Result<(), DomainError> {
        self.transition(Self::HandoffIssued)
    }

    pub(crate) fn claim_provider_callback(&mut self) -> Result<(), DomainError> {
        self.transition(Self::ProviderExchangeInProgress)
    }

    pub(crate) fn authenticate(&mut self) -> Result<(), DomainError> {
        self.transition(Self::Authenticated)
    }

    pub(crate) fn fail_provider_exchange(&mut self) -> Result<(), DomainError> {
        self.transition(Self::ProviderExchangeFailed)
    }

    pub(crate) fn issue_handoff(&mut self) -> Result<(), DomainError> {
        self.transition(Self::HandoffIssued)
    }

    pub(crate) fn complete(&mut self) -> Result<(), DomainError> {
        self.transition(Self::Completed)
    }

    pub(crate) fn expire(&mut self) -> Result<(), DomainError> {
        self.transition(Self::Expired)
    }

    pub(crate) fn cancel(&mut self) -> Result<(), DomainError> {
        self.transition(Self::Cancelled)
    }

    fn transition(&mut self, next: Self) -> Result<(), DomainError> {
        let allowed = matches!(
            (*self, next),
            (
                Self::AwaitingBrowserBinding,
                Self::AwaitingMethodSelection | Self::Expired | Self::Cancelled
            ) | (
                Self::AwaitingMethodSelection,
                Self::ProviderAuthorizationStarted
                    | Self::EmailAddressEntry
                    | Self::HandoffIssued
                    | Self::Expired
                    | Self::Cancelled
            ) | (
                Self::EmailAddressEntry,
                Self::EmailChallengePending | Self::Expired | Self::Cancelled
            ) | (
                Self::EmailChallengePending,
                Self::Authenticated | Self::Expired | Self::Cancelled
            ) | (
                Self::ProviderAuthorizationStarted,
                Self::ProviderExchangeInProgress | Self::Expired | Self::Cancelled
            ) | (
                Self::ProviderExchangeInProgress,
                Self::Authenticated | Self::ProviderExchangeFailed
            ) | (Self::Authenticated, Self::HandoffIssued | Self::Expired)
                | (Self::HandoffIssued, Self::Completed | Self::Expired)
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
    fn provider_login_follows_the_one_way_state_machine() {
        let mut status = LoginTransactionStatus::AwaitingBrowserBinding;
        status.bind_browser().unwrap();
        status.select_provider().unwrap();
        status.claim_provider_callback().unwrap();
        status.authenticate().unwrap();
        status.issue_handoff().unwrap();
        status.complete().unwrap();

        assert_eq!(status, LoginTransactionStatus::Completed);
        assert_eq!(status.expire(), Err(DomainError::InvalidTransition));
    }

    #[test]
    fn email_selection_is_one_way_and_converges_on_authentication() {
        let mut status = LoginTransactionStatus::AwaitingMethodSelection;
        status.select_email().unwrap();
        status.begin_email_challenge().unwrap();
        status.authenticate().unwrap();
        status.issue_handoff().unwrap();
        assert_eq!(status, LoginTransactionStatus::HandoffIssued);
        assert_eq!(
            status.select_provider(),
            Err(DomainError::InvalidTransition)
        );
    }

    #[test]
    fn method_selection_and_session_reuse_compete_on_one_state() {
        let mut selected = LoginTransactionStatus::AwaitingMethodSelection;
        selected.select_provider().unwrap();
        assert_eq!(
            selected.confirm_session_reuse(),
            Err(DomainError::InvalidTransition)
        );

        let mut reused = LoginTransactionStatus::AwaitingMethodSelection;
        reused.confirm_session_reuse().unwrap();
        assert_eq!(
            reused.select_provider(),
            Err(DomainError::InvalidTransition)
        );
    }

    #[test]
    fn claimed_callback_can_only_finish_or_fail_terminally() {
        let mut status = LoginTransactionStatus::ProviderAuthorizationStarted;
        status.claim_provider_callback().unwrap();
        assert_eq!(
            status.claim_provider_callback(),
            Err(DomainError::InvalidTransition)
        );
        status.fail_provider_exchange().unwrap();
        assert_eq!(status, LoginTransactionStatus::ProviderExchangeFailed);
        assert_eq!(status.cancel(), Err(DomainError::InvalidTransition));
    }

    #[test]
    fn expiry_and_cancellation_do_not_reactivate() {
        let mut expired = LoginTransactionStatus::AwaitingBrowserBinding;
        expired.expire().unwrap();
        assert_eq!(expired.bind_browser(), Err(DomainError::InvalidTransition));

        let mut cancelled = LoginTransactionStatus::AwaitingMethodSelection;
        cancelled.cancel().unwrap();
        assert_eq!(
            cancelled.select_provider(),
            Err(DomainError::InvalidTransition)
        );
    }
}
