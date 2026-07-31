mod admission;
#[allow(
    dead_code,
    reason = "the HTTP-free authentication repository slice precedes Runtime composition"
)]
mod authentication;
mod control_lifecycle;
mod error;
mod infrastructure;
mod provisioning;
mod readiness;
mod runtime_auth;
mod runtime_security;
#[allow(
    dead_code,
    reason = "the HTTP-free session authority precedes Runtime composition"
)]
mod session_authority;
mod unit_of_work;

#[cfg(test)]
pub(crate) use admission::MonotonicClock;
pub(crate) use admission::{
    AdmissionBucket, AdmissionDecision, AdmissionDimension, AdmissionDimensionKind,
    AdmissionEndpoint, AdmissionRejectionReason, AdmissionService, DistributedAdmissionCounter,
    DistributedAdmissionError,
};
pub(crate) use authentication::{
    AdmittedProviderMethod, AuthenticationRepository, BindHostedBrowser, ClaimProviderCallback,
    ClaimedProviderExchange, CreateLoginTransaction, FailProviderExchange, LoginRevisionSnapshot,
    LoginTransactionRecord, ProtectedValue, SelectProviderMethod, VersionedDigest,
};
pub(crate) use control_lifecycle::{
    ApplicationSessionRecord, BrowserSessionRecord, ControlLifecyclePort, ControlLifecycleService,
    DisableProjectUser, ManagedSessionStatus, ProjectUserRecord, ProjectUserSessions,
    ProjectUserStatus, RevokeApplicationSession, RevokeBrowserSession,
};
pub(crate) use error::ApplicationError;
pub(crate) use infrastructure::{
    Clock, ConfigurationSecretStore, EntropySource, RequestDigester, SignerStore,
};
pub(crate) use provisioning::{
    ApplicationConfiguration, ApplicationProvisioningPort, ApplicationRecord, CreateApplication,
    CreateProject, CreateProvider, PrepareProvider, PreparedProvider, PreparedSigningKey,
    ProjectPolicyRecord, ProjectProvisioningPort, ProjectRecord, ProviderProvisioningPort,
    ProviderRecord, ProviderRecovery, ProvisioningInfrastructure, ProvisioningOperationState,
    ProvisioningService, ReplaceApplicationConfiguration, SigningKeyActivationCandidate,
    SigningKeyProvisioningPort, SigningKeyRecord, SigningKeyRecovery, UpdateApplication,
    UpdateProject, UpdateProjectPolicy,
};
pub(crate) use readiness::{
    JwksDocument, PublicApplicationConfig, PublicProvider, ReadinessPort, ReadinessService,
};
pub(crate) use runtime_auth::{
    BeginLogin, ConfirmProjectBrowserLogout, ConfirmSessionReuse, CredentialPair, ExchangeHandoff,
    HostedBootstrap, ProviderCallback, RefreshSession, RuntimeAuthService, SelectProvider,
};
pub(crate) use runtime_security::{
    AccessTokenSessionLookup, BrowserLogoutContext, CurrentSession, HostedInteraction,
    HostedProviderMethod, LoginStartContext, OpaquePurpose, ProtectedPurpose,
    ProviderAuthorizationRequest, ProviderCallbackRequest, ProviderExchangeError, ProviderIdentity,
    ProviderRuntimeContext, ProviderSecretResolver, RuntimeAuthorityRepository, RuntimeProtector,
    RuntimeSigner, UpstreamProviderClient, VerificationKey,
};
#[allow(
    unused_imports,
    reason = "the HTTP-free session authority precedes Runtime composition"
)]
pub(crate) use session_authority::{
    BindBrowserLogout, BrowserLogoutRecord, CommitHandoffExchange, CompleteProviderCallback,
    ConfirmBrowserLogout, ConfirmBrowserSessionReuse, HandoffPreparation, HandoffSessionRecord,
    IssuedHandoff, LogoutApplicationSession, PrepareBrowserLogout, PrepareHandoffExchange,
    PrepareRefreshRotation, RecoverProviderExchanges, RefreshPreparation, RefreshPreparationResult,
    RefreshRotationResult, RotateRefreshToken, SessionAuthorityRepository,
    VerifiedProviderIdentity,
};
pub(crate) use unit_of_work::{CompleteIdempotency, NewProject, ProjectUnitOfWork};
