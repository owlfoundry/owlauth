mod admission;
#[allow(
    dead_code,
    reason = "the HTTP-free authentication repository slice precedes Runtime composition"
)]
mod authentication;
mod control_lifecycle;
mod email_control;
mod error;
#[allow(
    dead_code,
    reason = "identity mutation ports precede PostgreSQL and HTTP composition"
)]
mod identity_mutation;
mod infrastructure;
#[allow(
    dead_code,
    reason = "mail worker and SMTP adapter are composed in Runtime-capable modes"
)]
mod mail;
mod managed_connection;
mod managed_reauthorization;
#[allow(
    dead_code,
    reason = "passwordless email ports are consumed by Runtime and PostgreSQL"
)]
mod passwordless_email;
mod provider_callback;
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
    ClaimedProviderExchange, CreateLoginTransaction, DenyProviderCallback, FailProviderExchange,
    LoginRevisionSnapshot, LoginTransactionRecord, ProtectedValue, SelectProviderMethod,
    VersionedDigest,
};
pub(crate) use control_lifecycle::{
    ApplicationSessionRecord, BrowserSessionRecord, ControlLifecyclePort, ControlLifecycleService,
    DisableProjectUser, ManagedSessionStatus, ProjectUserIdentityKind, ProjectUserIdentityRecord,
    ProjectUserIdentityStatus, ProjectUserRecord, ProjectUserSessions, ProjectUserStatus,
    RevokeApplicationSession, RevokeBrowserSession,
};
pub(crate) use email_control::{
    CreateSmtpConfiguration, DeploymentSmtpGenerationRecord, EmailControlPort, EmailControlService,
    EmailPolicyRecord, PrepareSmtpConfiguration, PrepareSmtpTest, PreparedSmtpConfiguration,
    SmtpConfigurationRecord, SmtpControlStatus, SmtpControlTlsMode, SmtpTestOperationRecord,
    SmtpTestState, UpdateEmailPolicy,
};
pub(crate) use error::ApplicationError;
#[allow(
    unused_imports,
    reason = "identity mutation PostgreSQL and HTTP composition follows the application port"
)]
pub(crate) use identity_mutation::{
    BeginIdentityMutationEmailChallenge, CandidateEvidenceMaterial, ClaimIdentityMutationProvider,
    CommitIdentityMutationEmailGeneration, CompleteIdentityMutationEmailProof,
    ConfirmIdentityMutationReady, ControlIdentityMutationRepository, CreateIdentityMutation,
    CreateIdentityMutationResult, CreatedIdentityMutation,
    EstablishIdentityMutationMagicTransferContext, EstablishedIdentityMutationMagicTransferContext,
    ExpectedIdentity, ExpectedUser, FailIdentityMutationProvider,
    IdentityMutationAdmittedProviderProfile, IdentityMutationBindingsDisposition,
    IdentityMutationBootstrap, IdentityMutationCallbackOutcome, IdentityMutationCandidate,
    IdentityMutationCandidateEvidenceContext, IdentityMutationCandidateEvidenceEnvelope,
    IdentityMutationCandidateKind, IdentityMutationCandidateVerifier,
    IdentityMutationControlConfirmationPreparation, IdentityMutationControlService,
    IdentityMutationCreateOperation, IdentityMutationDigestVersions,
    IdentityMutationDurableEmailProtector, IdentityMutationEmailCandidate,
    IdentityMutationEmailChallengeAccepted, IdentityMutationEmailCompletionDecision,
    IdentityMutationEmailGenerationPreparation, IdentityMutationEmailProofDecision,
    IdentityMutationEmailProofKey, IdentityMutationEmailProofMaterial,
    IdentityMutationExistingEmailEvidence, IdentityMutationMagicTransferGate,
    IdentityMutationMagicTransferOwner, IdentityMutationPrimarySourceDisposition,
    IdentityMutationProofAuthoritySelection, IdentityMutationProofMaterialProtector,
    IdentityMutationProofMethodKind, IdentityMutationProviderCallback,
    IdentityMutationProviderCandidate, IdentityMutationProviderCapability,
    IdentityMutationProviderDenial, IdentityMutationProviderDigestVersions,
    IdentityMutationProviderRegistrationEvidence, IdentityMutationProviderSlotAuthority,
    IdentityMutationRecord, IdentityMutationRuntimeService, IdentityMutationSafeSlot,
    IdentityMutationSessionsDisposition, IdentityMutationSlotRecord, IdentityMutationTargetIssuer,
    IdentityMutationTargetVerifier, IdentityMutationView, PrepareIdentityMutationEmailGeneration,
    PreparedIdentityMutationCandidate, PreparedIdentityMutationConfirmation,
    PreparedIdentityMutationCreate, PreparedIdentityMutationProviderCompletion,
    ProviderProofObservation, ResolveIdentityMutationMagicTransferContext,
    ResolvedIdentityMutationMagicTransferContext, RuntimeIdentityMutationRepository,
    StartIdentityMutationMethod, StartedIdentityMutationMethod, SubmitIdentityMutationEmailProof,
    VerifiedIdentityMutationEmailChallenge, VerifyIdentityMutationEmailProof,
    VerifyIdentityMutationMagicTransferProof, VerifyRawIdentityMutationEmailProof,
};
pub(crate) use infrastructure::{
    Clock, ConfigurationSecretProvisioner, ConfigurationSecretStore, EntropySource,
    RequestDigester, SignerStore,
};
#[allow(
    unused_imports,
    reason = "mail worker composition follows the durable outbox repository"
)]
pub(crate) use mail::{
    ClaimedMailJob, ClaimedSmtpCredentialCleanup, ClaimedSmtpSecretCleanup, ClaimedSmtpTestJob,
    DeploymentSmtpDesiredStatus, DeploymentSmtpGeneration, DeploymentSmtpRegistry, MAX_CNAME_DEPTH,
    MAX_MAINTENANCE_ROWS_PER_TICK, MailChallengeOwner, MailOutboxRepository, MailRetryState,
    MailSubmission, MailTransport, MailTransportOutcome, MailWorker, SHORT_TERM_DATA_RETENTION,
    SmtpCredentialResolver, SmtpEndpoint, SmtpTlsMode, classify_smtp_status, mail_context,
    validate_private_relay_allowlist,
};
#[allow(
    unused_imports,
    reason = "managed connection composition and join phase use this contract"
)]
pub(crate) use managed_connection::{
    BoundedManagedProfile, ClaimedManagedCredential, ConnectionGuard, ManagedConnectionMetadata,
    ManagedConnectionRepository, ManagedConnectionService, ManagedCredentialContext,
    ManagedCredentialProtector, ManagedInteractionCleanupService, ManagedProfileAdapter,
    PreparedRenewal, ProviderReadError, ProviderRenewalResult, ProviderRevocationResult,
    RenewalOperationState, RenewedCredential, SuccessorProfileClaim,
};
#[cfg(test)]
pub(crate) use managed_reauthorization::ManagedAdapterCapabilitySnapshot;
pub(crate) use managed_reauthorization::{
    ClaimManagedReauthorization, CompletedManagedReauthorization, CreateManagedReauthorization,
    CreateManagedReauthorizationResult, FailManagedReauthorization, ManagedReauthorizationCallback,
    ManagedReauthorizationCallbackOutcome, ManagedReauthorizationControlService,
    ManagedReauthorizationDenial, ManagedReauthorizationDigestVersions,
    ManagedReauthorizationRecord, ManagedReauthorizationRepository,
    ManagedReauthorizationRuntimeService, ManagedReauthorizationStatus,
    ManagedReauthorizationTargetIssuer, ManagedReauthorizationTargetVerifier,
    ManagedReauthorizationView, PreparedManagedReauthorizationCreate, StartManagedReauthorization,
};
#[allow(unused_imports, reason = "passwordless email integration is additive")]
pub(crate) use passwordless_email::{
    AdmittedEmailMethod, CommitEmailGeneration, CompleteEmailProof, EmailGenerationPreparation,
    EmailIdentityAliasAuthority, EmailProofDecision, EmailProofKind, EstablishMagicTransferContext,
    PasswordlessEmailRepository, ResolveMagicTransferContext, ResolvedMagicTransferContext,
    SelectEmailMethod, VerifiedEmailChallenge, VerifyEmailProof,
};
pub(crate) use provider_callback::{ProviderCallbackOwner, ProviderCallbackOwnerResolver};
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
    BeginEmailChallenge, BeginLogin, ConfirmProjectBrowserLogout, ConfirmSessionReuse,
    CredentialPair, EmailCompletion, ExchangeHandoff, HostedBootstrap, ProviderCallback,
    ProviderCallbackDenial, RefreshSession, RuntimeAuthService, SelectEmail, SelectProvider,
    SubmitEmailProof, SubmitMagicTransferProof,
};
pub(crate) use runtime_security::{
    AccessTokenSessionLookup, BrowserLogoutContext, CurrentSession, DurableEmailAddressReader,
    HostedInteraction, HostedProviderMethod, LoginStartContext, OpaquePurpose,
    ProjectionVerifiedEmailProtector, ProtectedPurpose, ProviderAuthorization,
    ProviderAuthorizationRequest, ProviderCallbackRequest, ProviderExchangeError, ProviderIdentity,
    ProviderRequestProfile, ProviderRuntimeContext, ProviderSecretResolver,
    RenewableProviderCredential, RuntimeAuthorityRepository, RuntimeProtector, RuntimeSigner,
    UpstreamProviderClient, VerificationKey,
};
#[allow(
    unused_imports,
    reason = "the HTTP-free session authority precedes Runtime composition"
)]
pub(crate) use session_authority::{
    AuthenticatedIdentityEvidence, BindBrowserLogout, BrowserLogoutRecord, CommitHandoffExchange,
    CompleteAuthenticatedIdentity, ConfirmBrowserLogout, ConfirmBrowserSessionReuse,
    HandoffPreparation, HandoffSessionRecord, IssuedHandoff, LogoutApplicationSession,
    ManagedCredentialCapability, PrepareBrowserLogout, PrepareHandoffExchange,
    PrepareRefreshRotation, RecoverProviderExchanges, RefreshPreparation, RefreshPreparationResult,
    RefreshRotationResult, RotateRefreshToken, SessionAuthorityRepository,
    VerifiedProviderIdentity,
};
pub(crate) use unit_of_work::{CompleteIdempotency, NewProject, ProjectUnitOfWork};
