mod admission;
mod authentication;
mod client_api;
mod client_key;
mod client_readiness;
mod control_lifecycle;
mod email_control;
mod error;
mod identity_mutation;
mod infrastructure;
mod mail;
mod managed_connection;
mod managed_reauthorization;
mod passwordless_email;
mod provider_callback;
mod provider_onboarding;
mod provisioning;
mod readiness;
mod runtime_auth;
mod runtime_security;
mod session_authority;
#[cfg(test)]
mod unit_of_work;
mod webhook;

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
pub(crate) use client_api::{
    ActiveClientToken, ClientApiRepository, ClientApiService, ClientApplicationProjection,
    ClientEmailLookupDigester, ClientKeyAuthority, ClientPrincipal, ClientTokenIntrospection,
    ClientTokenSessionLookup, ClientTokenSignatureVerifier, ClientUser, ClientUserCursor,
    ClientUserPage, ClientUserStatus, ClientVerificationKey, MAX_CLIENT_USER_PAGE_LIMIT,
};
pub(crate) use client_key::{
    AcknowledgeProjectClientKeyDelivery, CLIENT_KEY_CREDENTIAL_PREFIX, CLIENT_KEY_PUBLIC_ID_BYTES,
    CLIENT_KEY_SECRET_BYTES, ClientKeyCreateAttemptError, ClientKeyIssuer, ClientKeyLifecyclePort,
    ClientKeyLifecycleService, ClientKeyVerifier, CreateProjectClientKey,
    CreateProjectClientKeyResult, IssuedClientCredential, MAX_ACTIVE_CLIENT_KEYS_PER_PROJECT,
    OneTimeClientCredential, ParsedClientCredential, PreparedProjectClientKey,
    ProjectClientKeyCursor, ProjectClientKeyRecord, ProjectClientKeyStatus, RevokeProjectClientKey,
    StoredProjectClientKeyCreate, client_key_display_prefix,
};
pub(crate) use client_readiness::{
    ClientDigestReadinessClaim, ClientDigestReadinessPort, ClientDigestReadinessService,
    ClientDigestReadinessSnapshot, ClientDigestReadinessState, MAX_REQUIRED_CLIENT_PROCESSES,
    valid_client_process_id,
};
pub(crate) use control_lifecycle::{
    ApplicationSessionRecord, BrowserSessionRecord, ControlLifecyclePort, ControlLifecycleService,
    DisableProjectUser, EnableProjectUser, ManagedSessionStatus, ProjectUserIdentityKind,
    ProjectUserIdentityRecord, ProjectUserIdentityStatus, ProjectUserPage, ProjectUserRecord,
    ProjectUserSessions, ProjectUserStatus, RevokeApplicationSession, RevokeBrowserSession,
};
pub(crate) use email_control::{
    CreateSmtpConfiguration, DeploymentSmtpGenerationRecord, EmailAssignmentRecord,
    EmailControlPort, EmailControlService, EmailPolicyRecord, PrepareSmtpConfiguration,
    PrepareSmtpTest, PreparedDeploymentSmtpGeneration, PreparedSmtpConfiguration, PreparedSmtpTest,
    ReconcileDeploymentSmtpGeneration, SmtpConfigurationRecord, SmtpControlStatus,
    SmtpControlTlsMode, SmtpTestOperationRecord, SmtpTestState, UpdateEmailPolicy,
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
    IdentityMutationProviderCandidate, IdentityMutationProviderCapabilities,
    IdentityMutationProviderCapability, IdentityMutationProviderDenial,
    IdentityMutationProviderDigestVersions, IdentityMutationProviderRegistrationEvidence,
    IdentityMutationProviderSlotAuthority, IdentityMutationRecord, IdentityMutationRuntimePort,
    IdentityMutationRuntimeService, IdentityMutationSafeSlot, IdentityMutationSessionsDisposition,
    IdentityMutationSlotRecord, IdentityMutationTargetIssuer, IdentityMutationTargetVerifier,
    IdentityMutationView, PrepareIdentityMutationEmailGeneration,
    PreparedIdentityMutationCandidate, PreparedIdentityMutationConfirmation,
    PreparedIdentityMutationCreate, PreparedIdentityMutationProviderCompletion,
    ProviderProofObservation, ResolveIdentityMutationMagicTransferContext,
    ResolvedIdentityMutationMagicTransferContext, RuntimeIdentityMutationRepository,
    StartIdentityMutationMethod, StartedIdentityMutationMethod, SubmitIdentityMutationEmailProof,
    VerifiedIdentityMutationEmailChallenge, VerifyIdentityMutationEmailProof,
    VerifyIdentityMutationMagicTransferProof, VerifyRawIdentityMutationEmailProof,
};
pub(crate) use infrastructure::{Clock, RequestDigester};
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
pub(crate) use provider_onboarding::{
    NamedProviderPreflight, OidcPreflightPort, OidcPreflightSummary, ProviderEgressPolicyPort,
    ProviderEgressPolicyRecord, ProviderOnboardingService, UpdateProviderEgressPolicy,
};
pub(crate) use provisioning::{
    ApplicationConfiguration, ApplicationProvisioningPort, ApplicationRecord,
    ConfigurationSecretSealers, CreateApplication, CreateProject, CreateProvider, PrepareProvider,
    PreparedProvider, PreparedSecretMaterial, PreparedSigningKey, PreparedSigningMaterial,
    ProjectPolicyRecord, ProjectProvisioningPort, ProjectRecord, ProviderProvisioningPort,
    ProviderRecord, ProviderRecovery, ProvisionedProtectedSigningMaterial,
    ProvisioningInfrastructure, ProvisioningOperationState, ProvisioningService,
    ReplaceApplicationConfiguration, SealedProtectedMaterial, SigningKeyMaintenanceItem,
    SigningKeyProvisioningPort, SigningKeyRecord, SigningProviderAction, SigningProviderCall,
    SigningProviderLease, UpdateApplication, UpdateProject, UpdateProjectPolicy,
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
#[cfg(test)]
pub(crate) use unit_of_work::{CompleteIdempotency, NewProject, ProjectUnitOfWork};
pub(crate) use webhook::{
    ApplicationUserEventRecord, ClaimedWebhookDelivery, ClaimedWebhookSecretCleanup,
    CreateWebhookEndpoint, HistoryCursor, PrepareWebhookEndpoint, PrepareWebhookRotation,
    PrepareWebhookSecretRotation, PreparedWebhookEndpoint, PreparedWebhookSecret,
    UpdateWebhookEndpoint, WebhookControlPort, WebhookControlService, WebhookDeliveryRecord,
    WebhookDeliveryRepository, WebhookEndpointRecord, WebhookEndpointValidator,
    WebhookSecretPreparationState, WebhookSecretResolver, WebhookTransport,
    WebhookTransportOutcome, WebhookWorker, endpoint_status, event_type,
};
