use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use owlauth_types::FEDERATED_PROJECT_AUTH_AVAILABLE;
use sea_orm::DatabaseConnection;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    adapters::{
        client_key_security::{ClientKeyDigestMaterial, SoftwareClientKeyRing},
        github::GithubOAuthProviderClient,
        oidc::{RestrictedOidcManagedProfileAdapter, RestrictedOidcProviderClient},
        postgres::{
            DatabasePools,
            authentication::PostgresAuthenticationRepository,
            client_api::{
                Ed25519ClientTokenVerifier, PostgresClientApiRepository,
                RuntimeClientEmailLookupDigester,
            },
            client_key::PostgresClientKeyRepository,
            client_readiness::PostgresClientDigestReadinessAdapter,
            control_lifecycle::PostgresControlLifecycleRepository,
            email::PostgresPasswordlessEmailRepository,
            email_control::PostgresEmailControlRepository,
            identity_mutation::{
                PostgresControlIdentityMutationRepository,
                PostgresRuntimeIdentityMutationRepository,
            },
            managed_connection::PostgresManagedConnectionRepository,
            managed_reauthorization::PostgresManagedReauthorizationRepository,
            projection::PostgresIdentityProjectionMaterializer,
            provider_callback::PostgresProviderCallbackOwnerResolver,
            provider_egress::PostgresProviderEgressPolicyRepository,
            provisioning::PostgresProvisioningAdapter,
            readiness::PostgresReadinessAdapter,
            runtime_authority::PostgresRuntimeAuthorityRepository,
            session_authority::PostgresSessionAuthorityRepository,
            webhook::PostgresWebhookRepository,
        },
        protected_runtime::PostgresProtectedRuntimeCustody,
        provider_registry::ProviderClientRegistry,
        redis_admission::RedisAdmissionCounter,
        runtime_security::{
            ManagedCredentialKeyMaterial, RuntimeKeyMaterial, SoftwareDurableEmailAddressReader,
            SoftwareIdentityMutationCandidateVerifier,
            SoftwareIdentityMutationDurableEmailProtector,
            SoftwareIdentityMutationProofMaterialProtector, SoftwareIdentityMutationTargetIssuer,
            SoftwareIdentityMutationTargetVerifier, SoftwareManagedCredentialProtector,
            SoftwareManagedReauthorizationTargetIssuer,
            SoftwareManagedReauthorizationTargetVerifier, SoftwareProjectionVerifiedEmailProtector,
            SoftwareRuntimeProtector, SplitRuntimeProtector, UnavailableDurableEmailAddressReader,
        },
        smtp::{ForbiddenSmtpDestinations, SafeSmtpTransport},
        system::{Sha256RequestDigester, SystemClock},
        webhook_http::SafeWebhookTransport,
    },
    application::{
        self, AdmissionService, ClientApiService, ClientDigestReadinessService,
        ClientEmailLookupDigester, ClientKeyLifecycleService, ClientKeyVerifier,
        ConfigurationSecretSealers, ControlLifecycleService, DurableEmailAddressReader,
        EmailControlService, IdentityMutationControlService, IdentityMutationProviderCapabilities,
        IdentityMutationRuntimeService, MailWorker, ManagedConnectionRepository,
        ManagedConnectionService, ManagedInteractionCleanupService,
        ManagedReauthorizationControlService, ManagedReauthorizationRuntimeService,
        ManagedReauthorizationTargetVerifier, ProjectionVerifiedEmailProtector,
        ProviderCallbackOwnerResolver, ProviderOnboardingService, ProvisioningInfrastructure,
        ProvisioningService, ReadinessService, RuntimeAuthService, RuntimeProtector,
        WebhookControlService, WebhookWorker,
    },
    config::ServerConfig,
    providers::ProviderRegistrations,
};

pub(crate) struct RuntimeHttpCapabilities {
    pub(crate) admission: Arc<AdmissionService>,
    pub(crate) readiness: Option<Arc<ReadinessService>>,
    pub(crate) auth: Option<Arc<RuntimeAuthService>>,
    pub(crate) callback_owners: Option<Arc<dyn ProviderCallbackOwnerResolver>>,
    pub(crate) managed_reauthorization: Option<Arc<ManagedReauthorizationRuntimeService>>,
    pub(crate) identity_mutations: Option<Arc<IdentityMutationRuntimeService>>,
    pub(crate) managed_sync: Option<Arc<ManagedConnectionService>>,
    pub(crate) webhook_delivery: Option<Arc<WebhookWorker>>,
}

pub(crate) struct ClientHttpCapabilities {
    pub(crate) admission: Arc<AdmissionService>,
    pub(crate) api: Option<Arc<ClientApiService>>,
    pub(crate) readiness: Option<Arc<ClientDigestReadinessService>>,
}

pub(crate) struct ControlHttpCapabilities {
    pub(crate) clock: Arc<dyn application::Clock>,
    pub(crate) provisioning: Option<Arc<ProvisioningService>>,
    pub(crate) lifecycle: Option<Arc<ControlLifecycleService>>,
    pub(crate) email_control: Option<Arc<EmailControlService>>,
    pub(crate) managed_connections: Option<Arc<dyn ManagedConnectionRepository>>,
    pub(crate) managed_reauthorization: Option<Arc<ManagedReauthorizationControlService>>,
    pub(crate) identity_mutations: Option<Arc<IdentityMutationControlService>>,
    pub(crate) webhooks: Option<Arc<WebhookControlService>>,
    pub(crate) provider_onboarding: Option<Arc<ProviderOnboardingService>>,
    pub(crate) client_keys: Option<Arc<ClientKeyLifecycleService>>,
}

pub(crate) struct HttpCapabilities {
    pub(crate) runtime: Option<RuntimeHttpCapabilities>,
    pub(crate) client: Option<ClientHttpCapabilities>,
    pub(crate) control: Option<ControlHttpCapabilities>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the private composition root keeps plane-specific capabilities visibly separate"
)]
pub(crate) fn build_http_capabilities(
    config: &ServerConfig,
    pools: Option<&DatabasePools>,
    runtime_incarnation: Uuid,
    client_incarnation: Uuid,
    custody_providers: &ProviderRegistrations,
) -> HttpCapabilities {
    let client_key_ring = (config.mode.has_client() || config.mode.has_control())
        .then(|| build_client_key_ring(config));
    let runtime_provider_clients = config
        .mode
        .has_runtime()
        .then(|| build_runtime_provider_clients(config));
    let control_preflight_client = config
        .mode
        .has_control()
        .then(|| build_control_preflight_client(config));

    let runtime = config.mode.has_runtime().then(|| {
        let database = pools.and_then(|pools| pools.runtime.clone());
        let runtime_components = (FEDERATED_PROJECT_AUTH_AVAILABLE)
            .then(|| {
                database.clone().map(|database| {
                    build_runtime_auth_service(
                        database,
                        config,
                        runtime_incarnation,
                        custody_providers,
                        runtime_provider_clients
                            .as_ref()
                            .expect("Runtime provider clients are composed once"),
                    )
                })
            })
            .flatten();
        RuntimeHttpCapabilities {
            admission: build_runtime_admission(config),
            readiness: database.clone().map(|database| {
                Arc::new(ReadinessService::new(Arc::new(
                    PostgresReadinessAdapter::new(
                        database,
                        config.runtime_process_id.clone(),
                        runtime_incarnation,
                        config.required_runtime_process_ids.clone(),
                        config.publication_lease_ttl,
                    ),
                )))
            }),
            auth: runtime_components
                .as_ref()
                .map(|(auth, _, _)| Arc::clone(auth)),
            managed_sync: runtime_components
                .as_ref()
                .map(|(_, sync, _)| Arc::clone(sync)),
            managed_reauthorization: runtime_components
                .as_ref()
                .map(|(_, _, service)| Arc::clone(service)),
            callback_owners: database.clone().map(|database| {
                Arc::new(PostgresProviderCallbackOwnerResolver::new(database))
                    as Arc<dyn ProviderCallbackOwnerResolver>
            }),
            identity_mutations: database.clone().map(|database| {
                build_identity_mutation_runtime_service(
                    database,
                    config,
                    runtime_incarnation,
                    custody_providers,
                    runtime_provider_clients
                        .as_ref()
                        .expect("Runtime provider clients are composed once"),
                )
            }),
            webhook_delivery: database.map(|database| {
                build_webhook_worker(database, config, runtime_incarnation, custody_providers)
            }),
        }
    });

    let client = config.mode.has_client().then(|| {
        let key_verifier = Arc::new(
            client_key_ring
                .as_ref()
                .expect("Client key ring is composed for Client")
                .verifier(),
        );
        let database = pools.and_then(|pools| pools.client.clone());
        let readiness = database.clone().map(|database| {
            Arc::new(
                ClientDigestReadinessService::new(
                    Arc::new(PostgresClientDigestReadinessAdapter::new(database)),
                    config.client_process_id.clone(),
                    client_incarnation,
                    key_verifier.readable_versions(),
                    config.required_client_process_ids.clone(),
                    config.client_digest_readiness_lease_ttl,
                )
                .expect("validated Client digest readiness configuration"),
            )
        });
        let api = database.map(|database| {
            let (source_reader, projection_protector) =
                build_projection_materializer_capabilities(config);
            let repository = PostgresClientApiRepository::new(
                database,
                config.client_process_id.clone(),
                client_incarnation,
                source_reader,
                projection_protector,
            )
            .expect("validated Client process identity");
            Arc::new(ClientApiService::new(
                Arc::new(repository),
                key_verifier.clone(),
                build_client_email_lookup_digester(config),
                Arc::new(Ed25519ClientTokenVerifier),
                Arc::new(SystemClock),
            ))
        });
        ClientHttpCapabilities {
            admission: build_client_admission(config),
            api,
            readiness,
        }
    });

    let control = config.mode.has_control().then(|| {
        let database = pools.and_then(|pools| pools.control.clone());
        ControlHttpCapabilities {
            clock: Arc::new(SystemClock),
            provisioning: database
                .clone()
                .map(|database| build_provisioning_service(database, config, custody_providers)),
            lifecycle: database.clone().map(|database| {
                Arc::new(ControlLifecycleService::new(
                    Arc::new(PostgresControlLifecycleRepository::new(
                        database,
                        build_identity_projection_materializer(config),
                    )),
                    Arc::new(SystemClock),
                ))
            }),
            email_control: database
                .clone()
                .map(|database| build_email_control_service(database, config, custody_providers)),
            managed_connections: database.clone().map(|database| {
                Arc::new(PostgresManagedConnectionRepository::new(
                    database,
                    build_identity_projection_materializer(config),
                )) as Arc<dyn ManagedConnectionRepository>
            }),
            managed_reauthorization: database
                .clone()
                .map(|database| build_managed_reauthorization_service(database, config)),
            identity_mutations: database
                .clone()
                .map(|database| build_identity_mutation_control_service(database, config)),
            webhooks: database
                .clone()
                .map(|database| build_webhook_control_service(database, config, custody_providers)),
            provider_onboarding: database.clone().map(|database| {
                Arc::new(ProviderOnboardingService::new(
                    Arc::new(PostgresProviderEgressPolicyRepository::new(database)),
                    Arc::new(
                        control_preflight_client
                            .as_ref()
                            .expect("Control preflight client is composed once")
                            .clone(),
                    ),
                    config.provider_allow_http_loopback,
                ))
            }),
            client_keys: database.map(|database| {
                Arc::new(ClientKeyLifecycleService::new(
                    Arc::new(
                        PostgresClientKeyRepository::new(
                            database,
                            config.required_client_process_ids.clone(),
                        )
                        .expect("validated Client verifier roster"),
                    ),
                    Arc::new(
                        client_key_ring
                            .as_ref()
                            .expect("Client key ring is composed for Control")
                            .issuer(),
                    ),
                    Arc::new(Sha256RequestDigester),
                    Arc::new(SystemClock),
                ))
            }),
        }
    });

    HttpCapabilities {
        runtime,
        client,
        control,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct UnavailableClientEmailLookupDigester;

impl ClientEmailLookupDigester for UnavailableClientEmailLookupDigester {
    fn digest_candidates(
        &self,
        _project_id: Uuid,
        _canonical_email: &str,
    ) -> Result<Vec<application::VersionedDigest>, application::ApplicationError> {
        Err(application::ApplicationError::Integrity)
    }
}

fn build_client_email_lookup_digester(config: &ServerConfig) -> Arc<dyn ClientEmailLookupDigester> {
    let Some(email) = config.email_identity_protection.as_ref() else {
        return Arc::new(UnavailableClientEmailLookupDigester);
    };
    let deployment = config
        .instance_id
        .clone()
        .expect("validated Client configuration has an instance ID");
    let active = RuntimeKeyMaterial::new(
        email.active.digest_key.expose_copy(),
        email.active.protection_key.expose_copy(),
    );
    let retained = email
        .retained
        .iter()
        .map(|(version, keys)| {
            (
                *version,
                RuntimeKeyMaterial::new(
                    keys.digest_key.expose_copy(),
                    keys.protection_key.expose_copy(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let readable_versions = email
        .retained
        .keys()
        .copied()
        .chain(std::iter::once(email.active_version))
        .collect::<BTreeSet<_>>();
    let protector: Arc<dyn RuntimeProtector> = Arc::new(
        SoftwareRuntimeProtector::new(deployment, email.active_version, active, retained)
            .expect("validated email identity protection ring"),
    );
    Arc::new(
        RuntimeClientEmailLookupDigester::new(protector, readable_versions)
            .expect("validated Client email lookup digest authority"),
    )
}

fn build_client_key_ring(config: &ServerConfig) -> SoftwareClientKeyRing {
    let digest = config
        .client_key_digest
        .as_ref()
        .expect("validated Client or Control configuration has a Client digest ring");
    SoftwareClientKeyRing::new(
        config
            .instance_id
            .clone()
            .expect("validated configuration has a deployment instance ID"),
        digest.active_version,
        ClientKeyDigestMaterial::new(digest.active_key.expose_copy()),
        digest
            .retained
            .iter()
            .map(|(version, key)| (*version, ClientKeyDigestMaterial::new(key.expose_copy())))
            .collect(),
    )
    .expect("validated Client digest ring")
}

fn build_provisioning_service(
    database: DatabaseConnection,
    config: &ServerConfig,
    providers: &ProviderRegistrations,
) -> Arc<ProvisioningService> {
    let (signing_selection, _) = providers
        .active_signing()
        .expect("validated Control signing provider selection");
    let (secret_selection, _) = providers
        .active_secret()
        .expect("validated Control secret provider selection");
    let adapter = PostgresProvisioningAdapter::new_protected(
        database,
        config.runtime.external_base.clone(),
        config.required_runtime_process_ids.clone(),
        config.key_propagation_delay,
        config.signing_verification_retention,
        config
            .instance_id
            .as_deref()
            .expect("validated configuration has a deployment instance ID"),
        signing_selection.provider_id().clone(),
        signing_selection.format_version(),
        secret_selection.provider_id().clone(),
        secret_selection.format_version(),
    )
    .expect("validated custody composition");
    let infrastructure = ProvisioningInfrastructure::new_protected(
        SystemClock,
        Sha256RequestDigester,
        config.provider_allow_http_loopback,
        providers.signing_provisioners().clone(),
        providers.secret_sealers().clone(),
    );
    Arc::new(ProvisioningService::new(Arc::new(adapter), infrastructure))
}

fn build_email_control_service(
    database: DatabaseConnection,
    config: &ServerConfig,
    providers: &ProviderRegistrations,
) -> Arc<EmailControlService> {
    let (selection, _) = providers
        .active_secret()
        .expect("validated Control secret provider selection");
    let repository = PostgresEmailControlRepository::new_protected(
        database,
        config.required_runtime_process_ids.clone(),
        config
            .instance_id
            .as_deref()
            .expect("validated configuration has a deployment instance ID"),
        selection.provider_id().clone(),
        selection.format_version(),
    )
    .expect("validated SMTP custody composition");
    Arc::new(EmailControlService::new_protected(
        Arc::new(repository),
        ConfigurationSecretSealers::new(providers.secret_sealers().clone()),
        Arc::new(SystemClock),
        Arc::new(Sha256RequestDigester),
    ))
}

fn build_webhook_control_service(
    database: DatabaseConnection,
    config: &ServerConfig,
    providers: &ProviderRegistrations,
) -> Arc<WebhookControlService> {
    let (selection, _) = providers
        .active_secret()
        .expect("validated Control secret provider selection");
    let (_, projection_protector) = build_projection_materializer_capabilities(config);
    let repository = PostgresWebhookRepository::new_control_protected(
        database,
        projection_protector,
        config
            .instance_id
            .as_deref()
            .expect("validated Control configuration has an instance ID"),
        selection.provider_id().clone(),
        selection.format_version(),
    )
    .expect("validated webhook custody composition");
    Arc::new(WebhookControlService::new_protected(
        Arc::new(repository),
        ConfigurationSecretSealers::new(providers.secret_sealers().clone()),
        Arc::new(SafeWebhookTransport::new(
            [config.runtime.bind, config.control.bind],
            config.webhook_allowed_private_ips.clone(),
            config.webhook_extra_root_cert_der.as_deref(),
        )),
        Arc::new(SystemClock),
    ))
}

fn build_webhook_worker(
    database: DatabaseConnection,
    config: &ServerConfig,
    runtime_incarnation: Uuid,
    providers: &ProviderRegistrations,
) -> Arc<WebhookWorker> {
    let protected_custody = PostgresProtectedRuntimeCustody::from_registrations(
        database.clone(),
        config
            .instance_id
            .as_deref()
            .expect("validated Runtime configuration has an instance ID"),
        providers,
    )
    .expect("validated protected webhook custody");
    let (_, projection_protector) = build_projection_materializer_capabilities(config);
    let repository = PostgresWebhookRepository::new_runtime_protected(
        database,
        projection_protector,
        config
            .instance_id
            .as_deref()
            .expect("validated Runtime configuration has an instance ID"),
    )
    .expect("validated webhook cleanup custody composition");
    Arc::new(
        WebhookWorker::new(
            Arc::new(repository),
            Arc::new(protected_custody),
            Arc::new(SafeWebhookTransport::new(
                [config.runtime.bind, config.control.bind],
                config.webhook_allowed_private_ips.clone(),
                config.webhook_extra_root_cert_der.as_deref(),
            )),
            Arc::new(SystemClock),
            config.runtime_process_id.clone(),
            runtime_incarnation,
            config.publication_lease_ttl,
        )
        .expect("validated webhook delivery worker configuration"),
    )
}

fn forbidden_smtp_listener_destinations(config: &ServerConfig) -> ForbiddenSmtpDestinations {
    let mut forbidden = ForbiddenSmtpDestinations::default();
    for bind in [config.runtime.bind, config.control.bind] {
        forbidden.insert_listener_bind(bind);
    }
    forbidden
}

fn build_runtime_admission(config: &ServerConfig) -> Arc<AdmissionService> {
    let admission = config
        .admission
        .as_ref()
        .expect("validated Runtime configuration has admission settings");
    build_admission(
        admission,
        admission
            .runtime_maximum_processes
            .expect("validated Runtime process bound")
            .get(),
    )
}

fn build_client_admission(config: &ServerConfig) -> Arc<AdmissionService> {
    let admission = config
        .admission
        .as_ref()
        .expect("validated Client configuration has admission settings");
    build_admission(
        admission,
        admission
            .client_maximum_processes
            .expect("validated Client process bound")
            .get(),
    )
}

fn build_admission(
    admission: &crate::config::AdmissionConfig,
    maximum_processes: u32,
) -> Arc<AdmissionService> {
    let distributed = admission.redis_url.as_ref().map(|url| {
        Arc::new(
            RedisAdmissionCounter::new(url.expose(), admission.redis_timeout)
                .expect("validated Redis admission URL"),
        ) as Arc<dyn application::DistributedAdmissionCounter>
    });
    Arc::new(AdmissionService::new(
        admission.namespace.clone(),
        admission.digest_key.expose_copy(),
        maximum_processes,
        distributed,
    ))
}

fn build_identity_projection_materializer(
    config: &ServerConfig,
) -> Arc<PostgresIdentityProjectionMaterializer> {
    let (source_reader, projection_protector) = build_projection_materializer_capabilities(config);
    Arc::new(PostgresIdentityProjectionMaterializer::new(
        source_reader,
        projection_protector,
    ))
}

fn build_projection_materializer_capabilities(
    config: &ServerConfig,
) -> (
    Arc<dyn DurableEmailAddressReader>,
    Arc<dyn ProjectionVerifiedEmailProtector>,
) {
    let deployment = config
        .instance_id
        .clone()
        .expect("validated configuration has an instance ID");
    let build_material =
        |active: &crate::config::RuntimeKeyConfig,
         retained: &BTreeMap<i32, crate::config::RuntimeKeyConfig>| {
            let active = RuntimeKeyMaterial::new(
                active.digest_key.expose_copy(),
                active.protection_key.expose_copy(),
            );
            let retained = retained
                .iter()
                .map(|(version, keys)| {
                    (
                        *version,
                        RuntimeKeyMaterial::new(
                            keys.digest_key.expose_copy(),
                            keys.protection_key.expose_copy(),
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            (active, retained)
        };
    let source_reader: Arc<dyn DurableEmailAddressReader> =
        match config.email_identity_protection.as_ref() {
            Some(email) => {
                let (active, retained) = build_material(&email.active, &email.retained);
                Arc::new(
                    SoftwareDurableEmailAddressReader::new(
                        deployment.clone(),
                        email.active_version,
                        active,
                        retained,
                    )
                    .expect("validated durable email identity protection configuration"),
                )
            }
            None => Arc::new(UnavailableDurableEmailAddressReader),
        };
    let projection_protector = Arc::new(build_projection_email_protector(config));
    (source_reader, projection_protector)
}

fn build_projection_email_protector(
    config: &ServerConfig,
) -> SoftwareProjectionVerifiedEmailProtector {
    let projection = &config.projection_email_protection;
    let retained = projection
        .retained
        .iter()
        .map(|(version, key)| (*version, key.expose_copy()))
        .collect::<BTreeMap<_, _>>();
    SoftwareProjectionVerifiedEmailProtector::new(
        config
            .instance_id
            .clone()
            .expect("validated projection protection has an instance ID"),
        projection.active_version,
        projection.active_key.expose_copy(),
        retained,
    )
    .expect("validated projection verified-email protection configuration")
}

fn protection_material(
    protection: &crate::config::RuntimeProtectionConfig,
) -> (i32, RuntimeKeyMaterial, BTreeMap<i32, RuntimeKeyMaterial>) {
    let active = RuntimeKeyMaterial::new(
        protection.active.digest_key.expose_copy(),
        protection.active.protection_key.expose_copy(),
    );
    let retained = protection
        .retained
        .iter()
        .map(|(version, keys)| {
            (
                *version,
                RuntimeKeyMaterial::new(
                    keys.digest_key.expose_copy(),
                    keys.protection_key.expose_copy(),
                ),
            )
        })
        .collect();
    (protection.active_version, active, retained)
}

fn identity_mutation_target_material(
    config: &ServerConfig,
) -> (i32, RuntimeKeyMaterial, BTreeMap<i32, RuntimeKeyMaterial>) {
    // The reviewed short-lived target material is shared only as raw roots. Identity target
    // facades apply their own cryptographic deployment domain and expose disjoint capabilities.
    protection_material(&config.managed_reauthorization_target_protection)
}

fn identity_mutation_evidence_material(
    config: &ServerConfig,
) -> (i32, RuntimeKeyMaterial, BTreeMap<i32, RuntimeKeyMaterial>) {
    protection_material(&config.identity_mutation_evidence_protection)
}

fn build_identity_runtime_protector(config: &ServerConfig) -> Arc<SplitRuntimeProtector> {
    let deployment = config
        .instance_id
        .as_deref()
        .expect("validated instance ID");
    let build = |protection: &crate::config::RuntimeProtectionConfig| {
        let (version, active, retained) = protection_material(protection);
        SoftwareRuntimeProtector::new(deployment.to_owned(), version, active, retained)
            .expect("validated protection ring")
    };
    let runtime = config
        .runtime_protection
        .as_ref()
        .expect("Runtime-only identity service requires generic Runtime protection");
    let email = config.email_identity_protection.as_ref().map(|protection| {
        let runtime_shape = crate::config::RuntimeProtectionConfig {
            active_version: protection.active_version,
            active: protection.active.clone(),
            retained: protection.retained.clone(),
        };
        build(&runtime_shape)
    });
    Arc::new(SplitRuntimeProtector::new(build(runtime), email))
}

fn build_identity_mutation_control_service(
    database: DatabaseConnection,
    config: &ServerConfig,
) -> Arc<IdentityMutationControlService> {
    let deployment = config
        .instance_id
        .as_deref()
        .expect("validated instance ID");
    let (target_version, target_active, target_retained) =
        identity_mutation_target_material(config);
    let target = Arc::new(
        SoftwareIdentityMutationTargetIssuer::new(
            deployment,
            target_version,
            target_active,
            target_retained,
        )
        .expect("validated identity mutation target issuer"),
    );
    let (evidence_version, evidence_active, evidence_retained) =
        identity_mutation_evidence_material(config);
    let evidence = Arc::new(
        SoftwareIdentityMutationCandidateVerifier::new(
            deployment,
            evidence_version,
            evidence_active,
            evidence_retained,
        )
        .expect("validated identity mutation evidence verifier"),
    );
    let (source_reader, projection_protector) = build_projection_materializer_capabilities(config);
    let repository = Arc::new(PostgresControlIdentityMutationRepository::new(
        database,
        Arc::new(PostgresIdentityProjectionMaterializer::new(
            source_reader,
            projection_protector,
        )),
        config.required_runtime_process_ids.clone(),
    ));
    Arc::new(
        IdentityMutationControlService::new(
            repository,
            target,
            evidence,
            Arc::new(SystemClock),
            config.runtime.external_base.clone(),
            IdentityMutationProviderCapabilities::reviewed(),
        )
        .expect("validated identity mutation Control service"),
    )
}

const PROVIDER_CALLBACK_CONCURRENCY_LIMIT: usize = 16;
const PROVIDER_PREFLIGHT_CONCURRENCY_LIMIT: usize = 4;
const GOOGLE_PROVIDER_ORIGINS: [&str; 4] = [
    "https://accounts.google.com",
    "https://oauth2.googleapis.com",
    "https://www.googleapis.com",
    "https://openidconnect.googleapis.com",
];

struct RuntimeProviderClients {
    oidc: RestrictedOidcProviderClient,
    google: RestrictedOidcProviderClient,
    registry: Arc<ProviderClientRegistry>,
}

fn build_runtime_provider_clients(config: &ServerConfig) -> RuntimeProviderClients {
    let callback_budget = Arc::new(Semaphore::new(PROVIDER_CALLBACK_CONCURRENCY_LIMIT));
    let oidc = RestrictedOidcProviderClient::new_allow_all_with_budget(
        config.provider_allow_http_loopback,
        callback_budget.clone(),
    )
    .expect("validated generic OIDC transport");
    let google = RestrictedOidcProviderClient::new_with_budget_and_callback_policy(
        GOOGLE_PROVIDER_ORIGINS,
        false,
        config.provider_allow_http_loopback,
        callback_budget.clone(),
    )
    .expect("fixed Google endpoint policy");
    let registry = Arc::new(ProviderClientRegistry::new(
        oidc.clone(),
        google.clone(),
        GithubOAuthProviderClient::new_with_budget_and_callback_policy(
            callback_budget,
            config.provider_allow_http_loopback,
        )
        .expect("fixed GitHub provider transport"),
    ));
    RuntimeProviderClients {
        oidc,
        google,
        registry,
    }
}

fn build_control_preflight_client(config: &ServerConfig) -> RestrictedOidcProviderClient {
    RestrictedOidcProviderClient::new_allow_all_with_budget(
        config.provider_allow_http_loopback,
        Arc::new(Semaphore::new(PROVIDER_PREFLIGHT_CONCURRENCY_LIMIT)),
    )
    .expect("validated independent OIDC preflight transport")
}

fn build_identity_mutation_runtime_service(
    database: DatabaseConnection,
    config: &ServerConfig,
    runtime_incarnation: Uuid,
    custody_providers: &ProviderRegistrations,
    provider_clients: &RuntimeProviderClients,
) -> Arc<IdentityMutationRuntimeService> {
    let deployment = config
        .instance_id
        .as_deref()
        .expect("validated instance ID");
    let protector = build_identity_runtime_protector(config);
    let (target_version, target_active, target_retained) =
        identity_mutation_target_material(config);
    let target = Arc::new(
        SoftwareIdentityMutationTargetVerifier::new(
            deployment,
            target_version,
            target_active,
            target_retained,
        )
        .expect("validated identity mutation target verifier"),
    );
    let (evidence_version, evidence_active, evidence_retained) =
        identity_mutation_evidence_material(config);
    let evidence = Arc::new(
        SoftwareIdentityMutationProofMaterialProtector::new(
            deployment,
            evidence_version,
            evidence_active,
            evidence_retained,
        )
        .expect("validated identity mutation evidence producer"),
    );
    let protected_custody = PostgresProtectedRuntimeCustody::from_registrations(
        database.clone(),
        deployment,
        custody_providers,
    )
    .expect("validated identity mutation protected custody");
    let provider = provider_clients.registry.clone();
    Arc::new(IdentityMutationRuntimeService::new(
        Arc::new(PostgresRuntimeIdentityMutationRepository::new(
            database,
            config.runtime_process_id.clone(),
            runtime_incarnation,
            config.required_runtime_process_ids.clone(),
        )),
        protector.clone(),
        target,
        evidence,
        Arc::new(SoftwareIdentityMutationDurableEmailProtector::new(
            protector.clone(),
        )),
        provider,
        Arc::new(protected_custody),
        Arc::new(SystemClock),
        config.runtime.external_base.clone(),
        IdentityMutationProviderCapabilities::reviewed(),
    ))
}

#[allow(
    clippy::too_many_lines,
    reason = "Runtime composition keeps one process incarnation and physically distinct short-term, email identity, projection email, managed target, and managed credential custody visible"
)]
fn build_runtime_auth_service(
    database: DatabaseConnection,
    config: &ServerConfig,
    runtime_incarnation: Uuid,
    custody_providers: &ProviderRegistrations,
    provider_clients: &RuntimeProviderClients,
) -> (
    Arc<RuntimeAuthService>,
    Arc<ManagedConnectionService>,
    Arc<ManagedReauthorizationRuntimeService>,
) {
    let protection = config
        .runtime_protection
        .as_ref()
        .expect("validated Runtime configuration has protection keys");
    let deployment_context = config
        .instance_id
        .clone()
        .expect("validated Runtime configuration has an instance ID");
    let build_ring =
        |active_version: i32,
         active: &crate::config::RuntimeKeyConfig,
         retained: &BTreeMap<i32, crate::config::RuntimeKeyConfig>| {
            let active = RuntimeKeyMaterial::new(
                active.digest_key.expose_copy(),
                active.protection_key.expose_copy(),
            );
            let retained = retained
                .iter()
                .map(|(version, keys)| {
                    (
                        *version,
                        RuntimeKeyMaterial::new(
                            keys.digest_key.expose_copy(),
                            keys.protection_key.expose_copy(),
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            SoftwareRuntimeProtector::new(
                deployment_context.clone(),
                active_version,
                active,
                retained,
            )
            .expect("validated Runtime protection configuration")
        };
    let protector = SplitRuntimeProtector::new(
        build_ring(
            protection.active_version,
            &protection.active,
            &protection.retained,
        ),
        config
            .email_identity_protection
            .as_ref()
            .map(|email_identity| {
                build_ring(
                    email_identity.active_version,
                    &email_identity.active,
                    &email_identity.retained,
                )
            }),
    );
    let interaction_readable_key_versions = protector.readable_key_versions();
    let protector = Arc::new(protector);

    let managed_protection = config
        .managed_credential_protection
        .as_ref()
        .expect("validated Runtime managed credential key ring");
    let managed_retained = managed_protection
        .retained
        .iter()
        .map(|(version, key)| {
            (
                *version,
                ManagedCredentialKeyMaterial::new(key.expose_copy()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let managed_protector = Arc::new(
        SoftwareManagedCredentialProtector::new(
            deployment_context,
            managed_protection.active_version,
            ManagedCredentialKeyMaterial::new(managed_protection.active_key.expose_copy()),
            managed_retained,
        )
        .expect("validated managed credential protection configuration"),
    );

    let provider = provider_clients.registry.as_ref().clone();
    let protected_custody = PostgresProtectedRuntimeCustody::from_registrations(
        database.clone(),
        config
            .instance_id
            .as_deref()
            .expect("validated Runtime configuration has an instance ID"),
        custody_providers,
    )
    .expect("validated protected Runtime custody");
    let secret_resolver = Arc::new(protected_custody.clone());
    let smtp_secret_resolver = Arc::new(protected_custody);
    let email = Arc::new(
        PostgresPasswordlessEmailRepository::new_with_runtime_identity(
            database.clone(),
            config.runtime_process_id.clone(),
            runtime_incarnation,
            config.required_runtime_process_ids.clone(),
            time::Duration::seconds(
                i64::try_from(
                    config
                        .publication_lease_ttl
                        .as_secs()
                        .max(5)
                        .saturating_mul(2),
                )
                .expect("validated Runtime publication lease duration"),
            ),
        ),
    );
    let mail_worker = Arc::new(
        MailWorker::new(
            email.clone(),
            Arc::new(SafeSmtpTransport::with_egress_policy(
                forbidden_smtp_listener_destinations(config),
                config.smtp_extra_root_cert_der.as_deref(),
                config
                    .deployment_smtp
                    .as_ref()
                    .map_or(&[], |smtp| smtp.explicitly_allowed_private_ips.as_slice()),
            )),
            smtp_secret_resolver,
            protector.clone(),
            config.runtime_process_id.clone(),
        )
        .expect("validated mail worker configuration"),
    );

    let managed_reauthorization_target_verifier =
        build_managed_reauthorization_target_verifier(config);
    let target_readable_key_versions =
        managed_reauthorization_target_verifier.readable_key_versions();
    let managed_adapter = Arc::new(RestrictedOidcManagedProfileAdapter::new(
        provider_clients.oidc.clone(),
        provider_clients.google.clone(),
        secret_resolver.clone(),
    ));
    let projection_materializer = build_identity_projection_materializer(config);
    let managed_repository = Arc::new(PostgresManagedConnectionRepository::new(
        database.clone(),
        projection_materializer.clone(),
    ));
    let interaction_cleanup = Arc::new(
        ManagedInteractionCleanupService::new(
            managed_repository.clone(),
            interaction_readable_key_versions,
            target_readable_key_versions,
            Arc::new(SystemClock),
        )
        .expect("validated Runtime short-term readable key inventory"),
    );
    let managed_sync = Arc::new(
        ManagedConnectionService::new(
            managed_repository.clone(),
            managed_protector.clone(),
            interaction_cleanup,
            managed_adapter,
            Arc::new(SystemClock),
        )
        .expect("validated managed provider adapter capability"),
    );
    let managed_reauthorization = Arc::new(
        ManagedReauthorizationRuntimeService::new(
            Arc::new(PostgresManagedReauthorizationRepository::new(
                database.clone(),
            )),
            managed_repository,
            protector.clone(),
            managed_reauthorization_target_verifier,
            managed_protector.clone(),
            Arc::new(provider.clone()),
            secret_resolver.clone(),
            Arc::new(SystemClock),
            crate::adapters::oidc::managed_profile_capabilities(),
        )
        .expect("validated managed reauthorization capability"),
    );
    let auth = Arc::new(RuntimeAuthService::new(
        Arc::new(PostgresAuthenticationRepository::new_with_runtime_identity(
            database.clone(),
            config.runtime_process_id.clone(),
            runtime_incarnation,
        )),
        Arc::new(
            PostgresSessionAuthorityRepository::new_with_runtime_identity_and_managed_protector(
                database.clone(),
                config.runtime_process_id.clone(),
                runtime_incarnation,
                managed_protector,
                protector.clone(),
                projection_materializer.clone(),
            ),
        ),
        Arc::new(
            PostgresRuntimeAuthorityRepository::new_with_runtime_identity_and_projection_materializer(
                database,
                config.runtime_process_id.clone(),
                runtime_incarnation,
                config.required_runtime_process_ids.clone(),
                projection_materializer,
            ),
        ),
        email,
        mail_worker,
        protector,
        secret_resolver.clone(),
        secret_resolver,
        Arc::new(provider),
        crate::adapters::oidc::managed_profile_capabilities(),
        Arc::new(SystemClock),
        config.runtime.external_base.clone(),
    ));
    (auth, managed_sync, managed_reauthorization)
}

fn managed_reauthorization_target_material(
    config: &ServerConfig,
) -> (i32, RuntimeKeyMaterial, BTreeMap<i32, RuntimeKeyMaterial>) {
    let protection = &config.managed_reauthorization_target_protection;
    let active = RuntimeKeyMaterial::new(
        protection.active.digest_key.expose_copy(),
        protection.active.protection_key.expose_copy(),
    );
    let retained = protection
        .retained
        .iter()
        .map(|(version, keys)| {
            (
                *version,
                RuntimeKeyMaterial::new(
                    keys.digest_key.expose_copy(),
                    keys.protection_key.expose_copy(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    (protection.active_version, active, retained)
}

pub(crate) fn build_managed_reauthorization_target_verifier(
    config: &ServerConfig,
) -> Arc<SoftwareManagedReauthorizationTargetVerifier> {
    let (active_version, active, retained) = managed_reauthorization_target_material(config);
    Arc::new(
        SoftwareManagedReauthorizationTargetVerifier::new(
            config
                .instance_id
                .as_deref()
                .expect("validated instance ID"),
            active_version,
            active,
            retained,
        )
        .expect("validated managed reauthorization target verifier configuration"),
    )
}

pub(crate) fn build_managed_reauthorization_target_issuer(
    config: &ServerConfig,
) -> Arc<SoftwareManagedReauthorizationTargetIssuer> {
    let (active_version, active, retained) = managed_reauthorization_target_material(config);
    Arc::new(
        SoftwareManagedReauthorizationTargetIssuer::new(
            config
                .instance_id
                .as_deref()
                .expect("validated instance ID"),
            active_version,
            active,
            retained,
        )
        .expect("validated managed reauthorization target issuer configuration"),
    )
}

pub(crate) fn build_managed_reauthorization_service(
    database: DatabaseConnection,
    config: &ServerConfig,
) -> Arc<ManagedReauthorizationControlService> {
    let target_issuer = build_managed_reauthorization_target_issuer(config);
    Arc::new(
        ManagedReauthorizationControlService::new(
            Arc::new(PostgresManagedReauthorizationRepository::new(database)),
            target_issuer,
            Arc::new(SystemClock),
            config.runtime.external_base.clone(),
            crate::adapters::oidc::managed_profile_capabilities(),
        )
        .expect("validated managed reauthorization capability"),
    )
}
