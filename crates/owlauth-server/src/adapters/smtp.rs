use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hickory_resolver::{
    TokioResolver,
    net::NetError,
    proto::rr::{RData, RecordType},
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use zeroize::{Zeroize, Zeroizing};

use crate::application::{
    ApplicationError, MailSubmission, MailTransport, MailTransportOutcome, SmtpTlsMode,
    classify_smtp_status,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const DATA_TIMEOUT: Duration = Duration::from_secs(10);
const SMTP_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 8_192;

#[derive(Clone, Debug, Default)]
pub(crate) struct ForbiddenSmtpDestinations {
    exact: HashSet<SocketAddr>,
    wildcard_ports: HashSet<u16>,
}

impl ForbiddenSmtpDestinations {
    pub(crate) fn insert_listener_bind(&mut self, bind: SocketAddr) {
        if bind.ip().is_unspecified() {
            self.wildcard_ports.insert(bind.port());
        } else {
            self.exact.insert(bind);
        }
    }

    fn contains(&self, destination: SocketAddr) -> bool {
        self.wildcard_ports.contains(&destination.port()) || self.exact.contains(&destination)
    }
}

#[async_trait]
trait SmtpDnsResolver: Send + Sync {
    async fn lookup_cname(&self, hostname: &str) -> Result<Option<String>, ApplicationError>;
    async fn lookup_ips(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, ApplicationError>;
}

struct SystemSmtpDnsResolver(TokioResolver);

#[async_trait]
impl SmtpDnsResolver for SystemSmtpDnsResolver {
    async fn lookup_cname(&self, hostname: &str) -> Result<Option<String>, ApplicationError> {
        match self.0.lookup(hostname, RecordType::CNAME).await {
            Ok(records) => Ok(records
                .answers()
                .iter()
                .find_map(|record| match &record.data {
                    RData::CNAME(name) => Some(name.0.to_utf8()),
                    _ => None,
                })),
            Err(error) if is_no_records(&error) => Ok(None),
            Err(_) => Err(ApplicationError::ExternalStore),
        }
    }

    async fn lookup_ips(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, ApplicationError> {
        self.0
            .lookup_ip(hostname)
            .await
            .map(|lookup| lookup.iter().collect())
            .map_err(|_| ApplicationError::ExternalStore)
    }
}

#[derive(Clone)]
pub(crate) struct SafeSmtpTransport {
    tls: TlsConnector,
    resolver: Arc<dyn SmtpDnsResolver>,
    test_loopback_destination: bool,
    forbidden_destinations: Arc<ForbiddenSmtpDestinations>,
    operator_allowed_private_ips: Arc<Vec<std::net::IpAddr>>,
}

impl SafeSmtpTransport {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        Self::with_root_certificates(roots, false, ForbiddenSmtpDestinations::default())
    }

    pub(crate) fn with_egress_policy(
        forbidden: ForbiddenSmtpDestinations,
        extra_root_cert_der: Option<&[u8]>,
        operator_allowed_private_ips: &[std::net::IpAddr],
    ) -> Self {
        let mut roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        if let Some(certificate) = extra_root_cert_der {
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    certificate.to_vec(),
                ))
                .expect("configuration validates the extra SMTP trust anchor");
        }
        let mut transport = Self::with_root_certificates(roots, false, forbidden);
        transport.operator_allowed_private_ips = Arc::new(operator_allowed_private_ips.to_vec());
        transport
    }

    #[cfg(test)]
    fn with_test_loopback_destination(roots: RootCertStore) -> Self {
        Self::with_root_certificates(roots, true, ForbiddenSmtpDestinations::default())
    }

    fn with_root_certificates(
        roots: RootCertStore,
        test_loopback_destination: bool,
        forbidden_destinations: ForbiddenSmtpDestinations,
    ) -> Self {
        // Select the provider explicitly because test-only transport dependencies may enable
        // rustls' `ring` feature alongside the production `aws-lc-rs` feature. Relying on
        // feature inference would then panic while composing an otherwise idle Runtime.
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("the selected rustls provider supports safe protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let resolver = TokioResolver::builder_tokio()
            .expect("system DNS resolver configuration is readable")
            .build()
            .expect("system DNS resolver can be constructed");
        Self {
            tls: TlsConnector::from(Arc::new(config)),
            resolver: Arc::new(SystemSmtpDnsResolver(resolver)),
            test_loopback_destination,
            forbidden_destinations: Arc::new(forbidden_destinations),
            operator_allowed_private_ips: Arc::new(Vec::new()),
        }
    }

    async fn resolve_complete_chain(
        &self,
        hostname: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(usize, Vec<std::net::IpAddr>), ApplicationError> {
        let mut current = hostname.trim_end_matches('.').to_ascii_lowercase();
        let mut visited = HashSet::from([current.clone()]);
        let mut depth = 0_usize;
        loop {
            ensure_deadline(deadline)?;
            let target = self.resolver.lookup_cname(&current).await?;
            let Some(target) = target else {
                break;
            };
            depth += 1;
            if depth > crate::application::MAX_CNAME_DEPTH {
                return Err(ApplicationError::Disabled);
            }
            let target = target.trim_end_matches('.').to_ascii_lowercase();
            if target.is_empty() || !visited.insert(target.clone()) {
                return Err(ApplicationError::Disabled);
            }
            current = target;
        }
        ensure_deadline(deadline)?;
        let mut addresses = self.resolver.lookup_ips(&current).await?;
        addresses.sort_unstable();
        addresses.dedup();
        Ok((depth, addresses))
    }

    async fn resolve_destination_until(
        &self,
        submission: &MailSubmission,
        deadline: tokio::time::Instant,
    ) -> Result<SocketAddr, ApplicationError> {
        ensure_deadline(deadline)?;
        let (cname_depth, ips) = timeout(
            CONNECT_TIMEOUT,
            self.resolve_complete_chain(&submission.endpoint.hostname, deadline),
        )
        .await
        .map_err(|_| ApplicationError::ExternalStore)??;
        if self.test_loopback_destination {
            if submission.endpoint.hostname != "localhost"
                || ips.is_empty()
                || ips.iter().any(|address| !address.is_loopback())
            {
                return Err(ApplicationError::Disabled);
            }
        } else {
            let mut endpoint = submission.endpoint.clone();
            for address in self.operator_allowed_private_ips.iter().copied() {
                if !endpoint.explicitly_allowed_private_ips.contains(&address) {
                    endpoint.explicitly_allowed_private_ips.push(address);
                }
            }
            endpoint.validate_resolution(cname_depth, &ips)?;
        }
        if ips.iter().any(|ip| {
            self.forbidden_destinations
                .contains(SocketAddr::new(*ip, submission.endpoint.port))
        }) {
            return Err(ApplicationError::Disabled);
        }
        ips.first()
            .copied()
            .map(|ip| SocketAddr::new(ip, submission.endpoint.port))
            .ok_or(ApplicationError::ExternalStore)
    }

    #[cfg(test)]
    async fn resolve_destination(
        &self,
        submission: &MailSubmission,
    ) -> Result<SocketAddr, ApplicationError> {
        self.resolve_destination_until(
            submission,
            tokio::time::Instant::now() + SMTP_ATTEMPT_TIMEOUT,
        )
        .await
    }

    async fn resolve_and_connect(
        &self,
        submission: &MailSubmission,
        deadline: tokio::time::Instant,
    ) -> Result<TcpStream, ApplicationError> {
        let pinned = self.resolve_destination_until(submission, deadline).await?;
        ensure_deadline(deadline)?;
        timeout(CONNECT_TIMEOUT, TcpStream::connect(pinned))
            .await
            .map_err(|_| ApplicationError::ExternalStore)?
            .map_err(|_| ApplicationError::ExternalStore)
    }
}

fn ensure_deadline(deadline: tokio::time::Instant) -> Result<(), ApplicationError> {
    if tokio::time::Instant::now() >= deadline {
        Err(ApplicationError::ExternalStore)
    } else {
        Ok(())
    }
}

fn pre_dispatch_failure(phase: &'static str, error: ApplicationError) -> MailTransportOutcome {
    tracing::warn!(
        event = "smtp_transport_stage_failed",
        phase,
        dispatch_uncertain = false,
        "SMTP transport failed before message dispatch"
    );
    match error {
        ApplicationError::Disabled => MailTransportOutcome::PolicyDenied,
        ApplicationError::InvalidInput | ApplicationError::Integrity => {
            MailTransportOutcome::Permanent
        }
        _ => MailTransportOutcome::Transient,
    }
}

fn tls_handshake_failure(phase: &'static str, error: &std::io::Error) -> MailTransportOutcome {
    let policy_failure = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
        .is_some();
    tracing::warn!(
        event = "smtp_transport_stage_failed",
        phase,
        category = tls_error_category(error),
        dispatch_uncertain = false,
        "SMTP TLS handshake failed"
    );
    if policy_failure {
        MailTransportOutcome::PolicyDenied
    } else {
        MailTransportOutcome::Transient
    }
}

fn tls_error_category(error: &std::io::Error) -> &'static str {
    let Some(rustls_error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
    else {
        return "io";
    };
    match rustls_error {
        rustls::Error::InvalidCertificate(certificate) => match certificate {
            rustls::CertificateError::UnknownIssuer => "certificate_unknown_issuer",
            rustls::CertificateError::NotValidForName
            | rustls::CertificateError::NotValidForNameContext { .. } => "certificate_name",
            rustls::CertificateError::NotValidYet
            | rustls::CertificateError::NotValidYetContext { .. } => "certificate_not_yet_valid",
            rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. } => {
                "certificate_expired"
            }
            rustls::CertificateError::InvalidPurpose
            | rustls::CertificateError::InvalidPurposeContext { .. } => "certificate_purpose",
            rustls::CertificateError::BadEncoding => "certificate_bad_encoding",
            rustls::CertificateError::BadSignature => "certificate_bad_signature",
            rustls::CertificateError::UnsupportedSignatureAlgorithmContext { .. }
            | rustls::CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext {
                ..
            } => "certificate_signature_algorithm",
            rustls::CertificateError::UnhandledCriticalExtension => {
                "certificate_critical_extension"
            }
            rustls::CertificateError::Revoked => "certificate_revoked",
            rustls::CertificateError::ApplicationVerificationFailure => {
                "certificate_application_verification"
            }
            rustls::CertificateError::Other(_) => "certificate_other",
            _ => "certificate_revocation",
        },
        rustls::Error::PeerIncompatible(_) => "peer_incompatible",
        rustls::Error::PeerMisbehaved(_) => "peer_misbehaved",
        rustls::Error::AlertReceived(_) => "peer_alert",
        _ => "tls_other",
    }
}

fn is_no_records(error: &NetError) -> bool {
    error.is_no_records_found()
}

impl SafeSmtpTransport {
    #[cfg(test)]
    async fn submit(
        &self,
        submission: MailSubmission,
    ) -> Result<MailTransportOutcome, ApplicationError> {
        self.submit_with_timeout(submission, SMTP_ATTEMPT_TIMEOUT)
            .await
    }

    #[cfg(test)]
    async fn submit_with_timeout(
        &self,
        submission: MailSubmission,
        attempt_timeout: Duration,
    ) -> Result<MailTransportOutcome, ApplicationError> {
        self.submit_until(submission, tokio::time::Instant::now() + attempt_timeout)
            .await
    }

    async fn submit_until(
        &self,
        submission: MailSubmission,
        deadline: tokio::time::Instant,
    ) -> Result<MailTransportOutcome, ApplicationError> {
        if tokio::time::Instant::now() >= deadline {
            return Ok(MailTransportOutcome::Transient);
        }
        let dispatch_started = AtomicBool::new(false);
        if let Ok(result) = tokio::time::timeout_at(
            deadline,
            self.submit_inner(submission, &dispatch_started, deadline),
        )
        .await
        {
            result
        } else {
            let dispatch_uncertain = dispatch_started.load(Ordering::Acquire);
            tracing::warn!(
                event = "smtp_transport_attempt_timed_out",
                dispatch_uncertain,
                "SMTP transport exceeded its whole-attempt deadline"
            );
            Ok(if dispatch_uncertain {
                MailTransportOutcome::Ambiguous
            } else {
                MailTransportOutcome::Transient
            })
        }
    }

    async fn submit_inner(
        &self,
        submission: MailSubmission,
        dispatch_started: &AtomicBool,
        deadline: tokio::time::Instant,
    ) -> Result<MailTransportOutcome, ApplicationError> {
        if let Err(error) = submission.validate() {
            return Ok(pre_dispatch_failure("submission_validate", error));
        }
        macro_rules! pre_dispatch {
            ($operation:expr, $phase:literal) => {
                match $operation {
                    Ok(value) => value,
                    Err(error) => return Ok(pre_dispatch_failure($phase, error)),
                }
            };
        }
        let Ok(hostname) = ServerName::try_from(submission.endpoint.hostname.clone()) else {
            return Ok(pre_dispatch_failure(
                "tls_server_name_validate",
                ApplicationError::InvalidInput,
            ));
        };
        let tcp = match self.resolve_and_connect(&submission, deadline).await {
            Ok(tcp) => tcp,
            Err(error) => return Ok(pre_dispatch_failure("resolve_or_connect", error)),
        };
        match submission.endpoint.tls_mode {
            SmtpTlsMode::ImplicitTls => {
                if ensure_deadline(deadline).is_err() {
                    return Ok(MailTransportOutcome::Transient);
                }
                let tls = match timeout(CONNECT_TIMEOUT, self.tls.connect(hostname, tcp)).await {
                    Ok(Ok(tls)) => tls,
                    Err(_) => {
                        return Ok(pre_dispatch_failure(
                            "implicit_tls_timeout",
                            ApplicationError::ExternalStore,
                        ));
                    }
                    Ok(Err(error)) => {
                        return Ok(tls_handshake_failure("implicit_tls_handshake", &error));
                    }
                };
                Ok(finish_smtp_session(
                    smtp_session(tls, submission, true, dispatch_started, deadline).await,
                ))
            }
            SmtpTlsMode::StartTlsRequired => {
                let mut tcp = tcp;
                let greeting = pre_dispatch!(read_response(&mut tcp, deadline).await, "greeting");
                if greeting / 100 != 2 {
                    return Ok(classify_smtp_status(greeting));
                }
                pre_dispatch!(
                    write_command(&mut tcp, b"EHLO owlauth.invalid\r\n", deadline).await,
                    "ehlo_write"
                );
                let ehlo = pre_dispatch!(
                    read_response_with_capability(&mut tcp, "STARTTLS", deadline).await,
                    "ehlo_response"
                );
                if ehlo.0 / 100 != 2 || !ehlo.1 {
                    return Ok(MailTransportOutcome::PolicyDenied);
                }
                pre_dispatch!(
                    write_command(&mut tcp, b"STARTTLS\r\n", deadline).await,
                    "starttls_write"
                );
                let starttls =
                    pre_dispatch!(read_response(&mut tcp, deadline).await, "starttls_response");
                if starttls != 220 {
                    return Ok(MailTransportOutcome::PolicyDenied);
                }
                if ensure_deadline(deadline).is_err() {
                    return Ok(MailTransportOutcome::Transient);
                }
                let tls = match timeout(CONNECT_TIMEOUT, self.tls.connect(hostname, tcp)).await {
                    Ok(Ok(tls)) => tls,
                    Err(_) => {
                        return Ok(pre_dispatch_failure(
                            "starttls_timeout",
                            ApplicationError::ExternalStore,
                        ));
                    }
                    Ok(Err(error)) => {
                        return Ok(tls_handshake_failure("starttls_handshake", &error));
                    }
                };
                Ok(finish_smtp_session(
                    smtp_session(tls, submission, false, dispatch_started, deadline).await,
                ))
            }
            SmtpTlsMode::DevelopmentLoopbackPlaintext => Ok(finish_smtp_session(
                smtp_session(tcp, submission, true, dispatch_started, deadline).await,
            )),
        }
    }
}

#[async_trait]
impl MailTransport for SafeSmtpTransport {
    async fn submit(
        &self,
        submission: MailSubmission,
        deadline: tokio::time::Instant,
    ) -> Result<MailTransportOutcome, ApplicationError> {
        let adapter_deadline = tokio::time::Instant::now() + SMTP_ATTEMPT_TIMEOUT;
        self.submit_until(submission, deadline.min(adapter_deadline))
            .await
    }
}

#[derive(Debug)]
struct SmtpSessionFailure {
    error: ApplicationError,
    phase: &'static str,
    dispatch_uncertain: bool,
}

fn finish_smtp_session(
    result: Result<MailTransportOutcome, SmtpSessionFailure>,
) -> MailTransportOutcome {
    match result {
        Ok(outcome) => outcome,
        Err(failure) => {
            tracing::warn!(
                event = "smtp_transport_phase_failed",
                phase = failure.phase,
                dispatch_uncertain = failure.dispatch_uncertain,
                "SMTP transport phase failed"
            );
            if failure.dispatch_uncertain {
                MailTransportOutcome::Ambiguous
            } else if failure.error == ApplicationError::ExternalStore {
                MailTransportOutcome::Transient
            } else {
                MailTransportOutcome::Permanent
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmtpCredential {
    username: String,
    password: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "the SMTP command state machine remains linear so dispatch certainty is explicit"
)]
async fn smtp_session<S>(
    mut stream: S,
    submission: MailSubmission,
    read_greeting: bool,
    dispatch_started: &AtomicBool,
    deadline: tokio::time::Instant,
) -> Result<MailTransportOutcome, SmtpSessionFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    macro_rules! phase {
        ($operation:expr, $phase:literal, $uncertain:expr) => {
            match $operation {
                Ok(value) => value,
                Err(error) => {
                    return Err(SmtpSessionFailure {
                        error,
                        phase: $phase,
                        dispatch_uncertain: $uncertain,
                    });
                }
            }
        };
    }

    if read_greeting {
        let greeting = phase!(
            read_response(&mut stream, deadline).await,
            "greeting",
            false
        );
        if greeting / 100 != 2 {
            return Ok(classify_smtp_status(greeting));
        }
    }
    phase!(
        write_command(&mut stream, b"EHLO owlauth.invalid\r\n", deadline).await,
        "ehlo_write",
        false
    );
    let ehlo = phase!(
        read_response(&mut stream, deadline).await,
        "ehlo_response",
        false
    );
    if ehlo / 100 != 2 {
        return Ok(classify_smtp_status(ehlo));
    }

    let mut credential: SmtpCredential = serde_json::from_slice(submission.credential.as_slice())
        .map_err(|_| SmtpSessionFailure {
        error: ApplicationError::Integrity,
        phase: "credential_decode",
        dispatch_uncertain: false,
    })?;
    if credential.username.is_empty()
        || credential.username.len() > 256
        || credential.password.len() > 2048
        || credential.username.contains(['\r', '\n', '\0'])
        || credential.password.contains(['\r', '\n', '\0'])
    {
        return Err(SmtpSessionFailure {
            error: ApplicationError::Integrity,
            phase: "credential_validate",
            dispatch_uncertain: false,
        });
    }
    let mut auth = Zeroizing::new(Vec::with_capacity(
        credential.username.len() + credential.password.len() + 2,
    ));
    auth.push(0);
    auth.extend_from_slice(credential.username.as_bytes());
    auth.push(0);
    auth.extend_from_slice(credential.password.as_bytes());
    let mut auth_command =
        Zeroizing::new(format!("AUTH PLAIN {}\r\n", STANDARD.encode(auth.as_slice())).into_bytes());
    credential.username.zeroize();
    credential.password.zeroize();
    phase!(
        write_command(&mut stream, auth_command.as_slice(), deadline).await,
        "auth_write",
        false
    );
    auth_command.zeroize();
    let auth_status = phase!(
        read_response(&mut stream, deadline).await,
        "auth_response",
        false
    );
    if auth_status / 100 != 2 {
        return Ok(classify_smtp_status(auth_status));
    }

    let mail_from = phase!(
        smtp_path_command("MAIL FROM", &submission.envelope_from),
        "mail_validate",
        false
    );
    phase!(
        write_command(&mut stream, mail_from.as_bytes(), deadline).await,
        "mail_write",
        false
    );
    let status = phase!(
        read_response(&mut stream, deadline).await,
        "mail_response",
        false
    );
    if status / 100 != 2 {
        return Ok(classify_smtp_status(status));
    }
    let recipient = phase!(
        smtp_path_command("RCPT TO", &submission.envelope_to),
        "rcpt_validate",
        false
    );
    phase!(
        write_command(&mut stream, recipient.as_bytes(), deadline).await,
        "rcpt_write",
        false
    );
    let status = phase!(
        read_response(&mut stream, deadline).await,
        "rcpt_response",
        false
    );
    if status / 100 != 2 {
        return Ok(classify_smtp_status(status));
    }
    phase!(
        write_command(&mut stream, b"DATA\r\n", deadline).await,
        "data_command",
        false
    );
    let status = phase!(
        read_response(&mut stream, deadline).await,
        "data_response",
        false
    );
    if status != 354 {
        return Ok(classify_smtp_status(status));
    }

    let mut message = Zeroizing::new(Vec::with_capacity(submission.body.len() + 640));
    message.extend_from_slice(format!("Message-ID: {}\r\n", submission.message_id).as_bytes());
    if let Some(sender_name) = submission.sender_name.as_deref() {
        let encoded_name = STANDARD.encode(sender_name.as_bytes());
        message.extend_from_slice(
            format!(
                "From: =?UTF-8?B?{encoded_name}?= <{}>\r\n",
                submission.envelope_from
            )
            .as_bytes(),
        );
    } else {
        message.extend_from_slice(format!("From: {}\r\n", submission.envelope_from).as_bytes());
    }
    if let Some(reply_to) = submission.reply_to.as_deref() {
        message.extend_from_slice(format!("Reply-To: {reply_to}\r\n").as_bytes());
    }
    message.extend_from_slice(format!("To: {}\r\n", submission.envelope_to).as_bytes());
    message.extend_from_slice(
        b"Subject: OwlAuth email sign-in\r\nAuto-Submitted: auto-generated\r\nContent-Type: text/plain; charset=utf-8\r\nReferrer-Policy: no-referrer\r\n\r\n",
    );
    phase!(
        dot_stuff(&submission.body, &mut message),
        "body_encode",
        false
    );
    if !message.ends_with(b"\r\n") {
        message.extend_from_slice(b"\r\n");
    }
    message.extend_from_slice(b".\r\n");
    if tokio::time::Instant::now() >= deadline {
        return Ok(MailTransportOutcome::Transient);
    }
    // After this point cancellation or connection loss cannot prove that the relay did not
    // accept some or all of the stable Message-ID submission.
    dispatch_started.store(true, Ordering::Release);
    phase!(
        timeout(DATA_TIMEOUT, stream.write_all(message.as_slice()))
            .await
            .map_err(|_| ApplicationError::ExternalStore)
            .and_then(|result| result.map_err(|_| ApplicationError::ExternalStore)),
        "body_write",
        true
    );
    phase!(ensure_deadline(deadline), "body_flush_deadline", true);
    phase!(
        timeout(DATA_TIMEOUT, stream.flush())
            .await
            .map_err(|_| ApplicationError::ExternalStore)
            .and_then(|result| result.map_err(|_| ApplicationError::ExternalStore)),
        "body_flush",
        true
    );
    let status = phase!(
        read_response(&mut stream, deadline).await,
        "final_response",
        true
    );
    // The final response is authoritative. Dropping the stream closes the session without letting
    // a best-effort QUIT overwrite a known delivery outcome.
    Ok(classify_smtp_status(status))
}

fn smtp_path_command(command: &str, value: &str) -> Result<String, ApplicationError> {
    if value.is_empty() || value.len() > 254 || value.contains(['\r', '\n', '\0', '<', '>']) {
        return Err(ApplicationError::Integrity);
    }
    Ok(format!("{command}:<{value}>\r\n"))
}

fn dot_stuff(input: &[u8], output: &mut Vec<u8>) -> Result<(), ApplicationError> {
    if input.contains(&0) {
        return Err(ApplicationError::Integrity);
    }
    let mut line_start = true;
    for byte in input {
        if line_start && *byte == b'.' {
            output.push(b'.');
        }
        output.push(*byte);
        line_start = *byte == b'\n';
    }
    Ok(())
}

async fn write_command<S: AsyncWrite + Unpin>(
    stream: &mut S,
    command: &[u8],
    deadline: tokio::time::Instant,
) -> Result<(), ApplicationError> {
    if command.len() > 4_096 || !command.ends_with(b"\r\n") {
        return Err(ApplicationError::Integrity);
    }
    ensure_deadline(deadline)?;
    timeout(COMMAND_TIMEOUT, stream.write_all(command))
        .await
        .map_err(|_| ApplicationError::ExternalStore)?
        .map_err(|_| ApplicationError::ExternalStore)?;
    ensure_deadline(deadline)?;
    timeout(COMMAND_TIMEOUT, stream.flush())
        .await
        .map_err(|_| ApplicationError::ExternalStore)?
        .map_err(|_| ApplicationError::ExternalStore)
}

async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    deadline: tokio::time::Instant,
) -> Result<u16, ApplicationError> {
    read_response_with_capability(stream, "", deadline)
        .await
        .map(|value| value.0)
}

async fn read_response_with_capability<S: AsyncRead + Unpin>(
    stream: &mut S,
    capability: &str,
    deadline: tokio::time::Instant,
) -> Result<(u16, bool), ApplicationError> {
    read_response_with_timeout_until(stream, capability, COMMAND_TIMEOUT, deadline).await
}

async fn read_response_with_timeout_until<S: AsyncRead + Unpin>(
    stream: &mut S,
    capability: &str,
    response_timeout: Duration,
    deadline: tokio::time::Instant,
) -> Result<(u16, bool), ApplicationError> {
    timeout(response_timeout, async {
        let mut response = Zeroizing::new(Vec::with_capacity(512));
        let mut found = false;
        loop {
            if response.len() >= MAX_RESPONSE_BYTES {
                return Err(ApplicationError::ExternalStore);
            }
            ensure_deadline(deadline)?;
            let mut byte = [0_u8; 1];
            stream
                .read_exact(&mut byte)
                .await
                .map_err(|_| ApplicationError::ExternalStore)?;
            response.push(byte[0]);
            if response.ends_with(b"\r\n") {
                let line_start = response[..response.len() - 2]
                    .iter()
                    .rposition(|value| *value == b'\n')
                    .map_or(0, |index| index + 1);
                let line = &response[line_start..response.len() - 2];
                if line.len() < 4 || !line[..3].iter().all(u8::is_ascii_digit) {
                    return Err(ApplicationError::ExternalStore);
                }
                if !capability.is_empty()
                    && line[4.min(line.len())..]
                        .windows(capability.len())
                        .any(|value| value.eq_ignore_ascii_case(capability.as_bytes()))
                {
                    found = true;
                }
                if line[3] == b' ' {
                    let code = std::str::from_utf8(&line[..3])
                        .ok()
                        .and_then(|value| value.parse::<u16>().ok())
                        .ok_or(ApplicationError::ExternalStore)?;
                    return Ok((code, found));
                }
                if line[3] != b'-' {
                    return Err(ApplicationError::ExternalStore);
                }
            }
        }
    })
    .await
    .map_err(|_| ApplicationError::ExternalStore)?
}

#[cfg(test)]
async fn read_response_with_timeout<S: AsyncRead + Unpin>(
    stream: &mut S,
    capability: &str,
    response_timeout: Duration,
) -> Result<(u16, bool), ApplicationError> {
    read_response_with_timeout_until(
        stream,
        capability,
        response_timeout,
        tokio::time::Instant::now() + response_timeout,
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use tokio::{
        io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
        net::TcpListener,
        sync::oneshot,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[derive(Default)]
    struct FakeDnsResolver {
        cnames: HashMap<String, String>,
        cname_errors: HashSet<String>,
        ips: HashMap<String, Vec<std::net::IpAddr>>,
        rebound_ips: HashMap<String, Vec<std::net::IpAddr>>,
        ip_errors: HashSet<String>,
        cname_delay: Duration,
        cname_calls: AtomicUsize,
        ip_calls: AtomicUsize,
    }

    #[async_trait]
    impl SmtpDnsResolver for FakeDnsResolver {
        async fn lookup_cname(&self, hostname: &str) -> Result<Option<String>, ApplicationError> {
            self.cname_calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.cname_delay);
            if self.cname_errors.contains(hostname) {
                Err(ApplicationError::ExternalStore)
            } else {
                Ok(self.cnames.get(hostname).cloned())
            }
        }

        async fn lookup_ips(
            &self,
            hostname: &str,
        ) -> Result<Vec<std::net::IpAddr>, ApplicationError> {
            let call = self.ip_calls.fetch_add(1, Ordering::SeqCst);
            if self.ip_errors.contains(hostname) {
                Err(ApplicationError::ExternalStore)
            } else if call > 0 {
                Ok(self
                    .rebound_ips
                    .get(hostname)
                    .or_else(|| self.ips.get(hostname))
                    .cloned()
                    .unwrap_or_default())
            } else {
                Ok(self.ips.get(hostname).cloned().unwrap_or_default())
            }
        }
    }

    fn transport_with_resolver(
        roots: RootCertStore,
        resolver: Arc<dyn SmtpDnsResolver>,
    ) -> SafeSmtpTransport {
        let mut transport = SafeSmtpTransport::with_root_certificates(
            roots,
            false,
            ForbiddenSmtpDestinations::default(),
        );
        transport.resolver = resolver;
        transport
    }

    fn resolved_submission(hostname: &str, port: u16) -> MailSubmission {
        let mut submission = loopback_submission(port, SmtpTlsMode::ImplicitTls);
        submission.endpoint.hostname = hostname.to_owned();
        submission.endpoint.explicitly_allowed_private_ips.clear();
        submission
    }

    struct BoundaryStream {
        input: VecDeque<u8>,
        read_calls: usize,
        sleep_on_read: usize,
        write_calls: Arc<AtomicUsize>,
    }

    impl AsyncRead for BoundaryStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.read_calls += 1;
            if self.read_calls == self.sleep_on_read {
                std::thread::sleep(Duration::from_millis(20));
            }
            if let Some(byte) = self.input.pop_front() {
                buffer.put_slice(&[byte]);
                std::task::Poll::Ready(Ok(()))
            } else {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "boundary stream exhausted",
                )))
            }
        }
    }

    impl AsyncWrite for BoundaryStream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn envelope_commands_and_dot_stuffing_reject_injection() {
        assert!(smtp_path_command("RCPT TO", "victim@example.test\r\nDATA").is_err());
        let mut output = Vec::new();
        dot_stuff(b"first\r\n.secret\r\n", &mut output).unwrap();
        assert_eq!(output, b"first\r\n..secret\r\n");
    }

    fn loopback_submission(port: u16, tls_mode: SmtpTlsMode) -> MailSubmission {
        MailSubmission {
            endpoint: crate::application::SmtpEndpoint {
                hostname: "localhost".to_owned(),
                port,
                tls_mode,
                explicitly_allowed_private_ips: Vec::new(),
                development_plaintext_enabled: tls_mode
                    == SmtpTlsMode::DevelopmentLoopbackPlaintext,
            },
            message_id: "<stable-capture@mail.owlauth.invalid>".to_owned(),
            envelope_from: "login@example.test".to_owned(),
            sender_name: None,
            reply_to: None,
            envelope_to: "person@example.test".to_owned(),
            credential: Zeroizing::new(
                br#"{"username":"capture-user","password":"capture-secret"}"#.to_vec(),
            ),
            body: Zeroizing::new(b"first\r\n.secret\r\n".to_vec()),
        }
    }

    async fn read_command<R: AsyncBufRead + Unpin>(reader: &mut R) -> String {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("SMTP command");
        line
    }

    async fn serve_smtp_session<S>(stream: S, send_greeting: bool) -> Vec<u8>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (read, mut write) = tokio::io::split(stream);
        let mut reader = BufReader::new(read);
        if send_greeting {
            write.write_all(b"220 capture ESMTP\r\n").await.unwrap();
        }
        assert!(read_command(&mut reader).await.starts_with("EHLO "));
        write
            .write_all(b"250-capture\r\n250 AUTH PLAIN\r\n")
            .await
            .unwrap();
        assert!(read_command(&mut reader).await.starts_with("AUTH PLAIN "));
        write.write_all(b"235 authenticated\r\n").await.unwrap();
        assert_eq!(
            read_command(&mut reader).await,
            "MAIL FROM:<login@example.test>\r\n"
        );
        write.write_all(b"250 sender ok\r\n").await.unwrap();
        assert_eq!(
            read_command(&mut reader).await,
            "RCPT TO:<person@example.test>\r\n"
        );
        write.write_all(b"250 recipient ok\r\n").await.unwrap();
        assert_eq!(read_command(&mut reader).await, "DATA\r\n");
        write.write_all(b"354 send message\r\n").await.unwrap();
        let mut message = Vec::new();
        loop {
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).await.unwrap();
            if line == b".\r\n" {
                break;
            }
            message.extend_from_slice(&line);
        }
        write.write_all(b"250 queued\r\n").await.unwrap();
        message
    }

    fn test_tls(hostname: &str) -> (RootCertStore, TlsAcceptor) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![hostname.to_owned()]).expect("test certificate");
        let certificate: CertificateDer<'static> = cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone()).expect("test trust root");
        let config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("test server certificate");
        (roots, TlsAcceptor::from(Arc::new(config)))
    }

    async fn spawn_implicit_tls_capture(
        hostname: &str,
    ) -> (u16, RootCertStore, oneshot::Receiver<Vec<u8>>) {
        let (roots, acceptor) = test_tls(hostname);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind implicit TLS SMTP");
        let port = listener.local_addr().expect("TLS capture address").port();
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS SMTP");
            if let Ok(stream) = acceptor.accept(stream).await {
                let _ = sender.send(serve_smtp_session(stream, true).await);
            }
        });
        (port, roots, receiver)
    }

    async fn read_raw_line<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut line = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream
                .read_exact(&mut byte)
                .await
                .expect("SMTP command byte");
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                return line;
            }
        }
    }

    async fn spawn_starttls_capture() -> (u16, RootCertStore, oneshot::Receiver<Vec<u8>>) {
        let (roots, acceptor) = test_tls("localhost");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind STARTTLS SMTP");
        let port = listener.local_addr().expect("STARTTLS address").port();
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept STARTTLS SMTP");
            stream.write_all(b"220 capture ESMTP\r\n").await.unwrap();
            assert!(read_raw_line(&mut stream).await.starts_with(b"EHLO "));
            stream
                .write_all(b"250-capture\r\n250 STARTTLS\r\n")
                .await
                .unwrap();
            assert_eq!(read_raw_line(&mut stream).await, b"STARTTLS\r\n");
            stream.write_all(b"220 begin TLS\r\n").await.unwrap();
            let stream = acceptor.accept(stream).await.expect("STARTTLS handshake");
            sender
                .send(serve_smtp_session(stream, false).await)
                .expect("STARTTLS capture receiver");
        });
        (port, roots, receiver)
    }

    async fn spawn_plaintext_capture() -> (u16, oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind capture SMTP");
        let port = listener.local_addr().expect("capture address").port();
        let (sender, receiver) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept SMTP");
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            write.write_all(b"220 capture ESMTP\r\n").await.unwrap();
            assert!(read_command(&mut reader).await.starts_with("EHLO "));
            write
                .write_all(b"250-capture\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            let auth = read_command(&mut reader).await;
            assert!(auth.starts_with("AUTH PLAIN "));
            write.write_all(b"235 authenticated\r\n").await.unwrap();
            assert_eq!(
                read_command(&mut reader).await,
                "MAIL FROM:<login@example.test>\r\n"
            );
            write.write_all(b"250 sender ok\r\n").await.unwrap();
            assert_eq!(
                read_command(&mut reader).await,
                "RCPT TO:<person@example.test>\r\n"
            );
            write.write_all(b"250 recipient ok\r\n").await.unwrap();
            assert_eq!(read_command(&mut reader).await, "DATA\r\n");
            write.write_all(b"354 send message\r\n").await.unwrap();
            let mut message = Vec::new();
            loop {
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).await.unwrap();
                if line == b".\r\n" {
                    break;
                }
                message.extend_from_slice(&line);
            }
            write.write_all(b"250 queued\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            sender.send(message).expect("capture receiver");
        });
        (port, receiver)
    }

    #[tokio::test]
    async fn dns_deadline_stops_between_cname_and_address_resolution() {
        let resolver = Arc::new(FakeDnsResolver {
            ips: HashMap::from([(
                "smtp.example.test".to_owned(),
                vec!["8.8.8.8".parse().unwrap()],
            )]),
            cname_delay: Duration::from_millis(20),
            ..FakeDnsResolver::default()
        });
        let transport = transport_with_resolver(RootCertStore::empty(), resolver.clone());

        assert_eq!(
            transport
                .resolve_destination_until(
                    &resolved_submission("smtp.example.test", 465),
                    tokio::time::Instant::now() + Duration::from_millis(15),
                )
                .await,
            Err(ApplicationError::ExternalStore)
        );
        assert_eq!(resolver.cname_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.ip_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resolver_follows_complete_cname_chain_once_and_pins_first_validated_address() {
        let resolver = Arc::new(FakeDnsResolver {
            cnames: HashMap::from([
                (
                    "smtp.example.test".to_owned(),
                    "edge.example.test.".to_owned(),
                ),
                (
                    "edge.example.test".to_owned(),
                    "relay.example.test.".to_owned(),
                ),
            ]),
            ips: HashMap::from([(
                "relay.example.test".to_owned(),
                vec!["9.9.9.9".parse().unwrap(), "8.8.8.8".parse().unwrap()],
            )]),
            ..FakeDnsResolver::default()
        });
        let transport = transport_with_resolver(RootCertStore::empty(), resolver.clone());
        let destination = transport
            .resolve_destination(&resolved_submission("smtp.example.test", 465))
            .await
            .expect("validated destination");
        assert_eq!(destination, "8.8.8.8:465".parse().unwrap());
        assert_eq!(resolver.cname_calls.load(Ordering::SeqCst), 3);
        assert_eq!(resolver.ip_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolver_rejects_cname_cycles_depth_errors_and_nxdomain() {
        let cycle = Arc::new(FakeDnsResolver {
            cnames: HashMap::from([
                (
                    "smtp.example.test".to_owned(),
                    "edge.example.test".to_owned(),
                ),
                (
                    "edge.example.test".to_owned(),
                    "smtp.example.test".to_owned(),
                ),
            ]),
            ..FakeDnsResolver::default()
        });
        assert_eq!(
            transport_with_resolver(RootCertStore::empty(), cycle)
                .resolve_destination(&resolved_submission("smtp.example.test", 465))
                .await,
            Err(ApplicationError::Disabled)
        );

        let mut depth = FakeDnsResolver::default();
        for index in 0..=crate::application::MAX_CNAME_DEPTH {
            depth.cnames.insert(
                format!("smtp-{index}.example.test"),
                format!("smtp-{}.example.test", index + 1),
            );
        }
        assert_eq!(
            transport_with_resolver(RootCertStore::empty(), Arc::new(depth))
                .resolve_destination(&resolved_submission("smtp-0.example.test", 465))
                .await,
            Err(ApplicationError::Disabled)
        );

        let cname_error = Arc::new(FakeDnsResolver {
            cname_errors: HashSet::from(["smtp.example.test".to_owned()]),
            ..FakeDnsResolver::default()
        });
        assert_eq!(
            transport_with_resolver(RootCertStore::empty(), cname_error)
                .resolve_destination(&resolved_submission("smtp.example.test", 465))
                .await,
            Err(ApplicationError::ExternalStore)
        );
        let nxdomain = Arc::new(FakeDnsResolver {
            ip_errors: HashSet::from(["smtp.example.test".to_owned()]),
            ..FakeDnsResolver::default()
        });
        assert_eq!(
            transport_with_resolver(RootCertStore::empty(), nxdomain)
                .resolve_destination(&resolved_submission("smtp.example.test", 465))
                .await,
            Err(ApplicationError::ExternalStore)
        );
    }

    #[tokio::test]
    async fn resolver_validates_every_mixed_address_and_never_re_resolves_before_connect() {
        let mixed = Arc::new(FakeDnsResolver {
            ips: HashMap::from([(
                "smtp.example.test".to_owned(),
                vec!["8.8.8.8".parse().unwrap(), "fd00::1".parse().unwrap()],
            )]),
            ..FakeDnsResolver::default()
        });
        assert_eq!(
            transport_with_resolver(RootCertStore::empty(), mixed)
                .resolve_destination(&resolved_submission("smtp.example.test", 465))
                .await,
            Err(ApplicationError::Disabled)
        );

        let rebinding = Arc::new(FakeDnsResolver {
            ips: HashMap::from([(
                "smtp.example.test".to_owned(),
                vec!["8.8.8.8".parse().unwrap()],
            )]),
            rebound_ips: HashMap::from([(
                "smtp.example.test".to_owned(),
                vec!["127.0.0.1".parse().unwrap()],
            )]),
            ..FakeDnsResolver::default()
        });
        let destination = transport_with_resolver(RootCertStore::empty(), rebinding.clone())
            .resolve_destination(&resolved_submission("smtp.example.test", 465))
            .await
            .expect("first resolution remains pinned");
        assert_eq!(destination, "8.8.8.8:465".parse().unwrap());
        assert_eq!(rebinding.ip_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn pinned_connection_preserves_original_hostname_for_tls_sni_and_validation() {
        let hostname = "smtp.alias.test";
        let (port, roots, capture) = spawn_implicit_tls_capture(hostname).await;
        let resolver = Arc::new(FakeDnsResolver {
            ips: HashMap::from([(hostname.to_owned(), vec!["127.0.0.1".parse().unwrap()])]),
            ..FakeDnsResolver::default()
        });
        let mut submission = resolved_submission(hostname, port);
        submission.endpoint.explicitly_allowed_private_ips = vec!["127.0.0.1".parse().unwrap()];
        let outcome = transport_with_resolver(roots, resolver)
            .submit(submission)
            .await
            .expect("pinned TLS delivery");
        assert_eq!(outcome, MailTransportOutcome::Delivered);
        assert!(!capture.await.expect("SNI capture").is_empty());
    }

    #[tokio::test]
    async fn forbidden_listener_destination_cannot_be_overridden_by_loopback_policy() {
        let (port, _capture) = spawn_plaintext_capture().await;
        let mut forbidden = ForbiddenSmtpDestinations::default();
        forbidden.insert_listener_bind(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));
        forbidden.insert_listener_bind(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)));
        let transport =
            SafeSmtpTransport::with_root_certificates(RootCertStore::empty(), true, forbidden);
        assert_eq!(
            transport
                .submit(loopback_submission(
                    port,
                    SmtpTlsMode::DevelopmentLoopbackPlaintext
                ))
                .await,
            Ok(MailTransportOutcome::PolicyDenied)
        );
    }

    #[test]
    fn wildcard_listener_port_denies_every_interface_and_private_allowlist_cannot_override() {
        let port = 9443;
        let private: std::net::IpAddr = "10.23.45.67".parse().unwrap();
        let public: std::net::IpAddr = "203.0.113.42".parse().unwrap();
        let mut forbidden = ForbiddenSmtpDestinations::default();
        forbidden.insert_listener_bind("0.0.0.0:9443".parse().unwrap());

        let mut endpoint =
            loopback_submission(port, SmtpTlsMode::DevelopmentLoopbackPlaintext).endpoint;
        endpoint.explicitly_allowed_private_ips = vec![private];
        assert!(endpoint.validate_resolution(0, &[private]).is_ok());
        assert!(forbidden.contains(SocketAddr::new(private, port)));
        assert!(forbidden.contains(SocketAddr::new(public, port)));
        assert!(!forbidden.contains(SocketAddr::new(private, port + 1)));
    }

    #[test]
    fn specific_listener_bind_denies_only_the_exact_address_and_port() {
        let mut forbidden = ForbiddenSmtpDestinations::default();
        forbidden.insert_listener_bind("10.23.45.67:9443".parse().unwrap());
        assert!(forbidden.contains("10.23.45.67:9443".parse().unwrap()));
        assert!(!forbidden.contains("10.23.45.68:9443".parse().unwrap()));
        assert!(!forbidden.contains("10.23.45.67:9444".parse().unwrap()));
    }

    #[tokio::test]
    async fn invalid_submission_and_tls_server_name_are_permanent_before_network_io() {
        let mut invalid = loopback_submission(465, SmtpTlsMode::ImplicitTls);
        invalid.endpoint.port = 0;
        assert_eq!(
            SafeSmtpTransport::new().submit(invalid).await,
            Ok(MailTransportOutcome::Permanent)
        );

        let mut invalid_name = loopback_submission(465, SmtpTlsMode::ImplicitTls);
        invalid_name.endpoint.hostname = "not a dns name".to_owned();
        assert_eq!(
            SafeSmtpTransport::new().submit(invalid_name).await,
            Ok(MailTransportOutcome::Permanent)
        );
    }

    #[tokio::test]
    async fn completed_response_at_deadline_cannot_start_the_next_smtp_command() {
        let greeting = b"220 boundary ESMTP\r\n";
        let writes = Arc::new(AtomicUsize::new(0));
        let stream = BoundaryStream {
            input: greeting.iter().copied().collect(),
            read_calls: 0,
            sleep_on_read: greeting.len(),
            write_calls: writes.clone(),
        };
        let dispatch_started = AtomicBool::new(false);
        let outcome = finish_smtp_session(
            smtp_session(
                stream,
                loopback_submission(2525, SmtpTlsMode::DevelopmentLoopbackPlaintext),
                true,
                &dispatch_started,
                tokio::time::Instant::now() + Duration::from_millis(15),
            )
            .await,
        );

        assert_eq!(outcome, MailTransportOutcome::Transient);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert!(!dispatch_started.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn response_deadline_cannot_be_extended_by_drip_fed_bytes() {
        let (mut reader, mut writer) = tokio::io::duplex(64);
        tokio::spawn(async move {
            for byte in b"220 drip ESMTP\r\n" {
                tokio::time::sleep(Duration::from_millis(30)).await;
                if writer.write_all(&[*byte]).await.is_err() {
                    break;
                }
            }
        });

        let started = tokio::time::Instant::now();
        assert_eq!(
            read_response_with_timeout(&mut reader, "", Duration::from_millis(100)).await,
            Err(ApplicationError::ExternalStore)
        );
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn whole_attempt_timeout_preserves_dispatch_certainty() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind pre-dispatch timeout SMTP");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(
            SafeSmtpTransport::new()
                .submit_with_timeout(
                    loopback_submission(port, SmtpTlsMode::DevelopmentLoopbackPlaintext),
                    Duration::from_millis(100),
                )
                .await,
            Ok(MailTransportOutcome::Transient)
        );

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind post-dispatch timeout SMTP");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            write.write_all(b"220 capture ESMTP\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"250 capture\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"235 authenticated\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"250 sender ok\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"250 recipient ok\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"354 send message\r\n").await.unwrap();
            loop {
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).await.unwrap();
                if line == b".\r\n" {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(
            SafeSmtpTransport::new()
                .submit_with_timeout(
                    loopback_submission(port, SmtpTlsMode::DevelopmentLoopbackPlaintext),
                    Duration::from_millis(200),
                )
                .await,
            Ok(MailTransportOutcome::Ambiguous)
        );
    }

    #[tokio::test]
    async fn expired_deadline_and_invalid_pre_data_credential_are_not_ambiguous() {
        assert_eq!(
            SafeSmtpTransport::new()
                .submit_until(
                    loopback_submission(9, SmtpTlsMode::DevelopmentLoopbackPlaintext),
                    tokio::time::Instant::now() - Duration::from_millis(1),
                )
                .await,
            Ok(MailTransportOutcome::Transient)
        );

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind credential validation SMTP");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            write.write_all(b"220 capture ESMTP\r\n").await.unwrap();
            assert!(read_command(&mut reader).await.starts_with("EHLO "));
            write
                .write_all(b"250-capture\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
        });
        let mut submission = loopback_submission(port, SmtpTlsMode::DevelopmentLoopbackPlaintext);
        submission.credential = Zeroizing::new(b"not-json".to_vec());
        assert_eq!(
            SafeSmtpTransport::new().submit(submission).await,
            Ok(MailTransportOutcome::Permanent)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pre_data_disconnect_is_transient_but_missing_final_response_is_ambiguous() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind pre-DATA disconnect");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });
        assert_eq!(
            SafeSmtpTransport::new()
                .submit(loopback_submission(
                    port,
                    SmtpTlsMode::DevelopmentLoopbackPlaintext,
                ))
                .await,
            Ok(MailTransportOutcome::Transient)
        );

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind post-DATA disconnect");
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            write.write_all(b"220 capture ESMTP\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"250 capture\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"235 authenticated\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"250 sender ok\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"250 recipient ok\r\n").await.unwrap();
            let _ = read_command(&mut reader).await;
            write.write_all(b"354 send message\r\n").await.unwrap();
            loop {
                let mut line = Vec::new();
                reader.read_until(b'\n', &mut line).await.unwrap();
                if line == b".\r\n" {
                    break;
                }
            }
            // Drop without a final response: the server may already have committed the message.
        });
        assert_eq!(
            SafeSmtpTransport::new()
                .submit(loopback_submission(
                    port,
                    SmtpTlsMode::DevelopmentLoopbackPlaintext,
                ))
                .await,
            Ok(MailTransportOutcome::Ambiguous)
        );
    }

    #[tokio::test]
    async fn production_transport_delivers_to_explicit_loopback_capture_with_stable_message_id() {
        let (port, capture) = spawn_plaintext_capture().await;
        let outcome = SafeSmtpTransport::new()
            .submit(loopback_submission(
                port,
                SmtpTlsMode::DevelopmentLoopbackPlaintext,
            ))
            .await
            .expect("submit to controlled capture");
        assert_eq!(outcome, MailTransportOutcome::Delivered);
        let message = capture.await.expect("captured message");
        let message = String::from_utf8(message).expect("SMTP message UTF-8");
        assert!(message.contains("Message-ID: <stable-capture@mail.owlauth.invalid>\r\n"));
        assert!(message.contains("From: login@example.test\r\n"));
        assert!(!message.contains("Reply-To:"));
        assert!(message.contains("first\r\n..secret\r\n"));
        assert!(!message.contains("capture-user"));
        assert!(!message.contains("capture-secret"));
    }

    #[tokio::test]
    async fn sender_display_name_and_reply_to_are_encoded_without_changing_the_envelope() {
        for (sender_name, expected_name) in [
            ("OwlAuth Team", "T3dsQXV0aCBUZWFt"),
            ("OwlAuth 登录", "T3dsQXV0aCDnmbvlvZU="),
        ] {
            let (port, capture) = spawn_plaintext_capture().await;
            let mut submission =
                loopback_submission(port, SmtpTlsMode::DevelopmentLoopbackPlaintext);
            submission.sender_name = Some(sender_name.to_owned());
            submission.reply_to = Some("support@example.test".to_owned());
            assert_eq!(
                SafeSmtpTransport::new().submit(submission).await,
                Ok(MailTransportOutcome::Delivered)
            );
            let message = String::from_utf8(capture.await.unwrap()).unwrap();
            assert!(message.contains(&format!(
                "From: =?UTF-8?B?{expected_name}?= <login@example.test>\r\n"
            )));
            assert!(message.contains("Reply-To: support@example.test\r\n"));
        }

        let mut injected = loopback_submission(2525, SmtpTlsMode::DevelopmentLoopbackPlaintext);
        injected.sender_name = Some("trusted\r\nBcc: victim@example.test".to_owned());
        assert_eq!(injected.validate(), Err(ApplicationError::InvalidInput));
        injected.sender_name = None;
        injected.reply_to = Some("reply@example.test\nBcc: victim@example.test".to_owned());
        assert_eq!(injected.validate(), Err(ApplicationError::InvalidInput));
    }

    #[tokio::test]
    async fn production_transport_validates_and_delivers_over_implicit_tls() {
        let (port, roots, capture) = spawn_implicit_tls_capture("localhost").await;
        let outcome = SafeSmtpTransport::with_test_loopback_destination(roots)
            .submit(loopback_submission(port, SmtpTlsMode::ImplicitTls))
            .await
            .expect("implicit TLS delivery");
        assert_eq!(outcome, MailTransportOutcome::Delivered);
        assert!(
            String::from_utf8(capture.await.expect("implicit TLS capture"))
                .unwrap()
                .contains("Message-ID: <stable-capture@mail.owlauth.invalid>")
        );
    }

    #[tokio::test]
    async fn production_transport_requires_and_delivers_over_starttls() {
        let (port, roots, capture) = spawn_starttls_capture().await;
        let outcome = SafeSmtpTransport::with_test_loopback_destination(roots)
            .submit(loopback_submission(port, SmtpTlsMode::StartTlsRequired))
            .await
            .expect("STARTTLS delivery");
        assert_eq!(outcome, MailTransportOutcome::Delivered);
        assert!(!capture.await.expect("STARTTLS capture").is_empty());
    }

    #[tokio::test]
    async fn production_transport_rejects_untrusted_tls_certificate() {
        let (port, _roots, _capture) = spawn_implicit_tls_capture("localhost").await;
        assert_eq!(
            SafeSmtpTransport::with_test_loopback_destination(
                webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .cloned()
                    .collect::<RootCertStore>(),
            )
            .submit(loopback_submission(port, SmtpTlsMode::ImplicitTls))
            .await,
            Ok(MailTransportOutcome::PolicyDenied)
        );
    }

    #[tokio::test]
    async fn production_transport_rejects_tls_hostname_mismatch() {
        let (port, roots, _capture) = spawn_implicit_tls_capture("smtp.invalid").await;
        assert_eq!(
            SafeSmtpTransport::with_test_loopback_destination(roots)
                .submit(loopback_submission(port, SmtpTlsMode::ImplicitTls))
                .await,
            Ok(MailTransportOutcome::PolicyDenied)
        );
    }

    #[tokio::test]
    async fn production_transport_rejects_starttls_downgrade() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind downgrade SMTP");
        let port = listener.local_addr().expect("downgrade address").port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept SMTP");
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            write.write_all(b"220 capture ESMTP\r\n").await.unwrap();
            assert!(read_command(&mut reader).await.starts_with("EHLO "));
            write
                .write_all(b"250-capture\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
        });
        let outcome = SafeSmtpTransport::with_test_loopback_destination(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
                .collect::<RootCertStore>(),
        )
        .submit(loopback_submission(port, SmtpTlsMode::StartTlsRequired))
        .await
        .expect("downgrade has a classified outcome");
        assert_eq!(outcome, MailTransportOutcome::PolicyDenied);
    }
}
