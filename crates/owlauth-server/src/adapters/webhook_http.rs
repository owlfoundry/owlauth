use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use hickory_resolver::{
    TokioResolver,
    net::NetError,
    proto::rr::{RData, RecordType},
};
use reqwest::{Certificate, Client, redirect::Policy};

use crate::{
    application::{
        ApplicationError, SmtpEndpoint, SmtpTlsMode, WebhookEndpointValidator, WebhookTransport,
        WebhookTransportOutcome,
    },
    domain::WebhookDeliveryOutcome,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

#[async_trait]
trait WebhookDnsResolver: Send + Sync {
    async fn lookup_cname(&self, hostname: &str) -> Result<Option<String>, ApplicationError>;
    async fn lookup_ips(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>, ApplicationError>;
}

struct SystemWebhookDnsResolver(TokioResolver);

#[async_trait]
impl WebhookDnsResolver for SystemWebhookDnsResolver {
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
pub(crate) struct SafeWebhookTransport {
    resolver: Arc<dyn WebhookDnsResolver>,
    forbidden_listener_addresses: Arc<Vec<SocketAddr>>,
    explicitly_allowed_private_ips: Arc<Vec<std::net::IpAddr>>,
    extra_root_certificate: Option<Certificate>,
}

impl SafeWebhookTransport {
    pub(crate) fn new(
        listener_addresses: impl IntoIterator<Item = SocketAddr>,
        explicitly_allowed_private_ips: Vec<std::net::IpAddr>,
        extra_root_cert_der: Option<&[u8]>,
    ) -> Self {
        Self {
            resolver: Arc::new(SystemWebhookDnsResolver(
                TokioResolver::builder_tokio()
                    .expect("system DNS resolver configuration is readable")
                    .build()
                    .expect("system DNS resolver can be constructed"),
            )),
            forbidden_listener_addresses: Arc::new(listener_addresses.into_iter().collect()),
            explicitly_allowed_private_ips: Arc::new(explicitly_allowed_private_ips),
            extra_root_certificate: extra_root_cert_der.map(|certificate| {
                Certificate::from_der(certificate)
                    .expect("validated webhook extra root certificate is parseable")
            }),
        }
    }

    async fn resolve_complete_chain(
        &self,
        hostname: &str,
    ) -> Result<(usize, Vec<std::net::IpAddr>), ApplicationError> {
        let mut current = hostname.trim_end_matches('.').to_ascii_lowercase();
        let mut visited = HashSet::from([current.clone()]);
        let mut depth = 0_usize;
        loop {
            let Some(target) = self.resolver.lookup_cname(&current).await? else {
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
        let mut addresses = self.resolver.lookup_ips(&current).await?;
        addresses.sort_unstable();
        addresses.dedup();
        Ok((depth, addresses))
    }

    async fn resolve_destination(
        &self,
        endpoint_url: &str,
    ) -> Result<(url::Url, String, SocketAddr), ApplicationError> {
        let url = url::Url::parse(endpoint_url).map_err(|_| ApplicationError::InvalidInput)?;
        if url.scheme() != "https"
            || url.port().is_some_and(|port| port == 0)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ApplicationError::InvalidInput);
        }
        let hostname = url
            .host_str()
            .filter(|host| host.parse::<std::net::IpAddr>().is_err())
            .ok_or(ApplicationError::InvalidInput)?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or(ApplicationError::InvalidInput)?;
        let (cname_depth, addresses) = self.resolve_complete_chain(&hostname).await?;
        SmtpEndpoint {
            hostname: hostname.clone(),
            port,
            tls_mode: SmtpTlsMode::ImplicitTls,
            explicitly_allowed_private_ips: (*self.explicitly_allowed_private_ips).clone(),
            development_plaintext_enabled: false,
        }
        .validate_resolution(cname_depth, &addresses)?;
        if addresses.iter().any(|address| {
            self.forbidden_listener_addresses.iter().any(|listener| {
                listener.port() == port
                    && (listener.ip().is_unspecified() || listener.ip() == *address)
            })
        }) {
            return Err(ApplicationError::Disabled);
        }
        let destination = addresses
            .first()
            .copied()
            .map(|address| SocketAddr::new(address, port))
            .ok_or(ApplicationError::Disabled)?;
        Ok((url, hostname, destination))
    }

    async fn send(
        &self,
        endpoint_url: &str,
        event_id: &str,
        attempt_timestamp: i64,
        signature: &str,
        raw_body: &[u8],
    ) -> Result<u16, WebhookSendFailure> {
        let (url, hostname, destination) = self
            .resolve_destination(endpoint_url)
            .await
            .map_err(WebhookSendFailure::before_dispatch)?;
        let mut client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(ATTEMPT_TIMEOUT)
            .redirect(Policy::none())
            .no_proxy()
            .resolve(&hostname, destination);
        if let Some(certificate) = &self.extra_root_certificate {
            client = client.add_root_certificate(certificate.clone());
        }
        let client = client.build().map_err(|_| WebhookSendFailure::Transient)?;
        let response = client
            .post(url)
            .header("OwlAuth-Webhook-Id", event_id)
            .header("OwlAuth-Webhook-Timestamp", attempt_timestamp.to_string())
            .header("OwlAuth-Webhook-Signature", signature)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(raw_body.to_vec())
            .send()
            .await
            .map_err(|_| WebhookSendFailure::Ambiguous)?;
        Ok(response.status().as_u16())
    }
}

#[async_trait]
impl WebhookEndpointValidator for SafeWebhookTransport {
    async fn validate(&self, endpoint_url: &str) -> Result<(), ApplicationError> {
        self.resolve_destination(endpoint_url).await.map(|_| ())
    }
}

#[async_trait]
impl WebhookTransport for SafeWebhookTransport {
    async fn post(
        &self,
        endpoint_url: &str,
        event_id: &str,
        attempt_timestamp: i64,
        signature: &str,
        raw_body: &[u8],
    ) -> WebhookTransportOutcome {
        let started = std::time::Instant::now();
        let (outcome, http_status) = match self
            .send(
                endpoint_url,
                event_id,
                attempt_timestamp,
                signature,
                raw_body,
            )
            .await
        {
            Ok(status) => (
                WebhookDeliveryOutcome::from_http_status(status),
                Some(status),
            ),
            Err(WebhookSendFailure::Permanent) => (WebhookDeliveryOutcome::Permanent, None),
            Err(WebhookSendFailure::Transient) => (WebhookDeliveryOutcome::Transient, None),
            Err(WebhookSendFailure::Ambiguous) => (WebhookDeliveryOutcome::Ambiguous, None),
        };
        WebhookTransportOutcome {
            outcome,
            http_status,
            duration_millis: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WebhookSendFailure {
    Permanent,
    Transient,
    Ambiguous,
}

impl WebhookSendFailure {
    const fn before_dispatch(error: ApplicationError) -> Self {
        match error {
            ApplicationError::InvalidInput | ApplicationError::Disabled => Self::Permanent,
            _ => Self::Transient,
        }
    }
}

fn is_no_records(error: &NetError) -> bool {
    error.is_no_records_found()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    struct FakeResolver {
        cnames: HashMap<String, String>,
        addresses: HashMap<String, Vec<IpAddr>>,
        failed_host: Option<String>,
    }

    #[async_trait]
    impl WebhookDnsResolver for FakeResolver {
        async fn lookup_cname(&self, hostname: &str) -> Result<Option<String>, ApplicationError> {
            if self.failed_host.as_deref() == Some(hostname) {
                return Err(ApplicationError::ExternalStore);
            }
            Ok(self.cnames.get(hostname).cloned())
        }

        async fn lookup_ips(&self, hostname: &str) -> Result<Vec<IpAddr>, ApplicationError> {
            if self.failed_host.as_deref() == Some(hostname) {
                return Err(ApplicationError::ExternalStore);
            }
            self.addresses
                .get(hostname)
                .cloned()
                .ok_or(ApplicationError::ExternalStore)
        }
    }

    struct RebindingResolver(AtomicUsize);

    #[async_trait]
    impl WebhookDnsResolver for RebindingResolver {
        async fn lookup_cname(&self, _hostname: &str) -> Result<Option<String>, ApplicationError> {
            Ok(None)
        }

        async fn lookup_ips(&self, _hostname: &str) -> Result<Vec<IpAddr>, ApplicationError> {
            let lookup = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(if lookup == 0 {
                vec!["1.1.1.1".parse().unwrap()]
            } else {
                vec!["10.0.0.10".parse().unwrap()]
            })
        }
    }

    fn transport(
        resolver: Arc<dyn WebhookDnsResolver>,
        listeners: Vec<SocketAddr>,
        allowed_private_ips: Vec<IpAddr>,
    ) -> SafeWebhookTransport {
        SafeWebhookTransport {
            resolver,
            forbidden_listener_addresses: Arc::new(listeners),
            explicitly_allowed_private_ips: Arc::new(allowed_private_ips),
            extra_root_certificate: None,
        }
    }

    fn fake_resolver(
        cnames: &[(&str, &str)],
        addresses: &[(&str, &[&str])],
    ) -> Arc<dyn WebhookDnsResolver> {
        Arc::new(FakeResolver {
            cnames: cnames
                .iter()
                .map(|(source, target)| ((*source).to_owned(), (*target).to_owned()))
                .collect(),
            addresses: addresses
                .iter()
                .map(|(host, values)| {
                    (
                        (*host).to_owned(),
                        values
                            .iter()
                            .map(|value| value.parse::<IpAddr>().unwrap())
                            .collect(),
                    )
                })
                .collect(),
            failed_host: None,
        })
    }

    #[tokio::test]
    async fn complete_cname_chain_is_canonicalized_and_pinned() {
        let transport = transport(
            fake_resolver(
                &[
                    ("hooks.example", "edge.example."),
                    ("edge.example", "final.example"),
                ],
                &[("final.example", &["2606:4700:4700::1111", "1.1.1.1"])],
            ),
            Vec::new(),
            Vec::new(),
        );
        let (url, hostname, destination) = transport
            .resolve_destination("https://hooks.example/events")
            .await
            .unwrap();
        assert_eq!(url.as_str(), "https://hooks.example/events");
        assert_eq!(hostname, "hooks.example");
        assert_eq!(destination.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(destination.port(), 443);
    }

    #[tokio::test]
    async fn one_denied_answer_denies_mixed_mapped_and_cross_listener_destinations() {
        let mixed = transport(
            fake_resolver(&[], &[("hooks.example", &["1.1.1.1", "10.0.0.8"])]),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            mixed.validate("https://hooks.example/events").await,
            Err(ApplicationError::Disabled)
        );

        let mapped = transport(
            fake_resolver(&[], &[("hooks.example", &["::ffff:10.0.0.8"])]),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            mapped.validate("https://hooks.example/events").await,
            Err(ApplicationError::Disabled)
        );

        let listener_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let cross_listener = transport(
            fake_resolver(&[], &[("hooks.example", &["1.1.1.1", "127.0.0.1"])]),
            vec![SocketAddr::new(listener_ip, 443)],
            vec![listener_ip],
        );
        assert_eq!(
            cross_listener
                .validate("https://hooks.example/events")
                .await,
            Err(ApplicationError::Disabled)
        );
    }

    #[tokio::test]
    async fn exact_private_allowlist_does_not_relax_other_addresses() {
        let allowed: IpAddr = "10.0.0.8".parse().unwrap();
        let allowed_transport = transport(
            fake_resolver(&[], &[("hooks.example", &["10.0.0.8"])]),
            Vec::new(),
            vec![allowed],
        );
        assert!(
            allowed_transport
                .validate("https://hooks.example/events")
                .await
                .is_ok()
        );

        let denied = transport(
            fake_resolver(&[], &[("hooks.example", &["10.0.0.9"])]),
            Vec::new(),
            vec![allowed],
        );
        assert_eq!(
            denied.validate("https://hooks.example/events").await,
            Err(ApplicationError::Disabled)
        );
    }

    #[tokio::test]
    async fn every_attempt_resolves_again_and_pre_dispatch_failures_are_not_ambiguous() {
        let rebinding = transport(
            Arc::new(RebindingResolver(AtomicUsize::new(0))),
            Vec::new(),
            Vec::new(),
        );
        assert!(
            rebinding
                .validate("https://hooks.example/events")
                .await
                .is_ok()
        );
        let denied = rebinding
            .post(
                "https://hooks.example/events",
                "event",
                1,
                "v1=signature",
                b"{}",
            )
            .await;
        assert_eq!(denied.outcome, WebhookDeliveryOutcome::Permanent);
        assert_eq!(denied.http_status, None);

        let dns_failure = transport(
            Arc::new(FakeResolver {
                cnames: HashMap::new(),
                addresses: HashMap::new(),
                failed_host: Some("hooks.example".to_owned()),
            }),
            Vec::new(),
            Vec::new(),
        );
        let failed = dns_failure
            .post(
                "https://hooks.example/events",
                "event",
                1,
                "v1=signature",
                b"{}",
            )
            .await;
        assert_eq!(failed.outcome, WebhookDeliveryOutcome::Transient);
        assert_eq!(failed.http_status, None);
    }

    #[tokio::test]
    async fn invalid_or_cyclic_endpoint_is_permanent_before_dispatch() {
        let cyclic = transport(
            fake_resolver(
                &[
                    ("hooks.example", "edge.example"),
                    ("edge.example", "hooks.example"),
                ],
                &[],
            ),
            Vec::new(),
            Vec::new(),
        );
        let failed = cyclic
            .post(
                "https://hooks.example/events",
                "event",
                1,
                "v1=signature",
                b"{}",
            )
            .await;
        assert_eq!(failed.outcome, WebhookDeliveryOutcome::Permanent);
        assert_eq!(failed.http_status, None);

        assert_eq!(
            cyclic
                .validate("https://user:password@hooks.example/events#fragment")
                .await,
            Err(ApplicationError::InvalidInput)
        );
    }
}
