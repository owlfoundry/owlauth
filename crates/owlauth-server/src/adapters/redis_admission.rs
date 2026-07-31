use std::time::Duration;

use async_trait::async_trait;
use redis::{
    Script,
    aio::{ConnectionManager, ConnectionManagerConfig},
};
use tokio::{
    sync::{Mutex, RwLock},
    time::{Instant, timeout_at},
};

use crate::application::{
    AdmissionBucket, AdmissionDecision, AdmissionRejectionReason, DistributedAdmissionCounter,
    DistributedAdmissionError,
};

const ATOMIC_FIXED_WINDOW: &str = r"
local server_time = redis.call('TIME')
local now = tonumber(server_time[1]) * 1000 + math.floor(tonumber(server_time[2]) / 1000)
local retry = 0
local window_keys = {}
local ttls = {}
for index, base_key in ipairs(KEYS) do
  local limit = tonumber(ARGV[(index - 1) * 2 + 1])
  local window_ms = tonumber(ARGV[(index - 1) * 2 + 2])
  local window = math.floor(now / window_ms)
  local ttl = window_ms - (now % window_ms)
  local key = base_key .. ':' .. window
  window_keys[index] = key
  ttls[index] = ttl
  local current = tonumber(redis.call('GET', key) or '0')
  if current >= limit and ttl > retry then
    retry = ttl
  end
end
if retry > 0 then
  return {0, retry}
end
for index, key in ipairs(window_keys) do
  redis.call('INCR', key)
  redis.call('PEXPIRE', key, ttls[index])
end
return {1, 0}
";

const MANAGER_RECOVERY_RETRIES: usize = 2;

#[derive(Clone)]
struct ManagerGeneration {
    number: u64,
    connection: ConnectionManager,
}

#[derive(Default)]
struct ManagerState {
    next_generation: u64,
    current: Option<ManagerGeneration>,
}

pub(crate) struct RedisAdmissionCounter {
    client: redis::Client,
    manager_state: RwLock<ManagerState>,
    manager_initialization: Mutex<()>,
    operation_timeout: Duration,
}

impl RedisAdmissionCounter {
    pub(crate) fn new(
        redis_url: &str,
        operation_timeout: Duration,
    ) -> Result<Self, DistributedAdmissionError> {
        let client = redis::Client::open(redis_url).map_err(|_| DistributedAdmissionError)?;
        Ok(Self {
            client,
            manager_state: RwLock::new(ManagerState::default()),
            manager_initialization: Mutex::new(()),
            operation_timeout,
        })
    }

    async fn current_manager(&self) -> Result<ManagerGeneration, DistributedAdmissionError> {
        if let Some(current) = self.manager_state.read().await.current.clone() {
            return Ok(current);
        }

        // Only manager creation is serialized. Healthy requests clone the single current manager
        // under the read lock and continue concurrently on its multiplexed connection.
        let _initialization = self.manager_initialization.lock().await;
        if let Some(current) = self.manager_state.read().await.current.clone() {
            return Ok(current);
        }

        let generation = {
            let mut state = self.manager_state.write().await;
            let generation = state
                .next_generation
                .checked_add(1)
                .ok_or(DistributedAdmissionError)?;
            state.next_generation = generation;
            generation
        };
        let connection = ConnectionManager::new_with_config(
            self.client.clone(),
            manager_config(self.operation_timeout),
        )
        .await
        .map_err(|_| DistributedAdmissionError)?;
        let current = ManagerGeneration {
            number: generation,
            connection,
        };
        self.manager_state.write().await.current = Some(current.clone());
        Ok(current)
    }

    async fn invalidate(&self, failed_generation: u64) {
        let mut state = self.manager_state.write().await;
        if state
            .current
            .as_ref()
            .is_some_and(|current| current.number == failed_generation)
        {
            state.current = None;
        }
    }
}

fn manager_config(operation_timeout: Duration) -> ConnectionManagerConfig {
    let maximum_delay_millis = u64::try_from(operation_timeout.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    ConnectionManagerConfig::new()
        .set_number_of_retries(MANAGER_RECOVERY_RETRIES)
        .set_factor(maximum_delay_millis.saturating_div(4).max(1))
        .set_max_delay(maximum_delay_millis)
        .set_connection_timeout(operation_timeout)
        .set_response_timeout(operation_timeout)
}

#[async_trait]
impl DistributedAdmissionCounter for RedisAdmissionCounter {
    async fn evaluate(
        &self,
        buckets: &[AdmissionBucket],
    ) -> Result<AdmissionDecision, DistributedAdmissionError> {
        if buckets.is_empty() {
            return Err(DistributedAdmissionError);
        }
        let deadline = Instant::now()
            .checked_add(self.operation_timeout)
            .ok_or(DistributedAdmissionError)?;
        let manager = timeout_at(deadline, self.current_manager())
            .await
            .map_err(|_| DistributedAdmissionError)??;
        let operation = async {
            let mut connection = manager.connection.clone();
            let script = Script::new(ATOMIC_FIXED_WINDOW);
            let mut invocation = script.prepare_invoke();
            for bucket in buckets {
                invocation.key(&bucket.key);
            }
            for bucket in buckets {
                invocation.arg(bucket.limit).arg(bucket.window_millis);
            }
            let response: Vec<i64> = invocation
                .invoke_async(&mut connection)
                .await
                .map_err(|_| DistributedAdmissionError)?;
            parse_response(&response)
        };
        let result = timeout_at(deadline, operation)
            .await
            .unwrap_or(Err(DistributedAdmissionError));
        if result.is_err() {
            // The outer deadline can cancel a command before redis-rs observes a recoverable I/O
            // error. Retire that manager ourselves, but only if it is still the current generation:
            // a late failure from an old clone must never clear a replacement manager.
            self.invalidate(manager.number).await;
        }
        result
    }
}

fn parse_response(response: &[i64]) -> Result<AdmissionDecision, DistributedAdmissionError> {
    match response {
        [1, 0] => Ok(AdmissionDecision::Allowed),
        [0, retry] if *retry > 0 => Ok(AdmissionDecision::Rejected {
            retry_after_seconds: u64::try_from(*retry)
                .map_err(|_| DistributedAdmissionError)?
                .div_ceil(1_000)
                .clamp(1, 60),
            reason: AdmissionRejectionReason::Quota,
        }),
        _ => Err(DistributedAdmissionError),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
    };

    use super::*;
    use crate::application::{AdmissionEndpoint, AdmissionService, MonotonicClock};

    struct TestClock(AtomicU64);

    impl TestClock {
        fn new(seconds: u64) -> Self {
            Self(AtomicU64::new(seconds.saturating_mul(1_000)))
        }

        fn set(&self, seconds: u64) {
            self.0
                .store(seconds.saturating_mul(1_000), Ordering::Relaxed);
        }
    }

    impl MonotonicClock for TestClock {
        fn elapsed_millis(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    async fn current_generation(counter: &RedisAdmissionCounter) -> Option<u64> {
        counter
            .manager_state
            .read()
            .await
            .current
            .as_ref()
            .map(|current| current.number)
    }

    #[test]
    fn lua_checks_every_bucket_before_incrementing_any_bucket() {
        let first_check = ATOMIC_FIXED_WINDOW.find("if retry > 0").unwrap();
        let first_increment = ATOMIC_FIXED_WINDOW.find("redis.call('INCR'").unwrap();
        assert!(first_check < first_increment);
        assert!(ATOMIC_FIXED_WINDOW.contains("redis.call('TIME')"));
        assert!(ATOMIC_FIXED_WINDOW.contains("PEXPIRE"));
    }

    #[tokio::test]
    async fn redis_eight_coordinates_two_instances_atomically_and_recovers_after_flush() {
        let container = GenericImage::new("redis", "8-bookworm")
            .with_exposed_port(6379.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .start()
            .await
            .expect("Redis 8 test container must start");
        let port = container.get_host_port_ipv4(6379.tcp()).await.unwrap();
        let url = format!("redis://127.0.0.1:{port}/");
        let first = RedisAdmissionCounter::new(&url, Duration::from_secs(1)).unwrap();
        let second = RedisAdmissionCounter::new(&url, Duration::from_secs(1)).unwrap();
        let bucket = |key: &str| AdmissionBucket {
            key: key.to_owned(),
            limit: 1,
            window_millis: 60_000,
        };

        assert_eq!(
            first.evaluate(&[bucket("coordination")]).await.unwrap(),
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            second.evaluate(&[bucket("coordination")]).await.unwrap(),
            AdmissionDecision::Rejected { .. }
        ));

        let client = redis::Client::open(url.as_str()).unwrap();
        let mut connection = client.get_multiplexed_async_connection().await.unwrap();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("coordination:*")
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
        let ttl: i64 = redis::cmd("PTTL")
            .arg(&keys[0])
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!((1..=60_000).contains(&ttl));

        assert_eq!(
            first.evaluate(&[bucket("full")]).await.unwrap(),
            AdmissionDecision::Allowed
        );
        assert!(matches!(
            second
                .evaluate(&[bucket("fresh"), bucket("full")])
                .await
                .unwrap(),
            AdmissionDecision::Rejected { .. }
        ));
        assert_eq!(
            second.evaluate(&[bucket("fresh")]).await.unwrap(),
            AdmissionDecision::Allowed
        );

        redis::cmd("FLUSHALL")
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        assert_eq!(
            second.evaluate(&[bucket("coordination")]).await.unwrap(),
            AdmissionDecision::Allowed
        );
    }

    #[tokio::test]
    async fn two_services_bound_concurrent_flush_and_disconnect_transitions() {
        let container = GenericImage::new("redis", "8-bookworm")
            .with_exposed_port(6379.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .start()
            .await
            .expect("Redis 8 test container must start");
        let port = container.get_host_port_ipv4(6379.tcp()).await.unwrap();
        let url = format!("redis://127.0.0.1:{port}/");
        let service = |namespace: &str| {
            let counter =
                Arc::new(RedisAdmissionCounter::new(&url, Duration::from_millis(500)).unwrap())
                    as Arc<dyn DistributedAdmissionCounter>;
            Arc::new(AdmissionService::new(
                namespace.to_owned(),
                [7; 32],
                2,
                Some(counter),
            ))
        };

        let first = service("flush-proof");
        let second = service("flush-proof");
        let mut requests = tokio::task::JoinSet::new();
        for service in [Arc::clone(&first), Arc::clone(&second)] {
            for _ in 0..32 {
                let service = Arc::clone(&service);
                requests.spawn(async move {
                    service
                        .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                        .await
                });
            }
        }
        let mut allowed = 0;
        while let Some(result) = requests.join_next().await {
            if result.unwrap() == AdmissionDecision::Allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 64);

        let client = redis::Client::open(url.as_str()).unwrap();
        let mut connection = client.get_multiplexed_async_connection().await.unwrap();
        redis::cmd("FLUSHALL")
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        for service in [&first, &second] {
            assert!(matches!(
                service
                    .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                    .await,
                AdmissionDecision::Rejected { .. }
            ));
        }

        let unused = service("disconnect-proof");
        let used = service("disconnect-proof");
        for _ in 0..32 {
            assert_eq!(
                used.admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                    .await,
                AdmissionDecision::Allowed
            );
        }
        let _ = redis::cmd("SHUTDOWN")
            .arg("NOSAVE")
            .query_async::<()>(&mut connection)
            .await;
        for _ in 0..32 {
            assert_eq!(
                unused
                    .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                    .await,
                AdmissionDecision::Allowed
            );
        }
        for service in [&unused, &used] {
            assert!(matches!(
                service
                    .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                    .await,
                AdmissionDecision::Rejected { .. }
            ));
        }
    }

    #[tokio::test]
    async fn same_initialized_manager_recovers_after_redis_eight_restart_without_adding_quota() {
        let port_reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = port_reservation.local_addr().unwrap().port();
        drop(port_reservation);
        let container = GenericImage::new("redis", "8-bookworm")
            .with_wait_for(WaitFor::message_on_stdout("Ready to accept connections"))
            .with_mapped_port(port, 6379.tcp())
            .start()
            .await
            .expect("Redis 8 test container must start");
        let url = format!("redis://127.0.0.1:{port}/");
        let counter = Arc::new(RedisAdmissionCounter::new(&url, Duration::from_secs(1)).unwrap());
        let distributed: Arc<dyn DistributedAdmissionCounter> = counter.clone();
        let clock = Arc::new(TestClock::new(59));
        let service = AdmissionService::new_with_test_monotonic(
            "restart-proof".to_owned(),
            [9; 32],
            64,
            Some(distributed),
            clock.clone(),
        );
        let probe = |key: &str| AdmissionBucket {
            key: format!("restart-proof:{key}"),
            limit: 10,
            window_millis: 60_000,
        };

        assert_eq!(
            counter.evaluate(&[probe("initial")]).await,
            Ok(AdmissionDecision::Allowed),
            "the ConnectionManager must initialize before the outage"
        );
        let initial_generation = current_generation(&counter).await.unwrap();
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Allowed
        );

        container.stop().await.unwrap();
        assert_eq!(
            counter.evaluate(&[probe("outage")]).await,
            Err(DistributedAdmissionError)
        );
        assert!(current_generation(&counter).await.is_none());
        assert!(matches!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Rejected {
                reason: AdmissionRejectionReason::Quota,
                ..
            }
        ));

        container.start().await.unwrap();
        let client = redis::Client::open(url.as_str()).unwrap();
        let mut fresh_connection = None;
        for _ in 0..30 {
            if let Ok(connection) = client.get_multiplexed_async_connection().await {
                fresh_connection = Some(connection);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut connection = fresh_connection.expect("restarted Redis 8 must become ready");

        let mut recovered = false;
        for _ in 0..30 {
            if counter.evaluate(&[probe("recovery")]).await.is_ok() {
                recovered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            recovered,
            "the initialized counter must install a healthy manager generation"
        );
        let recovered_generation = current_generation(&counter).await.unwrap();
        assert!(recovered_generation > initial_generation);

        // A delayed failure from an operation holding the retired manager cannot clear the new one.
        // Successful old operations never write to manager_state, so they cannot reinstall it either.
        counter.invalidate(initial_generation).await;
        assert_eq!(
            current_generation(&counter).await,
            Some(recovered_generation)
        );

        // Model Redis data loss during the outage. At the next monotonic fixed-window boundary,
        // Redis accepts again, but the process-local rolling event from t=59s remains authoritative.
        redis::cmd("FLUSHALL")
            .query_async::<()>(&mut connection)
            .await
            .unwrap();
        clock.set(60);
        assert_eq!(
            service
                .admit(AdmissionEndpoint::ProviderSelection, "client", &[])
                .await,
            AdmissionDecision::Rejected {
                retry_after_seconds: 59,
                reason: AdmissionRejectionReason::Quota,
            }
        );
    }

    #[test]
    fn malformed_script_responses_fail_closed() {
        assert_eq!(parse_response(&[]), Err(DistributedAdmissionError));
        assert_eq!(parse_response(&[1, 1]), Err(DistributedAdmissionError));
        assert_eq!(parse_response(&[0, 0]), Err(DistributedAdmissionError));
        assert_eq!(parse_response(&[0, -1]), Err(DistributedAdmissionError));
    }

    #[tokio::test]
    async fn unreachable_redis_returns_a_bounded_adapter_error() {
        let counter =
            RedisAdmissionCounter::new("redis://127.0.0.1:1/", Duration::from_millis(20)).unwrap();
        let result = counter
            .evaluate(&[AdmissionBucket {
                key: "test:v1:class:client:digest".to_owned(),
                limit: 1,
                window_millis: 60_000,
            }])
            .await;
        assert_eq!(result, Err(DistributedAdmissionError));
    }
}
