use owlauth_client::{Client, ClientConfig, ErrorCategory};

#[test]
fn constructs_a_project_application_bound_client() {
    let client = Client::new(ClientConfig::new(
        "https://auth.example.com/runtime",
        "project_public",
        "application_public",
        "publishable_key",
    ))
    .expect("valid client configuration");
    assert_eq!(client.base_url(), "https://auth.example.com/runtime/");
    assert_eq!(client.project_id(), "project_public");
    assert_eq!(client.application_id(), "application_public");
}

#[test]
fn production_defaults_reject_plain_http() {
    let error = Client::new(ClientConfig::new(
        "http://auth.example.com",
        "project_public",
        "application_public",
        "publishable_key",
    ))
    .expect_err("plain HTTP must fail");
    assert_eq!(error.category(), ErrorCategory::Configuration);
    assert_eq!(error.code(), "insecure_runtime_url");
}
