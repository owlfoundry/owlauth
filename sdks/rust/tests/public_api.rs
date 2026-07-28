use owlauth_client::Client;

#[test]
fn constructs_client() {
    let client = Client::new("https://auth.example.com");
    assert_eq!(client.base_url(), "https://auth.example.com");
}
