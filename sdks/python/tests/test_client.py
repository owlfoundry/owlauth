from owlauth import Client


def test_client_stores_base_url() -> None:
    client = Client("https://auth.example.com")

    assert client.base_url == "https://auth.example.com"
