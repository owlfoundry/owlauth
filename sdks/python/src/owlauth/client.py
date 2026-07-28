"""OwlAuth client configuration."""


class Client:
    """Client configuration for an OwlAuth server."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url

    @property
    def base_url(self) -> str:
        """Return the configured server URL."""
        return self._base_url
