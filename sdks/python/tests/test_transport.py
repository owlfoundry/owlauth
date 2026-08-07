from __future__ import annotations

from http.client import IncompleteRead
from typing import Any

import pytest
from owlauth import FailureKind, StdlibTransport, TransportFailure


class FakeResponse:
    status = 200

    def __init__(self, *, headers: dict[str, str], body: bytes = b"{}") -> None:
        self.headers = headers
        self.body = body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self.body[:size]


class TruncatedResponse(FakeResponse):
    def read(self, size: int) -> bytes:  # noqa: ARG002
        raise IncompleteRead(b'{"partial":', 32)


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    def open(self, request: object, *, timeout: float) -> FakeResponse:  # noqa: ARG002
        return self.response


def request_with_response(
    monkeypatch: pytest.MonkeyPatch, response: FakeResponse
) -> TransportFailure:
    monkeypatch.setattr("owlauth.transport.build_opener", lambda _handler: FakeOpener(response))
    with pytest.raises(TransportFailure) as captured:
        StdlibTransport().request(
            "GET",
            "https://runtime.example/config",
            headers={"Accept": "application/json"},
            body=None,
            timeout=1,
        )
    return captured.value


def test_stdlib_transport_reports_oversized_response_as_invalid_framing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = request_with_response(
        monkeypatch,
        FakeResponse(headers={"content-type": "application/json"}, body=b"x" * 65_537),
    )
    assert failure.kind is FailureKind.RESPONSE_INVALID
    assert failure.dispatched


@pytest.mark.parametrize(
    "headers",
    [
        {f"x-{index}": "v" for index in range(65)},
        {"x-oversized": "v" * 16_385},
    ],
)
def test_stdlib_transport_reports_oversized_headers_as_invalid_framing(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
) -> None:
    failure = request_with_response(monkeypatch, FakeResponse(headers=headers))
    assert failure.kind is FailureKind.RESPONSE_INVALID
    assert failure.dispatched


def test_stdlib_transport_reports_truncated_response_as_invalid_framing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure = request_with_response(
        monkeypatch,
        TruncatedResponse(headers={"content-type": "application/json"}),
    )
    assert failure.kind is FailureKind.RESPONSE_INVALID
    assert failure.dispatched
