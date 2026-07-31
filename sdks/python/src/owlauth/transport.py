"""Narrow synchronous HTTP transport for the Runtime protocol."""

from __future__ import annotations

import socket
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

_MAX_RESPONSE_BYTES = 65_536
_MAX_HEADER_COUNT = 64
_MAX_HEADER_BYTES = 16_384


class FailureKind(StrEnum):
    TRANSPORT = "transport"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class TransportFailure(Exception):
    """Safe failure signal for injectable transports."""

    def __init__(self, kind: FailureKind, *, dispatched: bool) -> None:
        super().__init__(kind.value)
        self.kind = kind
        self.dispatched = dispatched

    def __repr__(self) -> str:
        return f"TransportFailure(kind={self.kind.value!r}, dispatched={self.dispatched!r})"


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    """Injectable transport. Implementations must not follow redirects."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> TransportResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):  # noqa: ANN001, ANN201, ARG002
        return None


class StdlibTransport:
    """Bounded urllib transport with TLS verification and redirects disabled."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> TransportResponse:
        request_headers = {"User-Agent": "owlauth-python/0.0.1", **headers}
        request = Request(url, data=body, headers=request_headers, method=method)
        opener = build_opener(_NoRedirect())
        try:
            try:
                response = opener.open(request, timeout=timeout)
            except HTTPError as error:
                response = error
            with response:
                response_headers = _bounded_headers(response.headers.items())
                response_body = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(response_body) > _MAX_RESPONSE_BYTES:
                    raise TransportFailure(FailureKind.TRANSPORT, dispatched=True)
                return TransportResponse(
                    status=int(response.status), headers=response_headers, body=response_body
                )
        except TransportFailure:
            raise
        except TimeoutError as error:
            raise TransportFailure(FailureKind.TIMEOUT, dispatched=True) from error
        except URLError as error:
            kind = (
                FailureKind.TIMEOUT
                if isinstance(error.reason, (TimeoutError, socket.timeout))
                else FailureKind.TRANSPORT
            )
            raise TransportFailure(kind, dispatched=True) from error
        except OSError as error:
            raise TransportFailure(FailureKind.TRANSPORT, dispatched=True) from error


def _bounded_headers(items: list[tuple[str, str]]) -> dict[str, str]:
    if len(items) > _MAX_HEADER_COUNT:
        raise TransportFailure(FailureKind.TRANSPORT, dispatched=True)
    total = 0
    result: dict[str, str] = {}
    for name, value in items:
        total += len(name) + len(value)
        if total > _MAX_HEADER_BYTES:
            raise TransportFailure(FailureKind.TRANSPORT, dispatched=True)
        lowered = name.lower()
        if lowered in result:
            continue
        result[lowered] = value
    return result
