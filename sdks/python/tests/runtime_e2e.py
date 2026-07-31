"""Explicit real-Runtime Python SDK journey.

Invoke directly; this file is intentionally not collected by the normal pytest suite.
"""

from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass
from html.parser import HTMLParser
from http.client import HTTPConnection, HTTPSConnection
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from owlauth import Client, CredentialPair, RefreshError


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    headers: Any
    body: bytes


class BootstrapParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            return
        values = dict(attrs)
        name = values.get("name")
        content = values.get("content")
        if name is not None and content is not None:
            self.values[name] = content


def required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: object | None = None,
) -> HttpResult:
    encoded = None
    request_headers = dict(headers or {})
    if body is not None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        request_headers["Content-Type"] = "application/json"
    target = urlsplit(url)
    if target.scheme not in {"http", "https"} or target.hostname is None:
        raise RuntimeError("E2E navigation target is not HTTP(S)")
    connection_type = HTTPSConnection if target.scheme == "https" else HTTPConnection
    connection = connection_type(target.hostname, target.port, timeout=15)
    path = urlunsplit(("", "", target.path or "/", target.query, ""))
    try:
        connection.request(method, path, body=encoded, headers=request_headers)
        response = connection.getresponse()
        return HttpResult(response.status, response.headers, response.read(1_048_577))
    except ssl.SSLError as error:
        raise RuntimeError("real-server E2E requires a trusted TLS chain") from error
    finally:
        connection.close()


def update_cookies(result: HttpResult, cookies: dict[str, str]) -> None:
    for header in result.headers.get_all("Set-Cookie", []):
        parsed = SimpleCookie()
        parsed.load(header)
        for name, morsel in parsed.items():
            if morsel["max-age"] == "0":
                cookies.pop(name, None)
            else:
                cookies[name] = morsel.value


def cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def bootstrap(result: HttpResult, expected_flow: str) -> dict[str, Any]:
    if result.status != 200 or len(result.body) > 1_048_576:
        raise RuntimeError(f"Hosted flow returned HTTP {result.status}")
    parser = BootstrapParser()
    parser.feed(result.body.decode("utf-8"))
    if parser.values.get("owlauth-runtime-flow") != expected_flow:
        raise RuntimeError("Hosted flow identity did not match")
    value = json.loads(parser.values["owlauth-runtime-bootstrap"])
    if not isinstance(value, dict):
        raise RuntimeError("Hosted bootstrap was not an object")
    return value


def hosted_headers(runtime_origin: str, cookies: dict[str, str]) -> dict[str, str]:
    headers = {
        "Origin": runtime_origin,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }
    if cookies:
        headers["Cookie"] = cookie_header(cookies)
    return headers


def drive_provider(
    authorization_url: str,
    runtime_origin: str,
    redirect_uri: str,
    cookies: dict[str, str],
) -> str:
    target = authorization_url
    for _ in range(8):
        split = urlsplit(target)
        headers: dict[str, str] = {}
        if f"{split.scheme}://{split.netloc}" == runtime_origin and cookies:
            headers["Cookie"] = cookie_header(cookies)
        result = request("GET", target, headers=headers)
        update_cookies(result, cookies)
        location = result.headers.get("Location")
        if result.status not in {301, 302, 303, 307, 308} or location is None:
            raise RuntimeError(
                "controlled provider must complete authorization through bounded redirects"
            )
        if location.startswith(redirect_uri):
            return location
        target = urljoin(target, location)
    raise RuntimeError("provider redirect chain exceeded the E2E bound")


def login(
    client: Client,
    runtime_origin: str,
    redirect_uri: str,
    cookies: dict[str, str],
) -> CredentialPair:
    started = client.begin_login(redirect_uri)
    document_headers = {"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"}
    if cookies:
        document_headers["Cookie"] = cookie_header(cookies)
    page = request("GET", started.hosted_url, headers=document_headers)
    update_cookies(page, cookies)
    context = bootstrap(page, "interaction")
    providers = context.get("providers")
    if not isinstance(providers, list) or not providers:
        raise RuntimeError("Hosted UI exposed no admitted provider")
    handle = urlsplit(started.hosted_url).path.rsplit("/", 1)[-1]
    selection = request(
        "POST",
        f"{client.base_url}v1/projects/{client.project_id}/auth/interactions/{handle}/method",
        headers=hosted_headers(runtime_origin, cookies),
        body={
            "expected_revision": context["revision"],
            "csrf": context["csrf"],
            "provider_key": providers[0]["key"],
        },
    )
    if selection.status != 200:
        raise RuntimeError(f"provider selection returned HTTP {selection.status}")
    authorization_url = json.loads(selection.body)["url"]
    callback_url = drive_provider(authorization_url, runtime_origin, redirect_uri, cookies)
    return client.complete_login(callback_url, started.pending)


def confirm_browser_logout(
    client: Client,
    credentials: CredentialPair,
    runtime_origin: str,
    cookies: dict[str, str],
) -> None:
    prepared = client.prepare_browser_logout(credentials)
    page = request(
        "GET",
        prepared.hosted_url,
        headers={
            "Cookie": cookie_header(cookies),
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
        },
    )
    context = bootstrap(page, "browser-logout")
    handle = urlsplit(prepared.hosted_url).path.rsplit("/", 1)[-1]
    result = request(
        "POST",
        f"{client.base_url}v1/projects/{client.project_id}/auth/browser-logout/{handle}/confirm",
        headers=hosted_headers(runtime_origin, cookies),
        body={"expected_revision": context["revision"], "csrf": context["csrf"]},
    )
    update_cookies(result, cookies)
    if result.status != 200 or json.loads(result.body).get("completed") is not True:
        raise RuntimeError("Project browser logout was not confirmed")


def main() -> None:
    runtime_url = required("OWLAUTH_E2E_RUNTIME_URL")
    project_id = required("OWLAUTH_E2E_PROJECT_ID")
    application_id = required("OWLAUTH_E2E_APPLICATION_ID")
    publishable_key = required("OWLAUTH_E2E_PUBLISHABLE_KEY")
    redirect_uri = required("OWLAUTH_E2E_REDIRECT_URI")
    allow_loopback = os.environ.get("OWLAUTH_E2E_ALLOW_INSECURE_LOOPBACK") == "1"
    client = Client(
        runtime_url,
        project_id,
        application_id,
        publishable_key,
        allow_insecure_loopback=allow_loopback,
    )
    runtime = urlsplit(client.base_url)
    runtime_origin = f"{runtime.scheme}://{runtime.netloc}"
    cookies: dict[str, str] = {}

    config = client.get_public_configuration()
    if not config.login_available or not config.providers:
        raise RuntimeError("real Runtime does not advertise an admitted login method")

    first = login(client, runtime_origin, redirect_uri, cookies)
    client.current_user(first)
    successor = client.refresh(first)
    client.current_user(successor)
    try:
        client.refresh(first)
    except RefreshError:
        pass
    else:
        raise RuntimeError("replayed refresh generation was not rejected")

    second = login(client, runtime_origin, redirect_uri, cookies)
    if not client.logout_application(second).completed:
        raise RuntimeError("Application logout was not confirmed")

    third = login(client, runtime_origin, redirect_uri, cookies)
    confirm_browser_logout(client, third, runtime_origin, cookies)
    try:
        client.refresh(third)
    except RefreshError:
        pass
    else:
        raise RuntimeError("Project browser logout did not block refresh")

    print("Python SDK real-Runtime Project Auth E2E passed")


if __name__ == "__main__":
    main()
