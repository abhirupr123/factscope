"""Restricted outbound HTTP fetching for user-controlled URLs."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests


class UnsafeURLError(ValueError):
    """Raised when an outbound URL is not safe for the public fetcher."""


class ResponseTooLargeError(ValueError):
    """Raised when a remote response exceeds the configured byte limit."""


@dataclass(frozen=True)
class SafeFetchResult:
    content: bytes
    content_type: str
    final_url: str
    status_code: int
    headers: dict[str, str]


def _is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_public_url(url: str) -> str:
    """Validate that a URL resolves only to publicly routable IP addresses."""
    if not isinstance(url, str) or len(url) > 2048:
        raise UnsafeURLError("URL is missing or too long")

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise UnsafeURLError("Only HTTP and HTTPS URLs are supported")
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeURLError("URL host is missing or contains credentials")

    hostname = parsed.hostname.rstrip(".")
    if hostname.lower() == "localhost":
        raise UnsafeURLError("Local network URLs are not allowed")

    try:
        addresses = {
            str(item[4][0])
            for item in socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except socket.gaierror as exc:
        raise UnsafeURLError("URL host could not be resolved") from exc

    if not addresses or any(not _is_public_ip(address) for address in addresses):
        raise UnsafeURLError("Local or reserved network addresses are not allowed")
    return url


def _validate_connected_peer(response) -> None:
    """Verify the socket peer to prevent DNS-rebinding between check and connect."""
    raw = getattr(response, "raw", None)
    connection = getattr(raw, "_connection", None)
    sock = getattr(connection, "sock", None)
    if sock is None:
        original_response = getattr(raw, "_fp", None)
        buffered_reader = getattr(original_response, "fp", None)
        socket_io = getattr(buffered_reader, "raw", None)
        sock = getattr(socket_io, "_sock", None)
    if sock is None:
        raise UnsafeURLError("Could not verify the remote network address")

    try:
        peer_address = sock.getpeername()[0]
    except (OSError, TypeError, IndexError) as exc:
        raise UnsafeURLError("Could not verify the remote network address") from exc

    if not _is_public_ip(peer_address):
        raise UnsafeURLError("Connected peer is a local or reserved address")


def _is_empty_same_origin_redirect(response, current_url: str) -> bool:
    """Handle zero-byte redirects whose socket urllib3 already released."""
    if not (response.is_redirect or response.is_permanent_redirect):
        return False
    if str(response.headers.get("content-length", "")).strip() != "0":
        return False
    location = response.headers.get("location")
    if not location:
        return False

    current = urlsplit(current_url)
    destination = urlsplit(urljoin(current_url, location))
    return (
        destination.scheme == current.scheme
        and destination.hostname == current.hostname
        and destination.port == current.port
    )


def _validate_response_peer(response, current_url: str) -> None:
    """Verify the peer, except for content-free same-origin redirect hops."""
    try:
        _validate_connected_peer(response)
    except UnsafeURLError as exc:
        if (
            str(exc) == "Could not verify the remote network address"
            and _is_empty_same_origin_redirect(response, current_url)
        ):
            return
        raise


def safe_get(
    url: str,
    *,
    max_bytes: int,
    timeout: float = 10,
    max_redirects: int = 3,
    allowed_content_prefixes: tuple[str, ...] | None = None,
    headers: dict[str, str] | None = None,
) -> SafeFetchResult:
    """Fetch a bounded public URL while revalidating every redirect."""
    current_url = validate_public_url(url)
    request_headers = {
        "User-Agent": "FactScope/1.0",
        "Accept-Encoding": "identity",
        **(headers or {}),
    }

    with requests.Session() as session:
        for redirect_count in range(max_redirects + 1):
            validate_public_url(current_url)
            with session.get(
                current_url,
                headers=request_headers,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                _validate_response_peer(response, current_url)
                if response.is_redirect or response.is_permanent_redirect:
                    if redirect_count >= max_redirects:
                        raise UnsafeURLError("Too many redirects")
                    location = response.headers.get("location")
                    if not location:
                        raise UnsafeURLError("Redirect response has no location")
                    current_url = validate_public_url(urljoin(current_url, location))
                    continue

                response.raise_for_status()
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if allowed_content_prefixes and not any(
                    content_type.startswith(prefix) for prefix in allowed_content_prefixes
                ):
                    raise UnsafeURLError("Remote content type is not allowed")

                declared_length = response.headers.get("content-length")
                if declared_length:
                    try:
                        length = int(declared_length)
                    except ValueError as exc:
                        raise UnsafeURLError("Invalid Content-Length header") from exc
                    if length > max_bytes:
                        raise ResponseTooLargeError("Remote response is too large")

                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    received += len(chunk)
                    if received > max_bytes:
                        raise ResponseTooLargeError("Remote response is too large")
                    chunks.append(chunk)

                return SafeFetchResult(
                    content=b"".join(chunks),
                    content_type=content_type,
                    final_url=current_url,
                    status_code=response.status_code,
                    headers={str(k).lower(): str(v) for k, v in response.headers.items()},
                )

    raise UnsafeURLError("Unable to fetch URL")

def safe_probe(
    url: str,
    *,
    timeout: float = 5,
    max_redirects: int = 3,
    allowed_content_prefixes: tuple[str, ...] | None = None,
    headers: dict[str, str] | None = None,
) -> SafeFetchResult:
    """Probe a bounded public URL without downloading its response body."""
    current_url = validate_public_url(url)
    request_headers = {
        "User-Agent": "FactScope/1.0",
        "Accept-Encoding": "identity",
        **(headers or {}),
    }

    with requests.Session() as session:
        for redirect_count in range(max_redirects + 1):
            validate_public_url(current_url)
            with session.get(
                current_url,
                headers=request_headers,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
            ) as response:
                _validate_response_peer(response, current_url)
                if response.is_redirect or response.is_permanent_redirect:
                    if redirect_count >= max_redirects:
                        raise UnsafeURLError("Too many redirects")
                    location = response.headers.get("location")
                    if not location:
                        raise UnsafeURLError("Redirect response has no location")
                    current_url = validate_public_url(urljoin(current_url, location))
                    continue

                response.raise_for_status()
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if allowed_content_prefixes and not any(
                    content_type.startswith(prefix) for prefix in allowed_content_prefixes
                ):
                    raise UnsafeURLError("Remote content type is not allowed")
                return SafeFetchResult(
                    content=b"",
                    content_type=content_type,
                    final_url=current_url,
                    status_code=response.status_code,
                    headers={str(k).lower(): str(v) for k, v in response.headers.items()},
                )

    raise UnsafeURLError("Unable to probe URL")