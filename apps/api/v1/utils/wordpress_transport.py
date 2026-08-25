"""Fail-closed, DNS-pinned HTTPS transport for credentialed WordPress calls."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import time
import weakref
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from requests.adapters import HTTPAdapter

from apps.api.v1.utils.http import TimeoutSession


_DENIED_METADATA_HOSTS = frozenset(
    {
        "instance-data.ec2.internal",
        "metadata",
        "metadata.google.internal",
    }
)
_DENIED_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("168.63.129.16"),
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
_DENIED_IPV6_TRANSITION_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2001::/32"),
    ipaddress.ip_network("2002::/16"),
)
_PRIVATE_TARGET_SUPERNETS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
WORDPRESS_PROTOCOL_VERSION = "2"
WORDPRESS_PROTOCOL_HEADER = "X-BackupSheep-Protocol"
WORDPRESS_KEY_ID_HEADER = "X-BackupSheep-Key-Id"
WORDPRESS_TIMESTAMP_HEADER = "X-BackupSheep-Timestamp"
WORDPRESS_NONCE_HEADER = "X-BackupSheep-Nonce"
WORDPRESS_ROUTE_HEADER = "X-BackupSheep-Route"
WORDPRESS_CONTENT_SHA256_HEADER = "X-BackupSheep-Content-SHA256"
WORDPRESS_SIGNATURE_HEADER = "X-BackupSheep-Signature"
WORDPRESS_MAX_REQUEST_BYTES = 64 * 1024
_WORDPRESS_SIGNATURE_DOMAIN = "backupsheep-wordpress-v2"
_WORDPRESS_ROUTE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_WORDPRESS_NONCE = re.compile(r"^[0-9a-f]{32}$")
_WORDPRESS_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_WORDPRESS_INTEGRATION_KEY = re.compile(rb"^[A-Za-z0-9_-]{24,512}$")


class WordPressTransportError(ValueError):
    """The WordPress target could not be reached without crossing a trust boundary."""


def require_wordpress_protocol_v2():
    """Fail closed until the authenticated v2 plugin contract is enabled.

    The historical public plugin accepts a query-string bearer key and performs
    state-changing GET requests.  The Python client must not silently fall back to
    that contract merely to keep an old integration working.  Existing backup
    artifacts remain accessible; only calls to the unsafe source protocol stop.
    """

    if not getattr(settings, "WORDPRESS_INTEGRATION_ENABLED", False):
        raise WordPressTransportError(
            "WordPress backups are disabled until the authenticated protocol v2 "
            "plugin is installed and explicitly enabled"
        )


def _canonical_wordpress_v2_body(payload):
    if not isinstance(payload, dict):
        raise WordPressTransportError("WordPress protocol v2 requires an object body")
    try:
        body = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise WordPressTransportError(
            "WordPress protocol v2 request data is not canonical JSON"
        ) from None
    if len(body) > WORDPRESS_MAX_REQUEST_BYTES:
        raise WordPressTransportError("WordPress protocol v2 request is too large")
    return body


def build_wordpress_v2_request(route, payload, integration_key, *, now=None, nonce=None):
    """Return a canonical body and replay-resistant HMAC authentication headers.

    The integration key is a shared secret and is never placed in the URL or headers.
    Its digest is only a non-secret selector so a future plugin can support overlap
    during rotation. The route and exact body digest are part of the signature.
    """

    route = str(route or "")
    if not _WORDPRESS_ROUTE.fullmatch(route):
        raise WordPressTransportError("WordPress protocol v2 route is invalid")
    if not isinstance(integration_key, str):
        raise WordPressTransportError("WordPress integration key is unavailable")
    try:
        key = integration_key.encode("utf-8")
    except UnicodeEncodeError:
        raise WordPressTransportError("WordPress integration key is invalid") from None
    if not _WORDPRESS_INTEGRATION_KEY.fullmatch(key):
        raise WordPressTransportError(
            "WordPress integration key must be a bounded high-entropy token"
        )

    body = _canonical_wordpress_v2_body(payload)
    body_sha256 = hashlib.sha256(body).hexdigest()
    timestamp = int(time.time() if now is None else now)
    if timestamp < 0:
        raise WordPressTransportError("WordPress protocol v2 timestamp is invalid")
    nonce = secrets.token_hex(16) if nonce is None else str(nonce)
    if not _WORDPRESS_NONCE.fullmatch(nonce):
        raise WordPressTransportError("WordPress protocol v2 nonce is invalid")

    canonical = "\n".join(
        (
            _WORDPRESS_SIGNATURE_DOMAIN,
            WORDPRESS_PROTOCOL_VERSION,
            "POST",
            route,
            str(timestamp),
            nonce,
            body_sha256,
        )
    ).encode("ascii")
    signature = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    return body, {
        "Content-Type": "application/json",
        WORDPRESS_PROTOCOL_HEADER: WORDPRESS_PROTOCOL_VERSION,
        WORDPRESS_KEY_ID_HEADER: hashlib.sha256(key).hexdigest()[:32],
        WORDPRESS_TIMESTAMP_HEADER: str(timestamp),
        WORDPRESS_NONCE_HEADER: nonce,
        WORDPRESS_ROUTE_HEADER: route,
        WORDPRESS_CONTENT_SHA256_HEADER: body_sha256,
        WORDPRESS_SIGNATURE_HEADER: signature,
    }


@dataclass(frozen=True)
class PinnedWordPressTarget:
    hostname: str
    authority: str
    port: int
    selected_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    approved_ips: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    pinned_url: str


class WordPressPinnedHTTPSAdapter(HTTPAdapter):
    """Connect to an IP while verifying TLS for the configured WordPress host."""

    def __init__(self, tls_hostname: str):
        self.tls_hostname = tls_hostname
        # Credentialed WordPress routes can mutate state. Never retry them
        # implicitly after an unknown network outcome.
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs.update(
            assert_hostname=self.tls_hostname,
            server_hostname=self.tls_hostname,
        )
        return super().init_poolmanager(
            connections,
            maxsize,
            block=block,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        raise WordPressTransportError(
            "Proxies are disabled for DNS-pinned WordPress requests"
        )


def _configured_private_networks():
    configured = getattr(settings, "WORDPRESS_PRIVATE_TARGET_CIDRS", ())
    if isinstance(configured, str):
        configured = [item.strip() for item in configured.split(",") if item.strip()]
    networks = []
    for value in configured or ():
        try:
            network = (
                value
                if isinstance(
                    value,
                    (ipaddress.IPv4Network, ipaddress.IPv6Network),
                )
                else ipaddress.ip_network(str(value), strict=True)
            )
        except ValueError as error:
            raise WordPressTransportError(
                "WORDPRESS_PRIVATE_TARGET_CIDRS contains an invalid network"
            ) from error
        if not any(
            network.version == private_supernet.version
            and network.subnet_of(private_supernet)
            for private_supernet in _PRIVATE_TARGET_SUPERNETS
        ):
            raise WordPressTransportError(
                "WORDPRESS_PRIVATE_TARGET_CIDRS may contain only RFC1918 or ULA networks"
            )
        networks.append(network)
    return tuple(networks)


def _address_is_approved(address, private_networks):
    if address in _DENIED_METADATA_ADDRESSES:
        return False
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return False
    if isinstance(address, ipaddress.IPv6Address) and (
        address.is_site_local
        or address.sixtofour is not None
        or address.teredo is not None
        or any(address in network for network in _DENIED_IPV6_TRANSITION_NETWORKS)
    ):
        return False
    if address.is_global:
        return True
    return any(
        address.version == network.version and address in network
        for network in private_networks
    )


def _resolved_addresses(hostname, port):
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if isinstance(literal, ipaddress.IPv6Address) and literal.ipv4_mapped:
            literal = literal.ipv4_mapped
        return (literal,)

    try:
        answers = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, socket.gaierror) as error:
        raise WordPressTransportError("WordPress hostname resolution failed") from error

    addresses = []
    seen = set()
    for family, _socktype, _proto, _canonname, sockaddr in answers:
        if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
            raise WordPressTransportError(
                "WordPress hostname returned a non-IP address"
            )
        try:
            address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        except ValueError as error:
            raise WordPressTransportError(
                "WordPress hostname returned an invalid address"
            ) from error
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        if address not in seen:
            seen.add(address)
            addresses.append(address)
    if not addresses:
        raise WordPressTransportError("WordPress hostname resolved to no TCP addresses")
    return tuple(addresses)


def resolve_wordpress_target(base_url):
    """Resolve once, validate every answer, and build an IP-pinned HTTPS URL."""

    parts = urlsplit(base_url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise WordPressTransportError("WordPress credentials require HTTPS")
    if parts.username is not None or parts.password is not None:
        raise WordPressTransportError("WordPress URL must not contain credentials")
    if parts.query or parts.fragment:
        raise WordPressTransportError("WordPress URL must not contain query data")

    hostname = parts.hostname.rstrip(".").lower()
    if (
        hostname in _DENIED_METADATA_HOSTS
        or hostname.endswith(".metadata.google.internal")
    ):
        raise WordPressTransportError("WordPress metadata targets are forbidden")
    try:
        hostname = hostname.encode("idna").decode("ascii")
        port = parts.port or 443
    except (UnicodeError, ValueError) as error:
        raise WordPressTransportError("WordPress URL has an invalid host or port") from error

    addresses = _resolved_addresses(hostname, port)
    private_networks = _configured_private_networks()
    rejected = [
        address
        for address in addresses
        if not _address_is_approved(address, private_networks)
    ]
    if rejected:
        # Reject the whole DNS answer, even if it also contains a public address.
        # Choosing only the public member would preserve a DNS-rebinding race for
        # callers that later resolve the same hostname themselves.
        raise WordPressTransportError(
            "WordPress hostname resolved outside the approved target policy"
        )

    selected = addresses[0]
    rendered_ip = f"[{selected}]" if selected.version == 6 else str(selected)
    pinned_authority = f"{rendered_ip}:{port}"
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = authority_host if port == 443 else f"{authority_host}:{port}"
    path = (parts.path or "").rstrip("/") + "/"
    pinned_url = urlunsplit(("https", pinned_authority, path, "", ""))
    return PinnedWordPressTarget(
        hostname=hostname,
        authority=authority,
        port=port,
        selected_ip=selected,
        approved_ips=addresses,
        pinned_url=pinned_url,
    )


def _response_peer_address(response):
    raw = getattr(response, "raw", None)
    connection = getattr(raw, "_connection", None) or getattr(
        raw, "connection", None
    )
    sock = getattr(connection, "sock", None)
    if sock is None:
        return None
    try:
        peer = sock.getpeername()
        address = ipaddress.ip_address(str(peer[0]).split("%", 1)[0])
    except (AttributeError, IndexError, OSError, TypeError, ValueError):
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def pinned_wordpress_request(
    target,
    *,
    route,
    body,
    headers,
    auth,
    stream=False,
    timeout=None,
):
    """Make one direct pinned request; never resolve, redirect, retry, or proxy."""

    request_headers = {str(name): str(value) for name, value in (headers or {}).items()}
    route = str(route or "")
    if not _WORDPRESS_ROUTE.fullmatch(route):
        raise WordPressTransportError("WordPress protocol v2 route is invalid")
    if (
        not isinstance(body, bytes)
        or not body
        or len(body) > WORDPRESS_MAX_REQUEST_BYTES
    ):
        raise WordPressTransportError("WordPress protocol v2 body is invalid")
    required = {
        WORDPRESS_PROTOCOL_HEADER: WORDPRESS_PROTOCOL_VERSION,
        WORDPRESS_ROUTE_HEADER: route,
        WORDPRESS_CONTENT_SHA256_HEADER: hashlib.sha256(body).hexdigest(),
    }
    for name, expected in required.items():
        if request_headers.get(name) != expected:
            raise WordPressTransportError(
                "WordPress protocol v2 authentication headers are invalid"
            )
    if not _WORDPRESS_NONCE.fullmatch(request_headers.get(WORDPRESS_NONCE_HEADER, "")):
        raise WordPressTransportError("WordPress protocol v2 nonce header is invalid")
    if not _WORDPRESS_SIGNATURE.fullmatch(
        request_headers.get(WORDPRESS_SIGNATURE_HEADER, "")
    ):
        raise WordPressTransportError("WordPress protocol v2 signature header is invalid")
    key_id = request_headers.get(WORDPRESS_KEY_ID_HEADER, "")
    if not re.fullmatch(r"[0-9a-f]{32}", key_id):
        raise WordPressTransportError("WordPress protocol v2 key identifier is invalid")
    try:
        timestamp = int(request_headers.get(WORDPRESS_TIMESTAMP_HEADER, ""))
    except (TypeError, ValueError):
        raise WordPressTransportError(
            "WordPress protocol v2 timestamp header is invalid"
        ) from None
    if str(timestamp) != request_headers.get(WORDPRESS_TIMESTAMP_HEADER) or timestamp < 0:
        raise WordPressTransportError("WordPress protocol v2 timestamp header is invalid")

    query = {"rest_route": f"/backupsheep/v2/{route}"}
    if any(
        secret and str(secret) in query["rest_route"]
        for secret in (auth or ())
    ):
        raise WordPressTransportError("WordPress credentials must not be query parameters")

    session = TimeoutSession()
    session.trust_env = False
    adapter = WordPressPinnedHTTPSAdapter(target.hostname)
    session.mount("https://", adapter)
    request_headers["Host"] = target.authority

    try:
        # Keep the socket open until the selected peer can be checked. Non-stream
        # callers are materialized below before the dedicated session is closed.
        request_kwargs = {
            "params": query,
            "headers": request_headers,
            "auth": auth,
            "allow_redirects": False,
            "verify": True,
            "stream": True,
            "data": body,
        }
        if timeout is not None:
            request_kwargs["timeout"] = timeout
        response = session.post(target.pinned_url, **request_kwargs)
        peer = _response_peer_address(response)
        if peer is not None and peer != target.selected_ip:
            response.close()
            raise WordPressTransportError(
                "WordPress connection peer did not match the pinned address"
            )
        if not stream:
            # Materialize while the one-request pool is alive, then close it.
            response.content
            session.close()
            return response

        original_close = response.close
        finalizer = weakref.finalize(response, session.close)

        def close_pinned_response():
            try:
                original_close()
            finally:
                if finalizer.alive:
                    finalizer()

        response.close = close_pinned_response
        return response
    except Exception:
        session.close()
        raise
