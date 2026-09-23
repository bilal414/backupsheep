"""Security boundary for OVHcloud consumer-key authorization flows."""

from __future__ import annotations

import hashlib
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import ovh
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.cache import cache

from apps.api.v1.utils.http import request_timeout
from apps.api.v1.utils.oauth_security import (
    OAUTH_STATE_SESSION_KEY,
    OAUTH_STATE_TTL_SECONDS,
    consume_oauth_state,
    issue_oauth_state,
    validated_https_endpoint,
)


OVH_PROVIDER_CONFIG = {
    "ovh_ca": {
        "endpoint": "ovh-ca",
        "api_hostname": "ca.api.ovh.com",
        "app_key_setting": "OVH_CA_APP_KEY",
        "app_secret_setting": "OVH_CA_APP_SECRET",
        "callback_path": "/api/v1/callback/ovh/ca/",
    },
    "ovh_eu": {
        "endpoint": "ovh-eu",
        "api_hostname": "eu.api.ovh.com",
        "app_key_setting": "OVH_EU_APP_KEY",
        "app_secret_setting": "OVH_EU_APP_SECRET",
        "callback_path": "/api/v1/callback/ovh/eu/",
    },
    "ovh_us": {
        "endpoint": "ovh-us",
        "api_hostname": "api.us.ovhcloud.com",
        "app_key_setting": "OVH_US_APP_KEY",
        "app_secret_setting": "OVH_US_APP_SECRET",
        "callback_path": "/api/v1/callback/ovh/us/",
    },
}

_OVH_CREDENTIAL_RE = re.compile(r"[A-Za-z0-9._~-]{16,512}\Z")


def _provider_config(provider):
    try:
        return OVH_PROVIDER_CONFIG[str(provider)]
    except KeyError as error:
        raise ValueError("Unsupported OVH provider") from error


def _valid_ovh_credential(value):
    return isinstance(value, str) and bool(_OVH_CREDENTIAL_RE.fullmatch(value))


def ovh_member_has_integration_permission(request, account):
    """Authorize against the same exact account used by this OVH flow."""

    try:
        member = request.user.member
        account_id = account.pk
    except AttributeError:
        return False

    from apps.console.account.models import CoreAccountGroup
    from apps.console.member.models import CoreMemberAccount

    membership = member.memberships.filter(
        account_id=account_id,
        current=True,
        status=CoreMemberAccount.Status.ACTIVE,
    ).first()
    if membership is None:
        return False
    if membership.primary:
        return True
    return CoreAccountGroup.objects.filter(
        account_id=account_id,
        group__user=request.user,
        group__permissions__codename="integration_changes",
        group__permissions__content_type__app_label=(
            CoreAccountGroup._meta.app_label
        ),
        group__permissions__content_type__model=(
            CoreAccountGroup._meta.model_name
        ),
    ).exists()


def ovh_start_request_is_same_origin(request):
    """Require browser evidence that the GET start action came from this app."""

    app = urlsplit(str(settings.APP_URL or "").strip())
    if (
        app.scheme.lower() != "https"
        or not app.hostname
        or app.username is not None
        or app.password is not None
        or app.query
        or app.fragment
    ):
        return False
    expected_origin = urlunsplit(("https", app.netloc.lower(), "", "", ""))
    fetch_site = str(request.headers.get("Sec-Fetch-Site", "")).lower()
    if fetch_site:
        return fetch_site == "same-origin"
    for header in ("Origin", "Referer"):
        value = request.headers.get(header)
        if not value:
            continue
        parsed = urlsplit(value)
        origin = urlunsplit(
            (parsed.scheme.lower(), parsed.netloc.lower(), "", "", "")
        )
        return secrets.compare_digest(origin, expected_origin)
    return False


def _callback_url(provider, state):
    config = _provider_config(provider)
    app = urlsplit(str(settings.APP_URL or "").strip())
    if (
        app.scheme.lower() != "https"
        or not app.hostname
        or app.username is not None
        or app.password is not None
        or app.query
        or app.fragment
    ):
        raise ValueError("APP_URL must be an HTTPS origin for OVH callbacks")
    base_path = app.path.rstrip("/")
    return urlunsplit(
        (
            "https",
            app.netloc.lower(),
            base_path + config["callback_path"],
            urlencode({"state": state}),
            "",
        )
    )


def build_ovh_client(provider, *, consumer_key=None):
    """Create a bounded OVH SDK client pinned to the expected API host."""

    config = _provider_config(provider)
    kwargs = {
        "endpoint": config["endpoint"],
        "application_key": getattr(settings, config["app_key_setting"]),
        "application_secret": getattr(settings, config["app_secret_setting"]),
        "timeout": request_timeout(),
    }
    if consumer_key is not None:
        if not _valid_ovh_credential(consumer_key):
            raise ValueError("Invalid OVH consumer key")
        kwargs["consumer_key"] = consumer_key
    client = ovh.Client(**kwargs)
    endpoint = validated_https_endpoint(
        getattr(client, "_endpoint", None),
        allowed_hostnames={config["api_hostname"]},
        allowed_paths={"/1.0"},
    )
    session = getattr(client, "_session", None)
    if endpoint is None or session is None:
        raise ValueError("OVH SDK endpoint could not be verified")
    client._endpoint = endpoint
    # OVH signatures and consumer keys are custom headers that requests would
    # otherwise preserve across some redirects. Never follow one.
    session.max_redirects = 0
    return client


def validated_ovh_authorization_url(provider, value):
    """Validate OVH's provider-mandated credentialToken browser URL."""

    config = _provider_config(provider)
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value.strip())
        explicit_port = parsed.port
        query = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=4,
        )
    except (TypeError, ValueError):
        return None
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or hostname != config["api_hostname"]
        or parsed.username is not None
        or parsed.password is not None
        or explicit_port is not None
        or parsed.path.rstrip("/") != "/auth"
        or parsed.fragment
        or len(query) != 1
        or query[0][0] != "credentialToken"
        or not _valid_ovh_credential(query[0][1])
    ):
        return None
    return urlunsplit(
        (
            "https",
            hostname,
            "/auth/",
            urlencode({"credentialToken": query[0][1]}),
            "",
        )
    )


def _discard_ovh_state(request, provider):
    pending = request.session.get(OAUTH_STATE_SESSION_KEY, {})
    pending = dict(pending) if isinstance(pending, dict) else {}
    pending.pop(str(provider), None)
    if pending:
        request.session[OAUTH_STATE_SESSION_KEY] = pending
    else:
        request.session.pop(OAUTH_STATE_SESSION_KEY, None)


def _bind_consumer_key(request, *, provider, state, account, consumer_key):
    if not _valid_ovh_credential(consumer_key):
        return False
    pending = request.session.get(OAUTH_STATE_SESSION_KEY, {})
    pending = dict(pending) if isinstance(pending, dict) else {}
    record = pending.get(str(provider))
    if not isinstance(record, dict) or not isinstance(record.get("state"), str):
        return False
    if not secrets.compare_digest(record["state"], state):
        return False
    try:
        ciphertext = Fernet(account.get_encryption_key()).encrypt(
            consumer_key.encode("utf-8")
        )
    except (TypeError, ValueError):
        return False
    record = dict(record)
    record["consumer_key"] = ciphertext.decode("ascii")
    pending[str(provider)] = record
    request.session[OAUTH_STATE_SESSION_KEY] = pending
    return True


def prepare_ovh_authorization(request, provider):
    """Create and bind one OVH consumer-key authorization transaction."""

    member = request.user.member
    account = member.get_current_account()
    if not ovh_member_has_integration_permission(request, account):
        raise PermissionError("OVH integration permission denied")
    state_record = issue_oauth_state(
        request,
        provider=provider,
        member=member,
        account=account,
    )
    try:
        client = build_ovh_client(provider)
        key_request = client.new_consumer_key_request()
        key_request.add_rules(ovh.API_READ_ONLY, "/me")
        key_request.add_recursive_rules(ovh.API_READ_ONLY, "/cloud/project")
        key_request.add_recursive_rules(
            ovh.API_READ_WRITE, "/cloud/project/*/snapshot"
        )
        key_request.add_recursive_rules(
            ovh.API_READ_WRITE, "/cloud/project/*/volume/snapshot"
        )
        key_request.add_recursive_rules(
            ["POST"], "/cloud/project/*/instance/*/snapshot"
        )
        key_request.add_recursive_rules(
            ["POST"], "/cloud/project/*/volume/*/snapshot"
        )
        key_request.add_recursive_rules(
            ["GET", "POST"], "/cloud/project/*/instance"
        )
        key_request.add_recursive_rules(
            ["GET", "POST"], "/cloud/project/*/volume"
        )
        validation = key_request.request(
            redirect_url=_callback_url(provider, state_record["state"])
        )
        if not isinstance(validation, dict):
            raise ValueError("OVH returned an invalid authorization response")
        consumer_key = validation.get("consumerKey")
        authorization_url = validated_ovh_authorization_url(
            provider, validation.get("validationUrl")
        )
        if authorization_url is None or not _bind_consumer_key(
            request,
            provider=provider,
            state=state_record["state"],
            account=account,
            consumer_key=consumer_key,
        ):
            raise ValueError("OVH authorization transaction could not be bound")
        return authorization_url
    except Exception:
        _discard_ovh_state(request, provider)
        raise


def consume_ovh_transaction(request, provider, *, member, account, received_state):
    """Consume one OVH state and return its decrypted consumer key."""

    record = consume_oauth_state(
        request,
        provider=provider,
        received_state=received_state,
        member=member,
        account=account,
    )
    if not isinstance(record, dict):
        return None
    ciphertext = record.get("consumer_key")
    if not isinstance(ciphertext, str):
        return None
    try:
        consumer_key = Fernet(account.get_encryption_key()).decrypt(
            ciphertext.encode("ascii")
        ).decode("utf-8")
    except (InvalidToken, UnicodeError, TypeError, ValueError):
        return None
    if not _valid_ovh_credential(consumer_key):
        return None

    # Session backends do not universally offer atomic compare-and-delete.
    # This cache add is the concurrency fence if two callbacks race with the
    # same pre-consumption session snapshot.
    replay_digest = hashlib.sha256(
        f"{provider}:{received_state}".encode("utf-8")
    ).hexdigest()
    try:
        if not cache.add(
            f"ovh-oauth-consumed:{replay_digest}",
            True,
            timeout=OAUTH_STATE_TTL_SECONDS,
        ):
            return None
    except Exception:
        return None
    return consumer_key
