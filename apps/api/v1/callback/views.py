from requests_oauthlib import OAuth2Session
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.shortcuts import redirect
from django.contrib import messages
from sentry_sdk import capture_exception, capture_message
from django.db import transaction
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.member.models import CoreMember
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreAuthDigitalOcean,
    CoreAuthOVHCA,
    CoreAuthOVHEU,
    CoreAuthOVHUS, CoreAuthGoogleCloud, CoreConnectionLocation, CoreAuthBasecamp,
    _BoundedGoogleAuthorizedSession,
)
from apps.console.node.models import CoreGoogleCloud, CoreBasecamp
from apps.console.notification.models import (
    CoreNotificationSlack,
    SLACK_API_HOSTNAMES,
    SLACK_WEBHOOK_HOSTNAMES,
    sanitize_slack_oauth_metadata,
)
from apps.console.storage.models import (
    CoreStorage,
    CoreStorageType,
    CoreStorageDropbox,
    CoreStorageGoogleDrive,
    CoreStorageGoogleCloud,
    CoreStoragePCloud,
    CoreStorageOneDrive,
)
from apps.api.v1.utils.api_exceptions import ExceptionDefault
from ..utils.api_authentication import CsrfExemptSessionAuthentication
import time
from apps.api.v1.utils.http import requests, request_timeout
from rest_framework.parsers import FormParser
import dropbox
from cryptography.fernet import Fernet
from google.oauth2 import id_token
import google.oauth2.credentials
from datetime import datetime, timedelta, timezone
import secrets
from urllib.parse import urlsplit

from apps.api.v1.utils.api_permissions import (
    current_account_is_primary,
    member_has_perm,
)
from apps.api.v1.utils.oauth_security import (
    consume_oauth_state,
    validated_https_endpoint,
)
from apps.api.v1.connection.ovh_oauth import (
    build_ovh_client,
    consume_ovh_transaction,
    ovh_member_has_integration_permission,
)


PCLOUD_OAUTH_STATE_SESSION_KEY = "pcloud_oauth_state"
PCLOUD_ALLOWED_HOSTNAMES = frozenset({"api.pcloud.com", "eapi.pcloud.com"})
PCLOUD_OAUTH_STATE_TTL_SECONDS = 10 * 60


def _post_oauth_token(
    endpoint,
    *,
    allowed_hostnames,
    data,
    allowed_paths=None,
    allowed_path_suffixes=None,
    timeout=None,
):
    """POST credentials only to an exact provider host and never redirect."""

    endpoint = validated_https_endpoint(
        endpoint,
        allowed_hostnames=allowed_hostnames,
        allowed_paths=allowed_paths,
        allowed_path_suffixes=allowed_path_suffixes,
    )
    if endpoint is None:
        return None
    return requests.post(
        endpoint,
        data=data,
        headers={"Accept": "application/json"},
        allow_redirects=False,
        verify=True,
        timeout=timeout or request_timeout(),
    )


def _get_oauth_resource(
    endpoint,
    *,
    allowed_hostnames,
    headers,
    allowed_paths=None,
    allowed_path_prefixes=None,
):
    """GET a bearer-protected resource without forwarding across redirects."""

    endpoint = validated_https_endpoint(
        endpoint,
        allowed_hostnames=allowed_hostnames,
        allowed_paths=allowed_paths,
        allowed_path_prefixes=allowed_path_prefixes,
    )
    if endpoint is None:
        return None
    return requests.get(
        endpoint,
        headers=headers,
        allow_redirects=False,
        verify=True,
        timeout=request_timeout(),
    )


def _validated_slack_configuration_url(value):
    """Validate a display-only Slack workspace configuration link.

    Slack uses workspace subdomains for these links.  They are never requested
    by the server, and are persisted only as encrypted data, but suffix
    confusion, ports, credentials, query strings, and fragments are still
    rejected before storage.
    """

    if not isinstance(value, str):
        return None
    try:
        hostname = (urlsplit(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not (
        hostname in {"slack.com", "slack-gov.com"}
        or hostname.endswith(".slack.com")
        or hostname.endswith(".slack-gov.com")
    ):
        return None
    return validated_https_endpoint(
        value,
        allowed_hostnames={hostname},
        allowed_path_prefixes={"/"},
    )


def _validated_pcloud_hostname(value=None):
    """Return an exact official pCloud API hostname, or None.

    pCloud returns the API hostname in the callback. It is untrusted input and
    must not be allowed to turn the token or userinfo exchange into SSRF.
    """
    if value is None:
        configured = urlsplit(settings.PCLOUD_OAUTH_TOKEN_URL)
        value = configured.hostname
    if not isinstance(value, str):
        return None
    hostname = value.strip().lower().rstrip(".")
    if hostname not in PCLOUD_ALLOWED_HOSTNAMES:
        return None
    # Exact comparison above deliberately rejects schemes, ports, credentials,
    # paths, encoded delimiters and suffix-confusion hostnames.
    return hostname


def _consume_pcloud_oauth_state(request, received_state, member, account):
    expected = request.session.pop(PCLOUD_OAUTH_STATE_SESSION_KEY, None)
    if not isinstance(expected, dict) or not isinstance(received_state, str):
        return False
    expected_state = expected.get("state")
    if not isinstance(expected_state, str):
        return False
    try:
        issued_at = float(expected.get("issued_at"))
    except (TypeError, ValueError):
        return False
    age = time.time() - issued_at
    return (
        0 <= age <= PCLOUD_OAUTH_STATE_TTL_SECONDS
        and secrets.compare_digest(expected_state, received_state)
        and str(expected.get("member_id")) == str(member.pk)
        and str(expected.get("account_id")) == str(account.pk)
    )


class APICallbackSlack(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        error = data.get("error", None)
        error_description = data.get("error_description", None)
        member = self.request.user.member
        account = member.get_current_account()
        state_record = consume_oauth_state(
            request,
            provider="slack",
            received_state=data.get("state"),
            member=member,
            account=account,
        )
        if not current_account_is_primary(request) or state_record is None:
            messages.add_message(
                request,
                messages.ERROR,
                "The Slack connection request expired or could not be verified. Please try again.",
            )
            return redirect("console:settings:notification")
        if error:
            messages.add_message(
                request,
                messages.ERROR,
                error_description or "Slack did not authorize the connection.",
            )
            return redirect("console:settings:notification")

        code = data.get("code")
        if not code:
            messages.add_message(request, messages.ERROR, "The Slack callback was invalid.")
            return redirect("console:settings:notification")
        result = _post_oauth_token(
            settings.SLACK_TOKEN_URL,
            allowed_hostnames=SLACK_API_HOSTNAMES,
            allowed_paths={"/api/oauth.v2.access"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": settings.SLACK_CLIENT_ID,
                "client_secret": settings.SLACK_CLIENT_SECRET,
                "redirect_uri": f"{settings.APP_URL}/api/v1/callback/slack/",
            },
        )
        if result is None or result.status_code != 200:
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect account. Please contact support.",
            )
            return redirect("console:settings:notification")

        try:
            slack_data = result.json()
        except (TypeError, ValueError):
            slack_data = {}
        finally:
            result.close()
        incoming_webhook = slack_data.get("incoming_webhook")
        webhook_url = None
        configuration_url = None
        if isinstance(incoming_webhook, dict):
            webhook_url = validated_https_endpoint(
                incoming_webhook.get("url"),
                allowed_hostnames=SLACK_WEBHOOK_HOSTNAMES,
                allowed_path_prefixes={"/services/"},
            )
            configuration_url = _validated_slack_configuration_url(
                incoming_webhook.get("configuration_url")
            )
        if not slack_data.get("ok") or webhook_url is None:
            messages.add_message(
                request,
                messages.ERROR,
                "Slack returned an invalid authorization response. Please try again.",
            )
            return redirect("console:settings:notification")

        n_slack = CoreNotificationSlack.objects.filter(
            account=account,
            channel_id=incoming_webhook.get("channel_id"),
        ).first()
        if n_slack is None:
            n_slack = CoreNotificationSlack(account=account)
        n_slack.added_by = member
        n_slack.app_id = slack_data.get("app_id")
        n_slack.token_type = slack_data.get("token_type")
        n_slack.bot_user_id = slack_data.get("bot_user_id")
        try:
            expires_in = int(slack_data.get("expires_in"))
            n_slack.expiry = datetime.now(timezone.utc) + timedelta(
                seconds=expires_in
            ) if expires_in > 0 else None
        except (TypeError, ValueError):
            n_slack.expiry = None
        n_slack.channel = incoming_webhook.get("channel")
        n_slack.channel_id = incoming_webhook.get("channel_id")
        n_slack.set_secrets(
            access_token=slack_data.get("access_token"),
            refresh_token=slack_data.get("refresh_token"),
            configuration_url=configuration_url,
            webhook_url=webhook_url,
        )
        n_slack.data = sanitize_slack_oauth_metadata(slack_data)
        n_slack.save()

        messages.add_message(
            request,
            messages.SUCCESS,
            "Your slack is successfully connected.",
        )
        return redirect("console:settings:notification")


class APICallbackPCloud(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        error = data.get("error", None)
        error_description = data.get("error_description", None)
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()

        try:
            state = data.get("state", None)
            if not member_has_perm(request, "storage_changes"):
                messages.add_message(
                    request,
                    messages.ERROR,
                    "You do not have permission to connect storage accounts.",
                )
                return redirect("console:setup:integration_storage_open", integration_code="pcloud")
            if not _consume_pcloud_oauth_state(request, state, member, account):
                messages.add_message(
                    request,
                    messages.ERROR,
                    "The pCloud connection request expired or could not be verified. Please try again.",
                )
                return redirect("console:setup:integration_storage_open", integration_code="pcloud")
            if error:
                messages.add_message(request, messages.ERROR, error_description)
                return redirect("console:setup:integration_storage_open", integration_code="pcloud")
            else:
                code = data.get("code", None)
                location = data.get("locationid", None)
                hostname = _validated_pcloud_hostname(data.get("hostname"))
                if hostname is None or not code:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "The pCloud callback was invalid. Please try again.",
                    )
                    return redirect("console:setup:integration_storage_open", integration_code="pcloud")

                token_request_url = f"https://{hostname}/oauth2_token"
                r = requests.post(
                    token_request_url,
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "client_id": settings.PCLOUD_CLIENT_ID,
                        "client_secret": settings.PCLOUD_CLIENT_SECRET,
                        "redirect_uri": settings.APP_URL + settings.PCLOUD_REDIRECT_URL,
                    },
                    verify=True,
                    allow_redirects=False,
                    timeout=request_timeout(),
                )

                if r.status_code == 200:
                    is_new = True
                    result = r.json()
                    # Error Handling
                    if result.get("error") and result.get("error") != "":
                        capture_message(f"Unable to connect your storage. Error: {result.get('error')}")
                        messages.add_message(
                            request,
                            messages.ERROR,
                            f"Unable to connect your storage. Error: {result.get('error')}",
                        )
                        return redirect("console:setup:integration_storage_open", integration_code="pcloud")

                    storage = CoreStorage()

                    if CoreStoragePCloud.objects.filter(storage__account=account, userid=result.get("uid", result.get("userid"))).exists():
                        storage_pcloud = CoreStoragePCloud.objects.get(
                            storage__account=account,
                            userid=result.get("uid", result.get("userid")),
                        )
                        storage = storage_pcloud.storage
                        is_new = False
                    else:
                        storage_pcloud = CoreStoragePCloud()

                    storage.account = account

                    if is_new:
                        storage.status = CoreStorage.Status.ACTIVE
                        storage.type = CoreStorageType.objects.get(code="pcloud")

                    # Get User Profile using new token
                    headers = {
                        "content-type": "application/json",
                        "Authorization": f"Bearer {result['access_token']}",
                    }
                    r = requests.get(
                        f"https://{hostname}/userinfo",
                        headers=headers,
                        verify=True,
                        allow_redirects=False,
                        timeout=request_timeout(),
                    )

                    if r.status_code == 200:
                        user_info = r.json()
                        storage.name = user_info["email"]
                        storage.status = CoreStorage.Status.ACTIVE
                        storage.save()

                        storage_pcloud.storage = storage
                        storage_pcloud.access_token = bs_encrypt(result["access_token"], encryption_key)
                        storage_pcloud.token_type = result["token_type"]
                        storage_pcloud.userid = result.get("uid", result.get("userid"))

                        if location:
                            storage_pcloud.location = location
                        if hostname:
                            storage_pcloud.hostname = hostname
                        storage_pcloud.save()

                        messages.add_message(request, messages.SUCCESS, "Your storage is successfully connected.")

                        r.close()
                        return redirect("console:setup:integration_storage_open", integration_code="pcloud")
                else:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
                    )
                    return redirect("console:setup:integration_storage_open", integration_code="pcloud")
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
            )
            return redirect("console:setup:integration_storage_open", integration_code="pcloud")


class APICallbackMicrosoft(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()
        state_record = consume_oauth_state(
            request,
            provider="microsoft",
            received_state=data.get("state"),
            member=member,
            account=account,
        )
        if not member_has_perm(request, "storage_changes") or state_record is None:
            messages.add_message(
                request,
                messages.ERROR,
                "The OneDrive connection request expired or could not be verified. Please try again.",
            )
            return redirect(
                "console:setup:integration_storage_open", integration_code="onedrive"
            )
        if data.get("error"):
            messages.add_message(
                request,
                messages.ERROR,
                data.get("error_description")
                or "Microsoft did not authorize the connection.",
            )
            return redirect(
                "console:setup:integration_storage_open", integration_code="onedrive"
            )
        code = data.get("code")
        if not code or not state_record.get("code_verifier"):
            messages.add_message(request, messages.ERROR, "The OneDrive callback was invalid.")
            return redirect(
                "console:setup:integration_storage_open", integration_code="onedrive"
            )
        try:
            token_request = _post_oauth_token(
                settings.MS_OAUTH_TOKEN_URL,
                allowed_hostnames={"login.microsoftonline.com"},
                allowed_path_suffixes={"/oauth2/v2.0/token"},
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": settings.MS_CLIENT_ID,
                    "client_secret": settings.MS_CLIENT_SECRET_VALUE,
                    "redirect_uri": settings.APP_URL + settings.MS_REDIRECT_URL,
                    "code_verifier": state_record["code_verifier"],
                },
                timeout=request_timeout(),
            )
            if token_request is None or token_request.status_code != 200:
                raise ValueError("OneDrive token exchange failed")
            token_data = token_request.json()
            graph_base = validated_https_endpoint(
                settings.MS_GRAPH_ENDPOINT,
                allowed_hostnames={"graph.microsoft.com"},
                allowed_paths={"/v1.0"},
            )
            if graph_base is None:
                raise ValueError("OneDrive Graph endpoint is invalid")
            headers = {"Authorization": f"Bearer {token_data['access_token']}"}
            profile_request = _get_oauth_resource(
                f"{graph_base}/me",
                allowed_hostnames={"graph.microsoft.com"},
                allowed_paths={"/v1.0/me"},
                headers=headers,
            )
            drive_request = _get_oauth_resource(
                f"{graph_base}/me/drive",
                allowed_hostnames={"graph.microsoft.com"},
                allowed_paths={"/v1.0/me/drive"},
                headers=headers,
            )
            if (
                profile_request is None
                or profile_request.status_code != 200
                or drive_request is None
                or drive_request.status_code != 200
            ):
                raise ValueError("OneDrive account details could not be verified")
            profile_data = profile_request.json()
            drive_data = drive_request.json()

            storage = CoreStorage()
            if CoreStorageOneDrive.objects.filter(
                storage__account=account, user_id=profile_data.get("id")
            ).exists():
                storage_onedrive = CoreStorageOneDrive.objects.get(
                    storage__account=account,
                    user_id=profile_data.get("id"),
                )
                storage = storage_onedrive.storage
            else:
                storage_onedrive = CoreStorageOneDrive()

            storage.account = account
            storage.name = f"{profile_data.get('userPrincipalName', '')}"
            storage.status = CoreStorage.Status.ACTIVE
            storage.type = CoreStorageType.objects.get(code="onedrive")
            storage.save()

            storage_onedrive.storage = storage
            storage_onedrive.access_token = bs_encrypt(
                token_data["access_token"], encryption_key
            )
            storage_onedrive.refresh_token = bs_encrypt(
                token_data["refresh_token"], encryption_key
            )
            storage_onedrive.token_type = token_data["token_type"]
            storage_onedrive.scope = token_data["scope"]
            storage_onedrive.user_id = profile_data.get("id")
            storage_onedrive.drive_id = drive_data.get("id")
            storage_onedrive.drive_type = drive_data.get("driveType")
            storage_onedrive.metadata = drive_data
            storage_onedrive.expiry = datetime.fromtimestamp(
                int(time.time()) + int(token_data["expires_in"])
            )
            storage_onedrive.save()

            messages.add_message(
                request,
                messages.SUCCESS,
                "Your storage is successfully connected.",
            )
            return redirect(
                "console:setup:integration_storage_open", integration_code="onedrive"
            )
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
            )
            return redirect(
                "console:setup:integration_storage_open", integration_code="onedrive"
            )


class APICallbackBasecamp(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()
        state_record = consume_oauth_state(
            request,
            provider="basecamp",
            received_state=data.get("state"),
            member=member,
            account=account,
        )
        if not member_has_perm(request, "integration_changes") or state_record is None:
            messages.add_message(
                request,
                messages.ERROR,
                "The Basecamp connection request expired or could not be verified. Please try again.",
            )
            return redirect(
                "console:setup:integration_open", integration_code="basecamp"
            )
        if data.get("error"):
            messages.add_message(
                request,
                messages.ERROR,
                data.get("error_description")
                or "Basecamp did not authorize the connection.",
            )
            return redirect(
                "console:setup:integration_open", integration_code="basecamp"
            )
        code = data.get("code")
        if not code:
            messages.add_message(request, messages.ERROR, "The Basecamp callback was invalid.")
            return redirect(
                "console:setup:integration_open", integration_code="basecamp"
            )
        try:
            token_request = _post_oauth_token(
                settings.BASECAMP_TOKEN_ENDPOINT,
                allowed_hostnames={"launchpad.37signals.com"},
                allowed_paths={"/authorization/token"},
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "type": "web_server",
                    "client_id": settings.BASECAMP_CLIENT_ID,
                    "client_secret": settings.BASECAMP_CLIENT_SECRET,
                    "redirect_uri": settings.APP_URL + settings.BASECAMP_REDIRECT_URL,
                },
            )
            if token_request is None or token_request.status_code != 200:
                raise ValueError("Basecamp token exchange failed")
            token_data = token_request.json()
            response = _get_oauth_resource(
                "https://launchpad.37signals.com/authorization.json",
                allowed_hostnames={"launchpad.37signals.com"},
                allowed_paths={"/authorization.json"},
                headers={"Authorization": f"Bearer {token_data['access_token']}"},
            )
            if response is None or response.status_code != 200:
                raise ValueError("Basecamp authorization identity lookup failed")
            authorization = response.json()
            identity = authorization.get("identity")
            if not isinstance(identity, dict) or identity.get("id") is None:
                raise ValueError("Basecamp returned an invalid authorization identity")

            if CoreAuthBasecamp.objects.filter(
                connection__account=account, identity_id=identity["id"]
            ).exists():
                auth = CoreAuthBasecamp.objects.get(
                    connection__account=account, identity_id=identity["id"]
                )
            else:
                connection = CoreConnection()
                connection.integration = CoreIntegration.objects.get(code="basecamp")
                connection.name = (
                    f'{identity.get("email_address")} ({identity.get("id")})'
                )
                connection.account = account
                connection.location = connection.integration.locations.all().order_by(
                    "?"
                )[0]
                connection.save()
                auth = CoreAuthBasecamp(connection=connection)

            auth.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            auth.refresh_token = bs_encrypt(token_data["refresh_token"], encryption_key)
            auth.expiry = datetime.fromtimestamp(
                int(time.time()) + int(token_data["expires_in"])
            )
            auth.identity_id = identity["id"]
            auth.metadata = authorization
            auth.save()

            auth.connection.status = CoreConnection.Status.ACTIVE
            auth.connection.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                "Your account is successfully connected. You can create nodes for your Basecamp now.",
            )
            return redirect(
                "console:setup:integration_open", integration_code="basecamp"
            )
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your Basecamp account. Please contact support at " "support@backupsheep.com",
            )
            return redirect(
                "console:setup:integration_open", integration_code="basecamp"
            )


class APICallbackDigitalOcean(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        member = request.user.member
        account = member.get_current_account()
        state_record = consume_oauth_state(
            request,
            provider="digitalocean",
            received_state=data.get("state"),
            member=member,
            account=account,
        )
        if not member_has_perm(request, "integration_changes") or state_record is None:
            messages.add_message(
                request,
                messages.ERROR,
                "The DigitalOcean connection request expired or could not be verified. Please try again.",
            )
            return redirect("console:setup:integration_open", integration_code="digitalocean")
        if data.get("error"):
            messages.add_message(
                request,
                messages.ERROR,
                data.get("error_description")
                or "DigitalOcean did not authorize the connection.",
            )
            return redirect("console:setup:integration_open", integration_code="digitalocean")
        code = data.get("code")
        if not code:
            messages.add_message(
                request, messages.ERROR, "The DigitalOcean callback was invalid."
            )
            return redirect("console:setup:integration_open", integration_code="digitalocean")

        result = _post_oauth_token(
            settings.DIGITALOCEAN_TOKEN_URL,
            allowed_hostnames={"cloud.digitalocean.com"},
            allowed_paths={"/v1/oauth/token"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": settings.DIGITALOCEAN_APP_CLIENT_ID,
                "client_secret": settings.DIGITALOCEAN_APP_CLIENT_SECRET,
                "redirect_uri": f"{settings.APP_URL}/api/v1/callback/digitalocean/",
            },
        )
        if result is None or result.status_code != 200:
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect account. Please contact support.",
            )
            return redirect("console:setup:integration_open", integration_code="digitalocean")

        try:
            do_tokens = result.json()
            info = do_tokens["info"]
            info_uuid = info["uuid"]
            encryption_key = account.get_encryption_key()
            if CoreAuthDigitalOcean.objects.filter(
                connection__account=account, info_uuid=info_uuid
            ).exists():
                auth = CoreAuthDigitalOcean.objects.get(
                    connection__account=account, info_uuid=info_uuid
                )
            else:
                connection = CoreConnection()
                connection.integration = CoreIntegration.objects.get(
                    code="digitalocean"
                )
                connection.name = info["name"]
                connection.account = account
                connection.location = connection.integration.locations.all().order_by(
                    "?"
                )[0]
                connection.save()
                auth = CoreAuthDigitalOcean(connection=connection)

            auth.access_token = bs_encrypt(do_tokens["access_token"], encryption_key)
            auth.refresh_token = bs_encrypt(do_tokens["refresh_token"], encryption_key)
            auth.expiry = datetime.fromtimestamp(
                int(time.time()) + int(do_tokens["expires_in"])
            )
            auth.scope = do_tokens["scope"]
            auth.token_type = do_tokens.get("bearer") or do_tokens.get("token_type")
            auth.info_name = info["name"]
            auth.info_email = info["email"]
            auth.info_uuid = info_uuid
            auth.save()
            auth.connection.status = CoreConnection.Status.ACTIVE
            auth.connection.save()
        except (KeyError, TypeError, ValueError) as error:
            capture_exception(error)
            messages.add_message(
                request,
                messages.ERROR,
                "DigitalOcean returned an invalid authorization response.",
            )
            return redirect("console:setup:integration_open", integration_code="digitalocean")

        messages.add_message(
            request,
            messages.SUCCESS,
            "Your account is successfully connected. You can add schedules for this server.",
        )
        result.close()
        return redirect("console:setup:integration_open", integration_code="digitalocean")


_OVH_CALLBACK_CONFIG = {
    "ovh_ca": {
        "auth_model": CoreAuthOVHCA,
        "integration_code": "ovh_ca",
    },
    "ovh_eu": {
        "auth_model": CoreAuthOVHEU,
        "integration_code": "ovh_eu",
    },
    "ovh_us": {
        "auth_model": CoreAuthOVHUS,
        "integration_code": "ovh_us",
    },
}


def _ovh_profile_text(value, *, maximum, required=False):
    if value is None:
        if required:
            raise ValueError("OVH profile field is missing")
        return None
    value = str(value).strip()
    if (
        (required and not value)
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("OVH profile field is invalid")
    return value or None


def _complete_ovh_callback(request, provider):
    config = _OVH_CALLBACK_CONFIG[provider]
    integration_code = config["integration_code"]
    try:
        member = request.user.member
        account = member.get_current_account()
        consumer_key = consume_ovh_transaction(
            request,
            provider,
            member=member,
            account=account,
            received_state=request.query_params.get("state"),
        )
        permitted = ovh_member_has_integration_permission(request, account)
    except Exception:
        consumer_key = None
        permitted = False
    if not permitted or consumer_key is None:
        messages.add_message(
            request,
            messages.ERROR,
            "The OVHcloud authorization request expired or could not be verified. Please try again.",
        )
        return redirect(
            "console:setup:integration_open", integration_code=integration_code
        )

    try:
        client = build_ovh_client(provider, consumer_key=consumer_key)
        ovh_account = client.get("/me")
        if not isinstance(ovh_account, dict):
            raise ValueError("OVH returned an invalid account profile")
        customer_code = _ovh_profile_text(
            ovh_account.get("customerCode"), maximum=1024, required=True
        )
        first_name = _ovh_profile_text(
            ovh_account.get("firstname"), maximum=512
        )
        last_name = _ovh_profile_text(ovh_account.get("name"), maximum=512)
        info_name = " ".join(
            part for part in (first_name, last_name) if part
        ) or customer_code
        info_email = _ovh_profile_text(ovh_account.get("email"), maximum=255)
        info_organization = _ovh_profile_text(
            ovh_account.get("organization") or "n/a", maximum=1024
        )
        encryption_key = account.get_encryption_key()
        with transaction.atomic():
            auth = (
                config["auth_model"]
                .objects.select_for_update()
                .filter(
                    connection__account=account,
                    info_customer_code=customer_code,
                )
                .first()
            )
            if auth is None:
                connection = CoreConnection(account=account, added_by=member)
                connection.integration = CoreIntegration.objects.get(
                    code=integration_code
                )
                connection.name = connection.integration.name
                connection.location = connection.integration.locations.order_by(
                    "pk"
                ).first()
                if connection.location is None:
                    raise ValueError("OVH integration has no configured location")
                connection.save()
                auth = config["auth_model"](connection=connection)
            else:
                connection = CoreConnection.objects.select_for_update().get(
                    pk=auth.connection_id,
                    account=account,
                )

            auth.info_name = info_name
            auth.info_customer_code = customer_code
            auth.info_email = info_email
            auth.info_organization = info_organization
            auth.consumer_key = bs_encrypt(consumer_key, encryption_key)
            if not auth.consumer_key:
                raise ValueError("OVH consumer key encryption failed")
            auth.save()
            connection.status = CoreConnection.Status.ACTIVE
            connection.save(update_fields=["status", "modified"])

        messages.add_message(
            request,
            messages.SUCCESS,
            "Your OVHcloud account is successfully connected.",
        )
    except Exception as error:
        # Never send the exception or local consumer key to Sentry/logs.
        capture_message(
            f"{provider} callback failed ({type(error).__name__})",
            level="error",
        )
        messages.add_message(
            request,
            messages.ERROR,
            "Unable to connect the OVHcloud account. Please try again.",
        )
    return redirect(
        "console:setup:integration_open", integration_code=integration_code
    )


class APICallbackOVHCA(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return _complete_ovh_callback(request, "ovh_ca")


class APICallbackOVHUS(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return _complete_ovh_callback(request, "ovh_us")


class APICallbackOVHEU(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return _complete_ovh_callback(request, "ovh_eu")


class APICallbackDropbox(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        member = self.request.user.member
        account = member.get_current_account()
        state_record = consume_oauth_state(
            request,
            provider="dropbox",
            received_state=self.request.query_params.get("state"),
            member=member,
            account=account,
        )
        if not member_has_perm(request, "storage_changes") or state_record is None:
            messages.add_message(
                request,
                messages.ERROR,
                "The Dropbox connection request expired or could not be verified. Please try again.",
            )
            return redirect(
                "console:setup:integration_storage_open", integration_code="dropbox"
            )
        if self.request.query_params.get("error"):
            messages.add_message(
                request,
                messages.ERROR,
                self.request.query_params.get("error_description")
                or "Dropbox did not authorize the connection.",
            )
            return redirect(
                "console:setup:integration_storage_open", integration_code="dropbox"
            )
        code = self.request.query_params.get("code")
        if not code or not state_record.get("code_verifier"):
            messages.add_message(request, messages.ERROR, "The Dropbox callback was invalid.")
            return redirect(
                "console:setup:integration_storage_open", integration_code="dropbox"
            )
        try:
            encryption_key = account.get_encryption_key()
            r = _post_oauth_token(
                "https://api.dropboxapi.com/oauth2/token",
                allowed_hostnames={"api.dropboxapi.com"},
                allowed_paths={"/oauth2/token"},
                data={
                    "code": code,
                    "grant_type": "authorization_code",
                    "client_id": settings.DROPBOX_APP_KEY,
                    "client_secret": settings.DROPBOX_APP_SECRET,
                    "redirect_uri": f"{settings.APP_URL}/api/v1/callback/dropbox",
                    "code_verifier": state_record["code_verifier"],
                },
            )
            if r is not None and r.status_code == 200:
                is_new = True
                result = r.json()
                storage = CoreStorage()
                storage_dropbox = CoreStorageDropbox()

                if result.get("account_id", None):
                    if CoreStorageDropbox.objects.filter(
                        storage__account=account, account_id=result.get("account_id")
                    ).exists():
                        storage_dropbox = CoreStorageDropbox.objects.get(
                            storage__account=account,
                            account_id=result.get("account_id"),
                        )
                        storage = storage_dropbox.storage
                        is_new = False
                elif result.get("team_id", None):
                    if CoreStorageDropbox.objects.filter(
                        storage__account=account, team_id=result.get("team_id")
                    ).exists():
                        storage_dropbox = CoreStorageDropbox.objects.get(
                            storage__account=account, team_id=result.get("team_id")
                        )
                        storage = storage_dropbox.storage
                        is_new = False
                storage.account = account

                if is_new:
                    storage.status = CoreStorage.Status.ACTIVE
                    storage.type = CoreStorageType.objects.get(code="dropbox")

                dbx = dropbox.Dropbox(result["access_token"])
                dbx_account = dbx.users_get_current_account()
                storage.name = dbx_account.name.display_name + " - " + dbx_account.email
                storage.status = CoreStorage.Status.ACTIVE
                storage.save()

                storage_dropbox.storage = storage
                storage_dropbox.access_token = bs_encrypt(result["access_token"], encryption_key)
                storage_dropbox.refresh_token = bs_encrypt(result["refresh_token"], encryption_key)
                storage_dropbox.token_type = result["token_type"]
                storage_dropbox.account_id = result.get("account_id", None)
                storage_dropbox.team_id = result.get("team_id", None)
                storage_dropbox.uid = result.get("uid", None)
                storage_dropbox.expiry = datetime.fromtimestamp((int(time.time()) + int(result["expires_in"])))
                storage_dropbox.save()

                messages.add_message(request, messages.SUCCESS, "Your storage is successfully connected.")

                r.close()
                return redirect("console:setup:integration_storage_open", integration_code="dropbox")
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
                )
                return redirect("console:setup:integration_storage_open", integration_code="dropbox")
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
            )
            return redirect("console:setup:integration_storage_open", integration_code="dropbox")


class APICallbackGoogleDrive(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        member = self.request.user.member
        account = member.get_current_account()
        state_record = consume_oauth_state(
            request,
            provider="google_drive",
            received_state=self.request.query_params.get("state"),
            member=member,
            account=account,
        )
        if not member_has_perm(request, "storage_changes") or state_record is None:
            messages.add_message(
                request,
                messages.ERROR,
                "The Google Drive connection request expired or could not be verified. Please try again.",
            )
            return redirect(
                "console:setup:integration_storage_open",
                integration_code="google_drive",
            )
        if self.request.query_params.get("error"):
            messages.add_message(
                request,
                messages.ERROR,
                self.request.query_params.get("error_description")
                or "Google did not authorize the connection.",
            )
            return redirect(
                "console:setup:integration_storage_open",
                integration_code="google_drive",
            )
        code = self.request.query_params.get("code")
        if not code or not state_record.get("code_verifier"):
            messages.add_message(
                request, messages.ERROR, "The Google Drive callback was invalid."
            )
            return redirect(
                "console:setup:integration_storage_open",
                integration_code="google_drive",
            )
        try:
            encryption_key = account.get_encryption_key()
            scope = ["https://www.googleapis.com/auth/drive.file"]
            token_request = _post_oauth_token(
                "https://oauth2.googleapis.com/token",
                allowed_hostnames={"oauth2.googleapis.com"},
                allowed_paths={"/token"},
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": f"{settings.APP_URL}/api/v1/callback/google_drive/",
                    "code_verifier": state_record["code_verifier"],
                },
                timeout=request_timeout(),
            )
            if token_request is None or token_request.status_code != 200:
                raise ValueError("Google Drive token exchange failed")
            response = token_request.json()

            if response:
                is_new = True
                storage = CoreStorage()
                storage_google_drive = CoreStorageGoogleDrive()
                token_expiry = datetime.fromtimestamp(
                    int(time.time()) + int(response["expires_in"]),
                    tz=timezone.utc,
                )
                credentials = google.oauth2.credentials.Credentials(
                    response["access_token"],
                    token_uri="https://oauth2.googleapis.com/token",
                    client_id=settings.GOOGLE_CLIENT_ID,
                    client_secret=settings.GOOGLE_CLIENT_SECRET,
                    refresh_token=response["refresh_token"],
                    scopes=scope,
                    # google-auth currently compares against a naive UTC clock.
                    # Keep the model value timezone-aware below.
                    expiry=token_expiry.replace(tzinfo=None),
                )
                client = _BoundedGoogleAuthorizedSession(credentials)
                client.max_redirects = 0
                about_response = client.get(
                    "https://www.googleapis.com/drive/v3/about",
                    params={"fields": "appInstalled,user"},
                    allow_redirects=False,
                )
                if about_response.status_code != 200:
                    raise ValueError(
                        "Google Drive account details could not be verified."
                    )
                about = about_response.json()
                if not isinstance(about, dict) or not isinstance(
                    about.get("user"), dict
                ):
                    raise ValueError(
                        "Google Drive returned malformed account details."
                    )

                if CoreStorageGoogleDrive.objects.filter(
                    storage__account=account,
                    email_address=about["user"]["emailAddress"],
                ).exists():
                    storage_google_drive = CoreStorageGoogleDrive.objects.get(
                        storage__account=account,
                        email_address=about["user"]["emailAddress"],
                    )
                    storage = storage_google_drive.storage
                    is_new = False

                storage.account = account

                if is_new:
                    storage.type = CoreStorageType.objects.get(code="google_drive")

                storage.name = about["user"]["displayName"] + " -  " + about["user"]["emailAddress"]
                storage.status = CoreStorage.Status.ACTIVE
                storage.save()
                storage_google_drive.storage = storage
                storage_google_drive.access_token = bs_encrypt(credentials.token, encryption_key)
                storage_google_drive.refresh_token = bs_encrypt(credentials.refresh_token, encryption_key)
                storage_google_drive.expiry = token_expiry
                storage_google_drive.email_address = about["user"]["emailAddress"]
                storage_google_drive.display_name = about["user"]["displayName"]
                storage_google_drive.save()

                messages.add_message(request, messages.SUCCESS, "Your storage is successfully connected.")
                return redirect("console:setup:integration_storage_open", integration_code="google_drive")
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to connect your storage. Check if the domain administrators " "have disabled Drive apps.",
                )
                return redirect("console:setup:integration_storage_open", integration_code="google_drive")
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your storage. Check if the domain administrators have disabled " "Drive apps.",
            )
            return redirect("console:setup:integration_storage_open", integration_code="google_drive")


class APIGoogleCloud(APIView):
    """Reject the retired user-OAuth flow; Google Cloud uses service accounts."""

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        messages.add_message(
            request,
            messages.ERROR,
            "Google Cloud user OAuth is retired. Connect Google Cloud with a service account.",
        )
        return redirect(
            "console:setup:integration_open", integration_code="google_cloud"
        )
