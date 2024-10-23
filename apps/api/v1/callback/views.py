import stripe
from requests_oauthlib import OAuth2Session
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.shortcuts import redirect
from django.contrib import messages
from sentry_sdk import capture_exception, capture_message
from django.core.cache import cache
from apps.console.api.v1.utils.api_helpers import bs_encrypt
from apps.console.billing.models import CorePayPalCredit
from apps.console.member.models import CoreMember
from apps.console.connection.models import (
    CoreConnection,
    CoreIntegration,
    CoreAuthDigitalOcean,
    CoreAuthOVHCA,
    CoreAuthOVHEU,
    CoreAuthOVHUS, CoreAuthGoogleCloud, CoreConnectionLocation, CoreAuthBasecamp,
)
from apps.console.node.models import CoreGoogleCloud, CoreBasecamp
from apps.console.notification.models import CoreNotificationSlack
from apps.console.storage.models import (
    CoreStorage,
    CoreStorageType,
    CoreStorageDropbox,
    CoreStorageGoogleDrive,
    CoreStorageGoogleCloud,
    CoreStoragePCloud,
    CoreStorageOneDrive,
)
from apps.utils.api_exceptions import ExceptionDefault
from ..utils.api_authentication import CsrfExemptSessionAuthentication
import time
import ovh
import requests
from rest_framework.parsers import FormParser
import dropbox
import httplib2
from apiclient import discovery
from cryptography.fernet import Fernet
from google.oauth2 import id_token
import google.oauth2.credentials
from datetime import datetime
from slack_sdk import WebClient, WebhookClient
from slack_sdk.errors import SlackApiError


class APICallbackSlack(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        error = data.get("error", None)
        error_description = data.get("error_description", None)
        member = self.request.user.member
        account = member.get_current_account()

        if error:
            messages.add_message(request, messages.ERROR, error_description)
            return redirect("console:settings:notification")
        else:
            state = data.get("state", None)
            code = data.get("code", None)

            token_request_url = (
                f"{settings.SLACK_TOKEN_URL}?"
                f"grant_type=authorization_code"
                f"&code={code}"
                f"&client_id={settings.SLACK_CLIENT_ID}"
                f"&client_secret={settings.SLACK_CLIENT_SECRET}"
                f"&redirect_uri={settings.APP_URL + '/api/v1/callback/slack/'}"
            )

            result = requests.post(token_request_url)

            if result.status_code == 200:
                slack_data = result.json()

                if slack_data.get("ok"):
                    n_slack, created = CoreNotificationSlack.objects.get_or_create(
                        account=account,
                        channel=slack_data.get("incoming_webhook").get("channel"),
                        channel_id=slack_data.get("incoming_webhook").get("channel_id"),
                    )
                    n_slack.added_by = member
                    n_slack.app_id = slack_data.get("app_id")
                    n_slack.token_type = slack_data.get("token_type")
                    n_slack.access_token = slack_data.get("access_token")
                    n_slack.bot_user_id = slack_data.get("bot_user_id")
                    n_slack.refresh_token = slack_data.get("refresh_token")
                    n_slack.expiry = datetime.fromtimestamp((int(time.time()) + int(slack_data["expires_in"])))
                    n_slack.channel = slack_data.get("incoming_webhook").get("channel")
                    n_slack.url = slack_data.get("incoming_webhook").get("url")
                    n_slack.data = slack_data
                    n_slack.save()

                    # Send Welcome Message on Slack
                    webhook = WebhookClient(slack_data["incoming_webhook"]["url"])
                    webhook.send(
                        text="Hey! You successfully connected BackupSheep with your slack.",
                    )

                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        "Your slack is successfully connected.",
                    )

                    result.close()

                    n_slack.refresh_auth_token()

                    return redirect("console:settings:notification")
                else:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        f"Unable to connect account because of error {slack_data.get('error')}. Please contact support.",
                    )
                    return redirect("console:settings:notification")

            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to connect account. Please contact support.",
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
            if error:
                messages.add_message(request, messages.ERROR, error_description)
                return redirect("console:setup:integration_storage_open", integration_code="pcloud")
            else:
                state = data.get("state", None)
                code = data.get("code", None)
                location = data.get("locationid", None)
                hostname = data.get("hostname", settings.PCLOUD_OAUTH_TOKEN_URL)

                token_request_url = (
                    f"https://{hostname}/oauth2_token?"
                    f"grant_type=authorization_code"
                    f"&code={code}"
                    f"&client_id={settings.PCLOUD_CLIENT_ID}"
                    f"&client_secret={settings.PCLOUD_CLIENT_SECRET}"
                    f"&redirect_uri={settings.APP_URL + settings.PCLOUD_REDIRECT_URL}"
                )

                r = requests.post(token_request_url)

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

                    if CoreStoragePCloud.objects.filter(storage__account=account, userid=result.get("userid")).exists():
                        storage_pcloud = CoreStoragePCloud.objects.get(
                            storage__account=account,
                            userid=result.get("userid"),
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
                    r = requests.get(f"https://{hostname}/userinfo", headers=headers, verify=True)

                    if r.status_code == 200:
                        user_info = r.json()
                        storage.name = user_info["email"]
                        storage.status = CoreStorage.Status.ACTIVE
                        storage.save()

                        storage_pcloud.storage = storage
                        storage_pcloud.access_token = bs_encrypt(result["access_token"], encryption_key)
                        storage_pcloud.token_type = result["token_type"]
                        storage_pcloud.userid = result.get("userid", None)

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
        error = data.get("error", None)
        error_description = data.get("error_description", None)
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()

        try:
            if error:
                messages.add_message(request, messages.ERROR, error_description)
                return redirect("console:setup:integration_storage_open", integration_code="onedrive")
            else:
                code = data.get("code", None)

                params = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": settings.MS_CLIENT_ID,
                    "client_secret": settings.MS_CLIENT_SECRET_VALUE,
                    "redirect_uri": f"{settings.APP_URL + settings.MS_REDIRECT_URL}",
                }

                token_request = requests.post(settings.MS_OAUTH_TOKEN_URL, data=params)

                if token_request.status_code == 200:
                    token_data = token_request.json()

                    url = f"{settings.MS_GRAPH_ENDPOINT}/me"

                    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

                    profile_request = requests.request("GET", url, headers=headers, data={})

                    if profile_request.status_code == 200:
                        profile_data = profile_request.json()

                        url = f"{settings.MS_GRAPH_ENDPOINT}/users/{profile_data['id']}/drive"
                        drive_request = requests.request("GET", url, headers=headers, data={})

                        if drive_request.status_code == 200:
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
                            storage_onedrive.access_token = bs_encrypt(token_data["access_token"], encryption_key)
                            storage_onedrive.refresh_token = bs_encrypt(token_data["refresh_token"], encryption_key)
                            storage_onedrive.token_type = token_data["token_type"]
                            storage_onedrive.scope = token_data["scope"]
                            storage_onedrive.user_id = profile_data.get("id")
                            storage_onedrive.drive_id = drive_data.get("id")
                            storage_onedrive.drive_type = drive_data.get("driveType")
                            storage_onedrive.metadata = drive_data
                            storage_onedrive.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
                            storage_onedrive.save()

                            messages.add_message(request, messages.SUCCESS, "Your storage is successfully connected.")

                            return redirect("console:setup:integration_storage_open", integration_code="onedrive")
                    else:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
                        )
                else:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
                    )
                    return redirect("console:setup:integration_storage_open", integration_code="onedrive")
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your storage. Please contact support at " "support@backupsheep.com",
            )
            return redirect("console:setup:integration_storage_open", integration_code="onedrive")


class APICallbackBasecamp(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        error = data.get("error", None)
        error_description = data.get("error_description", None)
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()

        try:
            if error:
                messages.add_message(request, messages.ERROR, error_description)
                return redirect("console:setup:integration_open", integration_code="basecamp")
            else:
                code = data.get("code", None)

                params = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "type": "web_server",
                    "client_id": settings.BASECAMP_CLIENT_ID,
                    "client_secret": settings.BASECAMP_CLIENT_SECRET,
                    "redirect_uri": f"{settings.APP_URL + settings.BASECAMP_REDIRECT_URL}",
                }

                token_request = requests.post(settings.BASECAMP_TOKEN_ENDPOINT, data=params)

                if token_request.status_code == 200:
                    token_data = token_request.json()

                    url = "https://launchpad.37signals.com/authorization.json"

                    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

                    response = requests.request("GET", url, headers=headers, data={})

                    if response.status_code == 200:
                        authorization = response.json()

                        if CoreAuthBasecamp.objects.filter(
                            connection__account=account, identity_id=authorization.get("identity").get("id")
                        ).exists():
                            auth = CoreAuthBasecamp.objects.get(
                                connection__account=account, identity_id=authorization.get("identity").get("id")
                            )
                        else:
                            connection = CoreConnection()
                            connection.integration = CoreIntegration.objects.get(code="basecamp")
                            connection.name = f'{authorization.get("identity").get("email_address")} ({authorization.get("identity").get("id")})'
                            connection.account = account
                            connection.location = connection.integration.locations.all().order_by("?")[0]
                            connection.save()
                            auth = CoreAuthBasecamp(connection=connection)

                        auth.access_token = bs_encrypt(token_data["access_token"], encryption_key)
                        auth.refresh_token = bs_encrypt(token_data["refresh_token"], encryption_key)

                        auth.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))

                        auth.identity_id = authorization.get("identity").get("id")
                        auth.metadata = authorization
                        auth.save()

                        # set connection status to active
                        auth.connection.status = CoreConnection.Status.ACTIVE
                        auth.connection.save()

                        messages.add_message(
                            request,
                            messages.SUCCESS,
                            "Your account is successfully connected. You can create nodes for your Basecamp now.",
                        )

                        return redirect("console:setup:integration_open", integration_code="basecamp")
                    else:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            "Unable to connect your Basecamp account. Please contact support at " "support@backupsheep.com",
                        )
                else:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Unable to connect your Basecamp account. Please contact support at " "support@backupsheep.com",
                    )
                    return redirect("console:setup:integration_open", integration_code="basecamp")
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your Basecamp account. Please contact support at " "support@backupsheep.com",
            )
            return redirect("console:setup:integration_open", integration_code="basecamp")

class APICallbackIntercom(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        error = data.get("error", None)
        error_description = data.get("error_description", None)
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()

        try:
            if error:
                messages.add_message(request, messages.ERROR, error_description)
                return redirect("console:setup:integration_open", integration_code="intercom")
            else:
                code = data.get("code", None)

                params = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "type": "web_server",
                    "client_id": settings.INTERCOM_CLIENT_ID,
                    "client_secret": settings.INTERCOM_CLIENT_SECRET,
                    "redirect_uri": f"{settings.APP_URL + settings.INTERCOM_REDIRECT_URL}",
                }

                token_request = requests.post(settings.INTERCOM_TOKEN_ENDPOINT, data=params)

                if token_request.status_code == 200:
                    token_data = token_request.json()

                    url = "https://launchpad.37signals.com/authorization.json"

                    headers = {"Authorization": f"Bearer {token_data['access_token']}"}

                    response = requests.request("GET", url, headers=headers, data={})

                    if response.status_code == 200:
                        authorization = response.json()

                        if CoreAuthBasecamp.objects.filter(
                            connection__account=account, identity_id=authorization.get("identity").get("id")
                        ).exists():
                            auth = CoreAuthBasecamp.objects.get(
                                connection__account=account, identity_id=authorization.get("identity").get("id")
                            )
                        else:
                            connection = CoreConnection()
                            connection.integration = CoreIntegration.objects.get(code="basecamp")
                            connection.name = f'{authorization.get("identity").get("email_address")} ({authorization.get("identity").get("id")})'
                            connection.account = account
                            connection.location = connection.integration.locations.all().order_by("?")[0]
                            connection.save()
                            auth = CoreAuthBasecamp(connection=connection)

                        auth.access_token = bs_encrypt(token_data["access_token"], encryption_key)
                        auth.refresh_token = bs_encrypt(token_data["refresh_token"], encryption_key)

                        auth.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))

                        auth.identity_id = authorization.get("identity").get("id")
                        auth.metadata = authorization
                        auth.save()

                        # set connection status to active
                        auth.connection.status = CoreConnection.Status.ACTIVE
                        auth.connection.save()

                        messages.add_message(
                            request,
                            messages.SUCCESS,
                            "Your account is successfully connected. You can create nodes for your Basecamp now.",
                        )

                        return redirect("console:setup:integration_open", integration_code="basecamp")
                    else:
                        messages.add_message(
                            request,
                            messages.ERROR,
                            "Unable to connect your Basecamp account. Please contact support at " "support@backupsheep.com",
                        )
                else:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Unable to connect your Basecamp account. Please contact support at " "support@backupsheep.com",
                    )
                    return redirect("console:setup:integration_open", integration_code="basecamp")
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect your Basecamp account. Please contact support at " "support@backupsheep.com",
            )
            return redirect("console:setup:integration_open", integration_code="basecamp")


class APICallbackDigitalOcean(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        data = self.request.query_params
        error = data.get("error", None)
        error_description = data.get("error_description", None)

        if error:
            messages.add_message(request, messages.ERROR, error_description)
            return redirect("console:setup:integration_open", integration_code="digitalocean")
        else:
            state = data.get("state", None)
            code = data.get("code", None)

            token_request_url = (
                f"{settings.DIGITALOCEAN_TOKEN_URL}?"
                f"grant_type=authorization_code"
                f"&code={code}"
                f"&client_id={settings.DIGITALOCEAN_APP_CLIENT_ID}"
                f"&client_secret={settings.DIGITALOCEAN_APP_CLIENT_SECRET}"
                f"&redirect_uri={settings.APP_URL + '/api/v1/callback/digitalocean/'}"
            )

            result = requests.post(token_request_url)

            if result.status_code == 200:
                do_tokens = result.json()

                # """
                # Fetch account detail so we can identofy for which account this token belongs to.
                # Otherwise it will replace existing token. So if you are a user who's in different DigitalOcean teams then
                # this will create huge problem and invalidate all existing integrations.
                # """
                # client = {
                #     "content-type": "application/json",
                #     "Authorization": "%s %s"
                #                      % (do_tokens["bearer"], do_tokens["access_token"]),
                # }
                # account_req = requests.get(
                #     f"{settings.DIGITALOCEAN_API}/v2/account",
                #     headers=client,
                #     verify=True,
                # )
                # if account_req.status_code == 200:
                #     do_account = account_req.json()

                member = CoreMember.objects.get(id=state)
                account = member.get_current_account()
                encryption_key = account.get_encryption_key()

                if CoreAuthDigitalOcean.objects.filter(
                    connection__account=account, info_uuid=do_tokens["info"]["uuid"]
                ).exists():
                    auth = CoreAuthDigitalOcean.objects.get(
                        connection__account=account, info_uuid=do_tokens["info"]["uuid"]
                    )
                else:
                    connection = CoreConnection()
                    connection.integration = CoreIntegration.objects.get(code="digitalocean")
                    connection.name = do_tokens["info"]["name"]
                    connection.account = account
                    connection.location = connection.integration.locations.all().order_by("?")[0]
                    connection.save()
                    auth = CoreAuthDigitalOcean(connection=connection)

                auth.access_token = bs_encrypt(do_tokens["access_token"], encryption_key)
                auth.refresh_token = bs_encrypt(do_tokens["refresh_token"], encryption_key)
                auth.expiry = datetime.fromtimestamp((int(time.time()) + int(do_tokens["expires_in"])))
                auth.scope = do_tokens["scope"]
                auth.token_type = do_tokens["bearer"]
                auth.info_name = do_tokens["info"]["name"]
                auth.info_email = do_tokens["info"]["email"]
                auth.info_uuid = do_tokens["info"]["uuid"]
                auth.save()

                # set connection status to active
                auth.connection.status = CoreConnection.Status.ACTIVE
                auth.connection.save()

                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "Your account is successfully connected. You can add schedules for this server.",
                )

                result.close()
                return redirect("console:setup:integration_open", integration_code="digitalocean")
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to connect account. Please contact support.",
                )
                return redirect("console:setup:integration_open", integration_code="digitalocean")


class APICallbackOVHCA(APIView):
    def get(self, request):
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()

        ovh_consumer_key_sig = f"ovh_ca__consumer_key__{account.id}__{member.id}"
        ovh_consumer_key = cache.get(ovh_consumer_key_sig)

        # create a client
        client = ovh.Client(
            endpoint="ovh-ca",
            application_key=settings.OVH_CA_APP_KEY,
            application_secret=settings.OVH_CA_APP_SECRET,
            consumer_key=ovh_consumer_key,
        )

        ovh_account = client.get("/me")

        """
        Update existing authentication
        """
        info_name = f"{ovh_account.get('firstname', None)} {ovh_account.get('name', None)}"

        if CoreAuthOVHCA.objects.filter(
            connection__account=account, info_customer_code=ovh_account["customerCode"]
        ).exists():
            auth = CoreAuthOVHCA.objects.get(
                connection__account=account,
                info_customer_code=ovh_account["customerCode"],
            )
            auth.info_name = info_name
            auth.info_customer_code = ovh_account.get("info_customer_code")
            auth.info_email = ovh_account.get("email")
            auth.info_organization = ovh_account.get("organization", "n/a")
            auth.consumer_key = bs_encrypt(ovh_consumer_key, encryption_key)
            auth.save()
            auth.connection.status = CoreConnection.Status.ACTIVE
            auth.save()
        else:
            connection = CoreConnection(account=account)
            connection.integration = CoreIntegration.objects.get(code="ovh_ca")
            connection.name = connection.integration.name
            connection.location = connection.integration.locations.all().order_by("?")[0]
            connection.save()

            auth = CoreAuthOVHCA(connection=connection)
            auth.info_name = info_name
            auth.info_email = ovh_account.get("email", None)
            auth.info_organization = ovh_account.get("organization", "n/a")
            auth.info_customer_code = ovh_account.get("customerCode", None)
            auth.consumer_key = bs_encrypt(ovh_consumer_key, encryption_key)
            auth.save()

        messages.add_message(
            request,
            messages.SUCCESS,
            "Your account is successfully connected. You can add schedules for this server.",
        )
        return redirect("console:setup:integration_open", integration_code="ovh_ca")


class APICallbackOVHUS(APIView):
    def get(self, request):
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()

        ovh_consumer_key_sig = f"ovh_us__consumer_key__{account.id}__{member.id}"
        ovh_consumer_key = cache.get(ovh_consumer_key_sig)

        # create a client
        client = ovh.Client(
            endpoint="ovh-us",
            application_key=settings.OVH_US_APP_KEY,
            application_secret=settings.OVH_US_APP_SECRET,
            consumer_key=ovh_consumer_key,
        )

        ovh_account = client.get("/me")

        """
        Update existing authentication
        """
        info_name = f"{ovh_account.get('firstname', None)} {ovh_account.get('name', None)}"

        if CoreAuthOVHUS.objects.filter(
            connection__account=account, info_customer_code=ovh_account["customerCode"]
        ).exists():
            auth = CoreAuthOVHUS.objects.get(
                connection__account=account,
                info_customer_code=ovh_account["customerCode"],
            )
            auth.info_name = info_name
            auth.info_customer_code = ovh_account.get("info_customer_code")
            auth.info_email = ovh_account.get("email")
            auth.info_organization = ovh_account.get("organization", "n/a")
            auth.consumer_key = bs_encrypt(ovh_consumer_key, encryption_key)
            auth.save()
            auth.connection.status = CoreConnection.Status.ACTIVE
            auth.save()
        else:
            connection = CoreConnection(account=account)
            connection.integration = CoreIntegration.objects.get(code="ovh_us")
            connection.name = connection.integration.name
            connection.location = connection.integration.locations.all().order_by("?")[0]
            connection.save()

            auth = CoreAuthOVHUS(connection=connection)
            auth.info_name = info_name
            auth.info_email = ovh_account.get("email", None)
            auth.info_organization = ovh_account.get("organization", "n/a")
            auth.info_customer_code = ovh_account.get("customerCode", None)
            auth.consumer_key = bs_encrypt(ovh_consumer_key, encryption_key)
            auth.save()

        messages.add_message(
            request,
            messages.SUCCESS,
            "Your account is successfully connected. You can add schedules for this server.",
        )
        return redirect("console:setup:integration_open", integration_code="ovh_us")


class APICallbackOVHEU(APIView):
    def get(self, request):
        member = self.request.user.member
        account = member.get_current_account()
        encryption_key = account.get_encryption_key()

        ovh_consumer_key_sig = f"ovh_eu__consumer_key__{account.id}__{member.id}"
        ovh_consumer_key = cache.get(ovh_consumer_key_sig)

        # create a client
        client = ovh.Client(
            endpoint="ovh-eu",
            application_key=settings.OVH_EU_APP_KEY,
            application_secret=settings.OVH_EU_APP_SECRET,
            consumer_key=ovh_consumer_key,
        )

        ovh_account = client.get("/me")

        """
        Update existing authentication
        """
        info_name = f"{ovh_account.get('firstname', None)} {ovh_account.get('name', None)}"

        if CoreAuthOVHEU.objects.filter(
            connection__account=account, info_customer_code=ovh_account["customerCode"]
        ).exists():
            auth = CoreAuthOVHEU.objects.get(
                connection__account=account,
                info_customer_code=ovh_account["customerCode"],
            )
            auth.info_name = info_name
            auth.info_customer_code = ovh_account.get("info_customer_code")
            auth.info_email = ovh_account.get("email")
            auth.info_organization = ovh_account.get("organization", "n/a")
            auth.consumer_key = bs_encrypt(ovh_consumer_key, encryption_key)
            auth.save()
            auth.connection.status = CoreConnection.Status.ACTIVE
            auth.save()
        else:
            connection = CoreConnection(account=account)
            connection.integration = CoreIntegration.objects.get(code="ovh_eu")
            connection.name = connection.integration.name
            connection.location = connection.integration.locations.all().order_by("?")[0]
            connection.save()

            auth = CoreAuthOVHEU(connection=connection)
            auth.info_name = info_name
            auth.info_email = ovh_account.get("email", None)
            auth.info_organization = ovh_account.get("organization", "n/a")
            auth.info_customer_code = ovh_account.get("customerCode", None)
            auth.consumer_key = bs_encrypt(ovh_consumer_key, encryption_key)
            auth.save()

        messages.add_message(
            request,
            messages.SUCCESS,
            "Your account is successfully connected. You can add schedules for this server.",
        )
        return redirect("console:setup:integration_open", integration_code="ovh_eu")


class APICallbackPaypal(APIView):
    authentication_classes = (CsrfExemptSessionAuthentication,)
    permission_classes = ()
    parser_classes = (FormParser,)

    def post(self, request):

        try:

            params = self.request.data.copy()

            if params.get("custom", None):
                f = Fernet(settings.PAYPAL_ENCRYPTION_KEY)

                decrypted_username = f.decrypt(params.get("custom", None).encode())

                decrypted_username = decrypted_username.decode("utf-8")

                member = CoreMember.objects.get(user__username=decrypted_username)

                if CoreMember.objects.filter(user__username=decrypted_username).exists():

                    if (
                        params.get("txn_type", None) == "web_accept"
                        and params.get("payment_type", None) == "instant"
                        and params.get("payment_status", None) == "Completed"
                        and CorePayPalCredit.objects.filter(txn_id=params.get("txn_id", None), is_applied=True).exists()
                        is False
                    ):

                        VERIFY_URL_PROD = "https://www.paypal.com/cgi-bin/webscr"

                        # VERIFY_URL_TEST = 'https://www.sandbox.paypal.com/cgi-bin/webscr'

                        # Switch as appropriate
                        VERIFY_URL = VERIFY_URL_PROD

                        params["cmd"] = "_notify-validate"

                        # Post back to PayPal for validation
                        headers = {
                            "User-Agent": "BackupSheep-IPN-VerificationScript",
                            "content-type": "application/x-www-form-urlencoded",
                            "host": "www.paypal.com",
                        }

                        r = requests.post(VERIFY_URL, params=params, headers=headers, verify=True)

                        r.raise_for_status()

                        # Check return message and take action as needed
                        if r.text == "VERIFIED":
                            paypal_credit = CorePayPalCredit()
                            paypal_credit.txn_id = params["txn_id"]
                            paypal_credit.data = params
                            paypal_credit.billing = member.account.billing
                            paypal_credit.save()
                            stripe_customer = stripe.Customer.retrieve(member.account.billing.stripe_customer_id)
                            tax = params.get("tax", 0)
                            amount = params.get("mc_gross", 0)
                            credit = float(amount) - float(tax)
                            # account_balance = stripe_customer.account_balance
                            stripe_customer.balance = stripe_customer.balance - int(round(credit * 100))
                            stripe_customer.save()
                            paypal_credit.is_applied = True
                            paypal_credit.save()

                        elif r.text == "INVALID":
                            raise response_paypal_payment_unable_to_verify()
                        else:
                            raise response_paypal_payment_unable_to_verify()
                        r.close()
                    else:
                        raise response_paypal_payment_checks_failed()
                else:
                    raise response_paypal_credit_member_not_found()
            else:
                pass

        except Exception as e:
            capture_exception(e)
            if hasattr(e, "detail"):
                response = e.detail
            else:
                response = dict()
                response["message"] = (
                    "API Error: " + str(e.args[0]) if hasattr(e, "args") else "API call failed. Please contact support."
                )
                response["status"] = "error"
            raise ExceptionDefault(detail=response)
        content = {
            "response": "ok",
        }

        return Response(content)


class APICallbackDropbox(APIView):
    def get(self, request):
        try:
            member = self.request.user.member
            account = member.get_current_account()
            encryption_key = account.get_encryption_key()

            dropbox_url = "https://api.dropboxapi.com/oauth2/token"

            params = dict()

            params["code"] = self.request.query_params.get("code", None)
            params["grant_type"] = "authorization_code"
            params["client_id"] = settings.DROPBOX_APP_KEY
            params["client_secret"] = settings.DROPBOX_APP_SECRET
            params["redirect_uri"] = f"{settings.APP_URL}/api/v1/callback/dropbox"

            r = requests.post(dropbox_url, params=params)

            if r.status_code == 200:
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
    def get(self, request):

        try:
            member = self.request.user.member
            account = member.get_current_account()
            encryption_key = account.get_encryption_key()
            code = self.request.query_params.get("code", None)

            scope = ["https://www.googleapis.com/auth/drive.file"]
            oauth = OAuth2Session(
                settings.GOOGLE_CLIENT_ID,
                redirect_uri=f"{settings.APP_URL}/api/v1/callback/google_drive/",
                scope=scope,
            )
            response = oauth.fetch_token(
                "https://accounts.google.com/o/oauth2/token",
                code=code,
                authorization_response=f"{settings.APP_URL}{self.request.get_full_path()}",
                client_secret=settings.GOOGLE_CLIENT_SECRET,
            )

            if response:
                is_new = True
                storage = CoreStorage()
                storage_google_drive = CoreStorageGoogleDrive()
                credentials = google.oauth2.credentials.Credentials(
                    response["access_token"],
                    token_uri="https://accounts.google.com/o/oauth2/token",
                    client_id=settings.GOOGLE_CLIENT_ID,
                    client_secret=settings.GOOGLE_CLIENT_SECRET,
                    refresh_token=response["refresh_token"],
                )
                # authed_http = AuthorizedHttp(credentials)
                service = discovery.build("drive", "v3", credentials=credentials)

                about = service.about().get(fields="appInstalled,user").execute()

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
                storage_google_drive.expiry = credentials.expiry
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


# Todo: Need to delete this because we are using service accounts.
class APICallbackGoogleStorage(APIView):
    def get(self, request):

        try:
            member = self.request.user.member
            account = member.get_current_account()
            encryption_key = account.get_encryption_key()

            credentials = request.session["google_cloud_flow"].step2_exchange(self.request.query_params.get("code"))

            if credentials.access_token:
                is_new = True
                storage = CoreStorage()
                storage_google_cloud = CoreStorageGoogleCloud()
                http = credentials.authorize(httplib2.Http())
                service = discovery.build("storage", "v1", http=http)

                # service.buckets().insert(body={'name': 'yolo1'}, project='bilal414').execute()

                about = service.about().get(fields="appInstalled,user").execute()

                if CoreStorageGoogleCloud.objects.filter(
                    storage__account=account,
                    email_address=about["user"]["emailAddress"],
                ).exists():
                    storage_google_cloud = CoreStorageGoogleCloud.objects.get(
                        storage__account=account,
                        email_address=about["user"]["emailAddress"],
                    )

                    storage = storage_google_cloud.storage
                    is_new = False

                storage.account = account

                if is_new:
                    storage.status = CoreStorage.Status.ACTIVE
                    storage.type = CoreStorageType.objects.get(code="google_cloud_storage")
                storage.name = about["user"]["displayName"] + " -  " + about["user"]["emailAddress"]

                storage.save()

                storage_google_cloud.storage = storage
                storage_google_cloud.access_token = bs_encrypt(credentials.access_token, encryption_key)
                storage_google_cloud.refresh_token = bs_encrypt(credentials.refresh_token, encryption_key)
                storage_google_cloud.email_address = about["user"]["emailAddress"]
                storage_google_cloud.save()

                messages.add_message(request, messages.SUCCESS, "Your storage is successfully connected.")

                return redirect("console:storage:google_storage")
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Unable to connect Google Cloud storage. Check if the domain administrators "
                    "have disabled Google Cloud on your account.",
                )

                return redirect("console:storage:google_storage")

        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect Google Cloud storage. Check if the domain administrators "
                "have disabled Google Cloud on your account.",
            )

            return redirect("console:storage:google_storage")


# Todo: Need to delete this because we are using service accounts.
class APIGoogleCloud(APIView):
    def get(self, request):

        try:
            data = self.request.query_params
            error = data.get("error", None)
            error_description = data.get("error_description", None)
            member = self.request.user.member
            account = member.get_current_account()
            encryption_key = account.get_encryption_key()

            if error:
                messages.add_message(request, messages.ERROR, error_description)
                return redirect("console:setup:integration_open", integration_code="google_cloud")
            else:
                code = data.get("code", None)

                params = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": f"{settings.APP_URL + settings.GOOGLE_REDIRECT_URL}",
                }

                token_request = requests.post(settings.GOOGLE_OAUTH_TOKEN_URL, data=params)

                if token_request.status_code == 200:
                    token_data = token_request.json()

                    url = f"https://openidconnect.googleapis.com/v1/userinfo"

                    headers = {
                        "Authorization": f"{token_data['token_type']} {token_data['access_token']}",
                        "content-type": f"application/json"
                    }

                    profile_request = requests.get(url, headers=headers)

                    if profile_request.status_code == 200:
                        profile_data = profile_request.json()

                        # Check if already exists or not.
                        if CoreAuthGoogleCloud.objects.filter(
                                connection__account=account,
                                sub=profile_data["sub"]
                        ).exists():
                            google_cloud = CoreAuthGoogleCloud.objects.get(
                                connection__account=account,
                                sub=profile_data["sub"])
                            connection = google_cloud.connection
                        else:
                            connection = CoreConnection()
                            connection.name = f"{profile_data.get('name')} - {profile_data.get('email')}"
                            connection.account = account
                            connection.integration = CoreIntegration.objects.get(code="google_cloud")
                            connection.location = CoreConnectionLocation.objects.filter(
                                integrations__code="google_cloud"
                            ).first()
                            connection.added_by = member
                            connection.save()

                            google_cloud = CoreAuthGoogleCloud()
                            google_cloud.connection = connection
                            google_cloud.sub = profile_data["sub"]

                        # Update this on every connect
                        connection.status = CoreConnection.Status.ACTIVE
                        connection.save()
                        google_cloud.access_token = bs_encrypt(token_data['access_token'], encryption_key)
                        google_cloud.refresh_token = bs_encrypt(token_data['refresh_token'], encryption_key)
                        google_cloud.scope = token_data['scope']
                        google_cloud.token_type = token_data['token_type']
                        google_cloud.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
                        google_cloud.metadata = profile_data
                        google_cloud.save()
                        messages.add_message(request, messages.SUCCESS, "Your integration is successfully connected.")

                    return redirect("console:setup:integration_open", integration_code="google_cloud")
                else:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        "Unable to connect Google Cloud. Check if the domain administrators "
                        "have disabled Google Cloud on your account.",
                    )

                    return redirect("console:setup:integration_open", integration_code="google_cloud")
        except Exception as e:
            capture_exception(e)
            messages.add_message(
                request,
                messages.ERROR,
                "Unable to connect Google Cloud storage. Check if the domain administrators "
                "have disabled Google Cloud on your account.",
            )

            return redirect("console:setup:integration_open", integration_code="google_cloud")
