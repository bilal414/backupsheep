import inspect
from unittest import mock

from django.test import override_settings

from apps.api.v1.callback.views import APICallbackGoogleDrive
from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.connection.models import _BoundedGoogleAuthorizedSession
from apps.console.storage.models import CoreStorageGoogleDrive
from apps.tests import factories
from apps.tests.base import BaseTestCase


class GoogleDriveStorageTimeoutTests(BaseTestCase):
    def _storage(self):
        storage = factories.make_storage(
            self.account,
            self.member,
            code="google_drive",
        )
        encryption_key = self.account.get_encryption_key()
        return CoreStorageGoogleDrive.objects.create(
            storage=storage,
            access_token=bs_encrypt("access-token", encryption_key),
            refresh_token=bs_encrypt("refresh-token", encryption_key),
            email_address="drive@example.invalid",
        )

    @override_settings(
        GOOGLE_CLIENT_ID="client-id",
        GOOGLE_CLIENT_SECRET="client-secret",
        PROVIDER_HTTP_CONNECT_TIMEOUT=3,
        PROVIDER_HTTP_READ_TIMEOUT=17,
    )
    def test_drive_storage_uses_bounded_refresh_capable_session(self):
        client = self._storage().get_client()

        self.assertIsInstance(client, _BoundedGoogleAuthorizedSession)
        self.assertEqual(client.credentials.refresh_token, "refresh-token")
        self.assertEqual(
            client.credentials.token_uri,
            "https://oauth2.googleapis.com/token",
        )
        with mock.patch("requests.sessions.Session.request") as request:
            request.return_value = mock.Mock(status_code=200)
            client.get("https://provider.example.invalid/drive")
        self.assertEqual(request.call_args.kwargs["timeout"], (3.0, 17.0))
        self.assertEqual(client.adapters["https://"].max_retries.total, 0)

    @override_settings(
        GOOGLE_CLIENT_ID="client-id",
        GOOGLE_CLIENT_SECRET="client-secret",
        PROVIDER_HTTP_CONNECT_TIMEOUT=4,
        PROVIDER_HTTP_READ_TIMEOUT=19,
    )
    @mock.patch("google.oauth2.credentials.Credentials.refresh")
    @mock.patch("google.auth.transport.requests.Request")
    def test_explicit_token_refresh_uses_bounded_request(
        self, request_class, refresh
    ):
        storage = self._storage()
        storage.get_refresh_token()

        bounded_request = refresh.call_args.args[0]
        bounded_request(
            url="https://oauth2.googleapis.com/token",
            method="POST",
            headers={},
            body=b"",
        )
        request_class.return_value.assert_called_once_with(
            url="https://oauth2.googleapis.com/token",
            method="POST",
            headers={},
            body=b"",
            timeout=(4.0, 19.0),
        )

    def test_oauth_callback_has_bounded_token_and_about_requests(self):
        source = inspect.getsource(APICallbackGoogleDrive.get)

        self.assertIn("timeout=request_timeout()", source)
        self.assertIn("_BoundedGoogleAuthorizedSession(credentials)", source)
        self.assertNotIn("discovery.build", source)
