"""Focused offline tests for provider account identity pinning."""

from types import SimpleNamespace
from unittest import mock

import requests as raw_requests
from django.test import SimpleTestCase
from rest_framework.exceptions import APIException
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.connection.digitalocean.client import DigitalOceanAPIError
from apps.api.v1.connection.digitalocean.serializers import (
    CoreAuthDigitalOceanWriteSerializer,
)
from apps.api.v1.connection.digitalocean.views import CoreDigitalOceanView
from apps.api.v1.connection.upcloud.views import CoreUpCloudView
from apps.api.v1.connection.upcloud.serializers import CoreAuthUpCloudWriteSerializer
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.api.v1.utils.http import request_timeout
from apps._tasks.integration.oracle import OracleProviderError
from apps.console.backup.models import (
    CoreCloudRestore,
    CoreDigitalOceanBackup,
    CoreUpCloudBackup,
)
from apps.console.connection.models import (
    CoreAuthDigitalOcean,
    CoreAuthOracle,
    CoreAuthUpCloud,
)
from apps.console.node.models import (
    CoreDigitalOcean,
    CoreNode,
    CoreUpCloud,
    _backup_scope_fingerprint,
    _BackupProviderError,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.payload = payload if payload is not None else {}
        self.headers = {}
        self.closed = False

    def json(self):
        return self.payload

    def close(self):
        self.closed = True


def digitalocean_account(
    team_uuid="team-1",
    *,
    status="active",
    name="Personal",
    email="owner@example.com",
):
    return {
        "account": {
            "status": status,
            "uuid": "account-1",
            "name": "Owner",
            "email": email,
            "team": {"uuid": team_uuid, "name": name},
        }
    }


class ProviderAccountIdentityPinningTests(BaseTestCase):
    def _digitalocean_auth(self, *, info_uuid=None, info_name="Before"):
        connection = factories.make_connection(
            self.account, self.member, code="digitalocean", name="DO pinning"
        )
        return CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=bs_encrypt("do-token-secret", self.account.get_encryption_key()),
            info_uuid=info_uuid,
            info_name=info_name,
            info_email="before@example.com",
        )

    def _upcloud_auth(self, *, username="upcloud-account", token=True):
        connection = factories.make_connection(
            self.account, self.member, code="upcloud", name="UpCloud pinning"
        )
        key = self.account.get_encryption_key()
        return CoreAuthUpCloud.objects.create(
            connection=connection,
            username=bs_encrypt(username, key) if username is not None else None,
            password=bs_encrypt("basic-password", key) if not token else None,
            api_token=bs_encrypt("upcloud-token-secret", key) if token else None,
        )

    def _oracle_auth(self, *, tenancy="ocid1.tenancy.test.pinned"):
        connection = factories.make_connection(
            self.account, self.member, code="oracle", name="Oracle pinning"
        )
        return CoreAuthOracle.objects.create(
            connection=connection,
            user="ocid1.user.test.pinned",
            fingerprint="aa:bb:cc",
            tenancy=tenancy,
            region="us-test-1",
            private_key=bs_encrypt(
                "offline-private-key", self.account.get_encryption_key()
            ),
            profile="DEFAULT",
        )

    def test_oracle_verified_client_reads_back_pinned_tenancy(self):
        auth = self._oracle_auth()
        config = {
            "user": auth.user,
            "tenancy": auth.tenancy,
            "region": auth.region,
        }
        auth.get_client = mock.Mock(return_value=config)
        response = SimpleNamespace(
            status=200,
            data=SimpleNamespace(id=auth.tenancy, lifecycle_state="ACTIVE"),
            headers={},
        )
        with mock.patch("oci.identity.IdentityClient") as constructor:
            constructor.return_value.get_tenancy.return_value = response
            verified = auth.get_verified_client()

        self.assertEqual(verified, config)
        auth.get_client.assert_called_once_with(data=None)
        constructor.return_value.get_tenancy.assert_called_once_with(auth.tenancy)

    def test_oracle_tenancy_drift_is_rejected_without_provider_details(self):
        auth = self._oracle_auth()
        auth.get_client = mock.Mock(
            return_value={
                "user": auth.user,
                "tenancy": auth.tenancy,
                "region": auth.region,
            }
        )
        response = SimpleNamespace(
            status=200,
            data=SimpleNamespace(
                id="ocid1.tenancy.test.other", lifecycle_state="ACTIVE"
            ),
            headers={},
        )
        with mock.patch("oci.identity.IdentityClient") as constructor:
            constructor.return_value.get_tenancy.return_value = response
            with self.assertRaises(OracleProviderError) as raised:
                auth.get_verified_client()

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertNotIn("ocid1.tenancy.test.other", str(raised.exception))
        constructor.return_value.get_tenancy.assert_called_once_with(auth.tenancy)

    def test_digitalocean_get_client_is_local_only(self):
        auth = self._digitalocean_auth(info_uuid="team-1")
        with mock.patch(
            "apps.api.v1.connection.digitalocean.client.requests.request"
        ) as request:
            client = auth.get_client()

        request.assert_not_called()
        self.assertEqual(client["Authorization"], "Bearer do-token-secret")

    def test_digitalocean_initial_serializer_pins_valid_team_uuid(self):
        response = Response(payload=digitalocean_account(team_uuid="team-new"))
        serializer = CoreAuthDigitalOceanWriteSerializer(
            data={"api_key": "replacement-token"},
            context={"encryption_key": self.account.get_encryption_key()},
        )
        with mock.patch(
            "apps.api.v1.connection.digitalocean.serializers.requests.get",
            return_value=response,
        ) as get:
            self.assertTrue(serializer.is_valid(), serializer.errors)

        self.assertEqual(serializer.validated_data["info_uuid"], "team-new")
        self.assertEqual(
            bs_decrypt(
                serializer.validated_data["api_key"],
                self.account.get_encryption_key(),
            ),
            "replacement-token",
        )
        self.assertEqual(get.call_args.kwargs["timeout"], request_timeout())
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertTrue(response.closed)

    def test_digitalocean_verified_client_exact_match_refreshes_metadata(self):
        auth = self._digitalocean_auth(info_uuid="team-1")
        response = Response(payload=digitalocean_account(team_uuid="team-1", name="Renamed"))
        with mock.patch(
            "apps.api.v1.connection.digitalocean.client.requests.request",
            return_value=response,
        ) as request:
            client = auth.get_verified_client()

        self.assertEqual(client["Authorization"], "Bearer do-token-secret")
        self.assertEqual(request.call_args.kwargs["timeout"], request_timeout())
        self.assertTrue(response.closed)
        auth.refresh_from_db()
        self.assertEqual(auth.info_uuid, "team-1")
        self.assertEqual(auth.info_name, "Renamed")
        self.assertEqual(auth.info_email, "owner@example.com")

    def test_digitalocean_drift_is_rejected_without_overwriting_pin(self):
        auth = self._digitalocean_auth(info_uuid="team-old", info_name="Pinned")
        response = Response(payload=digitalocean_account(team_uuid="team-new", name="Drift"))
        with mock.patch(
            "apps.api.v1.connection.digitalocean.client.requests.request",
            return_value=response,
        ):
            with self.assertRaises(DigitalOceanAPIError) as raised:
                auth.get_verified_client()

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertNotIn("team-new", str(raised.exception))
        self.assertNotIn("do-token-secret", str(raised.exception))
        self.assertTrue(response.closed)
        auth.refresh_from_db()
        self.assertEqual(auth.info_uuid, "team-old")
        self.assertEqual(auth.info_name, "Pinned")

    def test_digitalocean_legacy_empty_pin_is_adopted_once(self):
        auth = self._digitalocean_auth(info_uuid=None)
        response = Response(payload=digitalocean_account(team_uuid="team-adopt"))
        with mock.patch(
            "apps.api.v1.connection.digitalocean.client.requests.request",
            return_value=response,
        ):
            auth.get_verified_client()

        auth.refresh_from_db()
        self.assertEqual(auth.info_uuid, "team-adopt")

    def test_digitalocean_http_and_payload_failures_are_typed_and_secret_free(self):
        cases = (
            (Response(status_code=401), "PROVIDER_AUTH_FAILED"),
            (Response(status_code=429), "PROVIDER_RATE_LIMIT"),
            (Response(status_code=503), "PROVIDER_TRANSIENT_OUTAGE"),
            (Response(payload={"account": {"status": "active"}}), "PROVIDER_MALFORMED_RESPONSE"),
            (Response(payload=digitalocean_account(status="suspended")), "PROVIDER_AUTH_FAILED"),
        )
        for response, code in cases:
            with self.subTest(code=code):
                auth = self._digitalocean_auth(info_uuid="team-1")
                with mock.patch(
                    "apps.api.v1.connection.digitalocean.client.requests.request",
                    return_value=response,
                ):
                    with self.assertRaises(DigitalOceanAPIError) as raised:
                        auth.get_verified_client()
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn("do-token-secret", str(raised.exception))
                self.assertTrue(response.closed)

    def test_digitalocean_serializer_credential_replacement_sets_new_witness(self):
        auth = self._digitalocean_auth(info_uuid="team-old")
        response = Response(payload=digitalocean_account(team_uuid="team-new"))
        serializer = CoreAuthDigitalOceanWriteSerializer(
            auth,
            data={"api_key": "new-token"},
            context={"encryption_key": self.account.get_encryption_key()},
        )
        with mock.patch(
            "apps.api.v1.connection.digitalocean.serializers.requests.get",
            return_value=response,
        ):
            self.assertTrue(serializer.is_valid(), serializer.errors)

        self.assertEqual(serializer.validated_data["info_uuid"], "team-new")
        self.assertNotIn("new-token", repr(serializer.errors))
        self.assertNotIn("new-token", repr(serializer.data))

    def test_upcloud_token_serializer_pins_provider_username_and_keeps_token_write_only(self):
        response = Response(payload={"account": {"username": "upcloud-new"}})
        serializer = CoreAuthUpCloudWriteSerializer(
            data={"api_token": "upcloud-token-secret"},
            context={"encryption_key": self.account.get_encryption_key()},
        )
        with mock.patch(
            "apps.api.v1.connection.upcloud.serializers.requests.get",
            return_value=response,
        ) as get:
            self.assertTrue(serializer.is_valid(), serializer.errors)

        key = self.account.get_encryption_key()
        self.assertEqual(bs_decrypt(serializer.validated_data["username"], key), "upcloud-new")
        self.assertEqual(bs_decrypt(serializer.validated_data["api_token"], key), "upcloud-token-secret")
        self.assertIsNone(serializer.validated_data["password"])
        self.assertNotIn("api_token", serializer.data)
        self.assertNotIn("upcloud-token-secret", repr(serializer.data))
        self.assertEqual(get.call_args.kwargs["timeout"], request_timeout())
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertTrue(response.closed)

    def test_upcloud_verified_client_exact_match_uses_token_and_timeout(self):
        auth = self._upcloud_auth(username="upcloud-account")
        response = Response(payload={"account": {"username": "upcloud-account"}})
        with mock.patch(
            "apps.console.connection.models.requests.get", return_value=response
        ) as get:
            client = auth.get_verified_client()

        self.assertIn("UpCloudBearerAuth", repr(client))
        self.assertNotIn("upcloud-token-secret", repr(client))
        self.assertEqual(get.call_args.kwargs["timeout"], request_timeout())
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertTrue(response.closed)

    def test_upcloud_drift_is_rejected_without_overwriting_pinned_username(self):
        auth = self._upcloud_auth(username="upcloud-old")
        response = Response(payload={"account": {"username": "upcloud-new"}})
        with mock.patch(
            "apps.console.connection.models.requests.get", return_value=response
        ):
            with self.assertRaises(_BackupProviderError) as raised:
                auth.get_verified_client()

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertNotIn("upcloud-new", str(raised.exception))
        self.assertNotIn("upcloud-token-secret", str(raised.exception))
        self.assertTrue(response.closed)
        auth.refresh_from_db()
        self.assertEqual(
            bs_decrypt(auth.username, self.account.get_encryption_key()),
            "upcloud-old",
        )

    def test_upcloud_legacy_token_row_adopts_username_once(self):
        auth = self._upcloud_auth(username=None)
        response = Response(payload={"account": {"username": "upcloud-adopt"}})
        with mock.patch(
            "apps.console.connection.models.requests.get", return_value=response
        ):
            auth.get_verified_client()

        auth.refresh_from_db()
        self.assertEqual(
            bs_decrypt(auth.username, self.account.get_encryption_key()),
            "upcloud-adopt",
        )

    def test_upcloud_basic_auth_compatibility_remains_local_and_verified(self):
        auth = self._upcloud_auth(username="upcloud-basic", token=False)
        client = auth.get_client()
        self.assertEqual(client.username, "upcloud-basic")
        self.assertEqual(client.password, "basic-password")
        response = Response(payload={"account": {"username": "upcloud-basic"}})
        with mock.patch(
            "apps.console.connection.models.requests.get", return_value=response
        ):
            verified = auth.get_verified_client()
        self.assertEqual(verified.username, "upcloud-basic")

    def test_upcloud_http_payload_timeout_and_provider_errors_are_safe(self):
        cases = (
            (Response(status_code=401), "PROVIDER_AUTH_FAILED"),
            (Response(status_code=429), "PROVIDER_RATE_LIMIT"),
            (Response(status_code=503), "PROVIDER_TRANSIENT_OUTAGE"),
            (Response(payload={"account": {}}), "PROVIDER_MALFORMED_RESPONSE"),
        )
        for response, code in cases:
            with self.subTest(code=code):
                auth = self._upcloud_auth()
                with mock.patch(
                    "apps.console.connection.models.requests.get", return_value=response
                ):
                    with self.assertRaises(_BackupProviderError) as raised:
                        auth.get_verified_client()
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn("provider-secret-canary", str(raised.exception))
                self.assertTrue(response.closed)

        auth = self._upcloud_auth()
        with mock.patch(
            "apps.console.connection.models.requests.get",
            side_effect=raw_requests.Timeout("provider-secret-canary"),
        ):
            with self.assertRaises(_BackupProviderError) as raised:
                auth.get_verified_client()
        self.assertEqual(raised.exception.code, "PROVIDER_TIMEOUT")
        self.assertNotIn("provider-secret-canary", str(raised.exception))

    def test_upcloud_token_replacement_updates_witness_only_after_validation(self):
        auth = self._upcloud_auth(username="upcloud-old")
        response = Response(payload={"account": {"username": "upcloud-new"}})
        serializer = CoreAuthUpCloudWriteSerializer(
            auth,
            data={"api_token": "replacement-token"},
            context={"encryption_key": self.account.get_encryption_key()},
        )
        with mock.patch(
            "apps.api.v1.connection.upcloud.serializers.requests.get",
            return_value=response,
        ):
            self.assertTrue(serializer.is_valid(), serializer.errors)

        key = self.account.get_encryption_key()
        self.assertEqual(bs_decrypt(serializer.validated_data["username"], key), "upcloud-new")
        self.assertIsNotNone(serializer.validated_data["api_token"])
        self.assertNotIn("replacement-token", repr(serializer.data))

    def test_upcloud_serializer_never_returns_provider_exception_text(self):
        response = Response(status_code=500, payload={"error_message": "provider-secret-canary"})
        serializer = CoreAuthUpCloudWriteSerializer(
            data={"api_token": "upcloud-token-secret"},
            context={"encryption_key": self.account.get_encryption_key()},
        )
        with mock.patch(
            "apps.api.v1.connection.upcloud.serializers.requests.get",
            return_value=response,
        ):
            self.assertFalse(serializer.is_valid())
        rendered = repr(serializer.errors)
        self.assertNotIn("provider-secret-canary", rendered)
        self.assertNotIn("upcloud-token-secret", rendered)
        self.assertEqual(serializer.errors["credentials"][0].code, "PROVIDER_TRANSIENT_OUTAGE")


class ProviderAccountIdentityPayloadTests(SimpleTestCase):
    def test_digitalocean_team_shape_is_required_for_a_valid_uuid(self):
        with self.assertRaises(DigitalOceanAPIError) as raised:
            CoreAuthDigitalOcean._account_identity(
                {"account": {"status": "active", "team": "not-an-object"}}
            )
        self.assertEqual(raised.exception.code, "PROVIDER_MALFORMED_RESPONSE")

    def test_upcloud_username_must_be_a_nonempty_single_line_string(self):
        for value in (None, "", "  ", "bad\nusername", 12):
            with self.subTest(value=value):
                with self.assertRaises(_BackupProviderError) as raised:
                    CoreAuthUpCloud._account_username({"account": {"username": value}})
                self.assertEqual(raised.exception.code, "PROVIDER_MALFORMED_RESPONSE")


class ProviderIdentityEnforcementCallSiteTests(BaseTestCase):
    """Every provider boundary must verify account ownership before resource I/O."""

    def _digitalocean_graph(self):
        connection = factories.make_connection(
            self.account, self.member, code="digitalocean", name="DO call-site audit"
        )
        auth = CoreAuthDigitalOcean.objects.create(
            connection=connection,
            api_key=bs_encrypt("do-call-site-token", self.account.get_encryption_key()),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.CLOUD,
            name="do-call-site-source",
            added_by=self.member,
        )
        integration = CoreDigitalOcean.objects.create(
            node=node, name="do-call-site-source", unique_id="do-source"
        )
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=integration,
            uuid="do-call-site-backup",
            unique_id="do-snapshot",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
        )
        return auth, node, integration, backup

    def _upcloud_graph(self):
        connection = factories.make_connection(
            self.account, self.member, code="upcloud", name="UpCloud call-site audit"
        )
        key = self.account.get_encryption_key()
        auth = CoreAuthUpCloud.objects.create(
            connection=connection,
            username=bs_encrypt("upcloud-call-site-user", key),
            password=bs_encrypt("upcloud-call-site-password", key),
        )
        node = CoreNode.objects.create(
            connection=connection,
            type=CoreNode.Type.VOLUME,
            name="upcloud-call-site-source",
            added_by=self.member,
        )
        integration = CoreUpCloud.objects.create(
            node=node,
            name="upcloud-call-site-source",
            unique_id="upcloud-source",
            metadata={"_bs_zone": "us-chi1"},
        )
        scope = {
            "account_id": str(connection.account_id),
            "connection_id": str(connection.id),
            "zone": "us-chi1",
        }
        backup = CoreUpCloudBackup.objects.create(
            upcloud=integration,
            uuid="upcloud-call-site-backup",
            unique_id="upcloud-backup",
            status=UtilBackup.Status.IN_PROGRESS,
            type=UtilBackup.Type.ON_DEMAND,
            attempt_no=1,
            metadata={
                "_bs_provider": "upcloud",
                "_bs_ownership_verified": True,
                "_bs_marker": "upcloud-call-site-backup",
                "_bs_source_id": "upcloud-source",
                "_bs_scope": scope,
                "_bs_scope_fingerprint": _backup_scope_fingerprint(
                    "upcloud", "upcloud-source", "storage", scope
                ),
            },
        )
        return auth, node, integration, backup

    def test_digitalocean_auth_inventory_and_api_discovery_stop_on_drift(self):
        auth, _node, _integration, _backup = self._digitalocean_graph()
        drift = DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")
        with mock.patch.object(CoreAuthDigitalOcean, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.api.v1.connection.digitalocean.client.list_eligible_objects"
        ) as listing:
            with self.assertRaises(APIException):
                auth.get_eligible_objects()
        verifier.assert_called_once()
        listing.assert_not_called()

        request = APIRequestFactory().get("/objects/", {"object_type": "cloud"})
        force_authenticate(request, user=self.user)
        with mock.patch.object(CoreAuthDigitalOcean, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.api.v1.connection.digitalocean.views.list_eligible_objects"
        ) as listing:
            response = CoreDigitalOceanView.as_view({"get": "objects"})(
                request, pk=auth.connection_id
            )
        self.assertGreaterEqual(response.status_code, 400)
        verifier.assert_called_once()
        listing.assert_not_called()

    def test_upcloud_auth_inventory_and_api_discovery_stop_on_drift(self):
        auth, _node, _integration, _backup = self._upcloud_graph()
        drift = _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH")
        with mock.patch.object(CoreAuthUpCloud, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps._tasks.integration.upcloud.list_upcloud_servers"
        ) as listing:
            with self.assertRaises(APIException):
                auth.get_eligible_objects()
        verifier.assert_called_once()
        listing.assert_not_called()

        request = APIRequestFactory().get("/objects/", {"object_type": "cloud"})
        force_authenticate(request, user=self.user)
        with mock.patch.object(CoreAuthUpCloud, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.api.v1.connection.upcloud.views.list_upcloud_servers"
        ) as listing:
            response = CoreUpCloudView.as_view({"get": "objects"})(
                request, pk=auth.connection_id
            )
        self.assertGreaterEqual(response.status_code, 400)
        verifier.assert_called_once()
        listing.assert_not_called()

    def test_digitalocean_poll_mutation_restore_and_delete_stop_on_drift(self):
        auth, node, integration, backup = self._digitalocean_graph()
        drift = DigitalOceanAPIError("PROVIDER_OWNERSHIP_MISMATCH")

        with mock.patch.object(CoreAuthDigitalOcean, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.backup.models.requests.get"
        ) as get, mock.patch("apps.console.backup.models.requests.delete") as delete:
            result = backup.poll_status()
        self.assertEqual(result, UtilBackup.Status.FAILED)
        verifier.assert_called_once()
        get.assert_not_called()
        delete.assert_not_called()

        backup.refresh_from_db()
        backup.status = UtilBackup.Status.IN_PROGRESS
        backup.save(update_fields=["status", "modified"])
        with mock.patch.object(CoreAuthDigitalOcean, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.node.models.requests.get"
        ) as get, mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(Exception):
                integration.create_snapshot(backup)
        verifier.assert_called_once()
        get.assert_not_called()
        post.assert_not_called()

        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="do-drift-restore",
            params={"size": "s-1vcpu-1gb"},
        )
        with mock.patch.object(CoreAuthDigitalOcean, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.node.models.requests.get"
        ) as get, mock.patch("apps.console.node.models.requests.post") as post:
            integration.restore_snapshot(backup, restore)
        verifier.assert_called_once()
        get.assert_not_called()
        post.assert_not_called()

        auth, _node, _integration, backup = self._digitalocean_graph()
        backup.status = UtilBackup.Status.DELETE_REQUESTED
        backup.save(update_fields=["status", "modified"])
        with mock.patch.object(CoreAuthDigitalOcean, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.backup.models.requests.get"
        ) as get, mock.patch("apps.console.backup.models.requests.delete") as delete:
            backup.soft_delete()
        verifier.assert_called_once()
        get.assert_not_called()
        delete.assert_not_called()

    def test_upcloud_poll_mutation_restore_and_delete_stop_on_drift(self):
        auth, node, integration, backup = self._upcloud_graph()
        drift = _BackupProviderError("PROVIDER_OWNERSHIP_MISMATCH")

        with mock.patch.object(CoreAuthUpCloud, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.backup.models.requests.get"
        ) as get, mock.patch("apps.console.backup.models.requests.delete") as delete:
            result = backup.poll_status()
        self.assertEqual(result, UtilBackup.Status.FAILED)
        verifier.assert_called_once()
        get.assert_not_called()
        delete.assert_not_called()

        backup.refresh_from_db()
        backup.status = UtilBackup.Status.IN_PROGRESS
        backup.save(update_fields=["status", "modified"])
        with mock.patch.object(CoreAuthUpCloud, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.node.models.requests.get"
        ) as get, mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(Exception):
                integration.create_snapshot(backup)
        verifier.assert_called_once()
        get.assert_not_called()
        post.assert_not_called()

        backup.status = UtilBackup.Status.COMPLETE
        backup.save(update_fields=["status", "modified"])
        restore = CoreCloudRestore.objects.create(
            node=node,
            backup_id=backup.id,
            name="upcloud-drift-restore",
            params={"zone": "us-chi1"},
        )
        with mock.patch.object(CoreAuthUpCloud, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.node.models.requests.get"
        ) as get, mock.patch("apps.console.node.models.requests.post") as post:
            with self.assertRaises(Exception):
                integration.restore_snapshot(backup, restore)
        verifier.assert_called_once()
        get.assert_not_called()
        post.assert_not_called()

        auth, _node, _integration, backup = self._upcloud_graph()
        backup.status = UtilBackup.Status.DELETE_REQUESTED
        backup.save(update_fields=["status", "modified"])
        with mock.patch.object(CoreAuthUpCloud, "get_verified_client", side_effect=drift) as verifier, mock.patch(
            "apps.console.backup.models.requests.get"
        ) as get, mock.patch("apps.console.backup.models.requests.delete") as delete:
            backup.soft_delete()
        verifier.assert_called_once()
        get.assert_not_called()
        delete.assert_not_called()
