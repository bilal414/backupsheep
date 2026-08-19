import hashlib
import importlib
import os
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from types import SimpleNamespace
from unittest import mock

from botocore.exceptions import ClientError
from django.test import SimpleTestCase, override_settings

from apps._tasks.exceptions import (
    NodeDigitalOceanSpacesBucketDeletedError,
    NodeDigitalOceanSpacesNoSuchBucketError,
    StorageDOSpacesUploadFailedError,
    StorageFilebaseQuotaExceededError,
)
from apps.console.backup.models import CoreWebsiteBackupStoragePoints
from apps.console.node.models import CoreNode


@dataclass(frozen=True)
class AdapterSpec:
    module: str
    function: str
    relation: str
    metadata_key: str
    endpoint: str
    key_uses_node: bool = False
    region_name: str | None = None
    connect_timeout: int = 10
    read_timeout: int = 60
    max_attempts: int = 5
    extra_args: dict | None = None


ADAPTERS = (
    AdapterSpec(
        "do_spaces",
        "storage_do_spaces",
        "storage_do_spaces",
        "do_spaces_s3_object",
        "https://region.example",
    ),
    AdapterSpec(
        "wasabi",
        "storage_wasabi",
        "storage_wasabi",
        "wasabi_s3_object",
        "https://region.example",
    ),
    AdapterSpec(
        "filebase",
        "storage_filebase",
        "storage_filebase",
        "filebase_s3_object",
        "https://s3.filebase.io",
    ),
    AdapterSpec(
        "backblaze_b2",
        "storage_backblaze_b2",
        "storage_backblaze_b2",
        "backblaze_b2_s3_object",
        "https://provider.example",
    ),
    AdapterSpec(
        "linode",
        "storage_linode",
        "storage_linode",
        "linode_s3_object",
        "https://provider.example",
    ),
    AdapterSpec(
        "exoscale",
        "storage_exoscale",
        "storage_exoscale",
        "exoscale_s3_object",
        "https://region.example",
    ),
    AdapterSpec(
        "oracle",
        "storage_oracle",
        "storage_oracle",
        "oracle_s3_object",
        "https://provider.example",
        region_name="region-1",
    ),
    AdapterSpec(
        "scaleway",
        "storage_scaleway",
        "storage_scaleway",
        "scaleway_s3_object",
        "https://provider.example",
        region_name="region-1",
    ),
    AdapterSpec(
        "upcloud",
        "storage_upcloud",
        "storage_upcloud",
        "upcloud_s3_object",
        "https://safe1.upcloudobjects.com",
    ),
    AdapterSpec(
        "cloudflare",
        "storage_cloudflare",
        "storage_cloudflare",
        "cloudflare_r2_s3_object",
        "https://provider.example",
        key_uses_node=True,
        region_name="auto",
    ),
    AdapterSpec(
        "rackcorp",
        "storage_rackcorp",
        "storage_rackcorp",
        "rackcorp_s3_object",
        "https://provider.example",
        key_uses_node=True,
        region_name="region-1",
    ),
    AdapterSpec(
        "ionos",
        "storage_ionos",
        "storage_ionos",
        "ionos_s3_object",
        "https://provider.example",
        key_uses_node=True,
        region_name="region-1",
    ),
    AdapterSpec(
        "idrive",
        "storage_idrive",
        "storage_idrive",
        "idrive_s3_object",
        "https://idrive.example",
        key_uses_node=True,
    ),
    AdapterSpec(
        "leviia",
        "storage_leviia",
        "storage_leviia",
        "leviia_s3_object",
        "https://provider.example",
        key_uses_node=True,
        region_name="auto",
    ),
    AdapterSpec(
        "tencent",
        "storage_tencent",
        "storage_tencent",
        "tencent_cos_s3_object",
        "https://cos.region-1.myqcloud.com",
        key_uses_node=True,
        region_name="region-1",
        extra_args={"StorageClass": "STANDARD"},
    ),
    AdapterSpec(
        "alibaba",
        "storage_alibaba",
        "storage_alibaba",
        "alibaba_oss_s3_object",
        "https://s3.oss-region-1.aliyuncs.com",
        key_uses_node=True,
        region_name="region-1",
    ),
    AdapterSpec(
        "ibm",
        "storage_ibm",
        "storage_ibm",
        "ibm_cos_s3_object",
        "https://provider.example",
        key_uses_node=True,
        region_name="region-1",
    ),
)


def _provider(spec, prefix="backups"):
    endpoint = "provider.example"
    if spec.module == "alibaba":
        endpoint = "oss-region-1.aliyuncs.com"
    elif spec.module == "upcloud":
        endpoint = "safe1.upcloudobjects.com"
    return SimpleNamespace(
        access_key=b"encrypted-access",
        secret_key=b"encrypted-secret",
        bucket_name="test-bucket",
        prefix=prefix,
        endpoint=endpoint,
        endpoint_url="https://idrive.example",
        region=SimpleNamespace(code="region-1", endpoint="region.example"),
    )


def _stored_backup(spec, prefix="backups"):
    provider = _provider(spec, prefix)
    storage = SimpleNamespace(
        account=SimpleNamespace(get_encryption_key=lambda: b"encryption-key")
    )
    setattr(storage, spec.relation, provider)
    backup = SimpleNamespace(
        uuid="backup-uuid",
        uuid_str="backup-uuid",
        attempt_no=1,
        type="on_demand",
        node=SimpleNamespace(name_slug="website-node"),
        record_artifact_integrity=mock.Mock(),
    )
    point = SimpleNamespace(
        backup=backup,
        backup_id=42,
        storage=storage,
        storage_file_id=None,
        metadata={},
        status=None,
        Status=SimpleNamespace(
            UPLOAD_FAILED_FILE_NOT_FOUND="file_not_found",
            UPLOAD_VALIDATION="validating",
            UPLOAD_COMPLETE="complete",
        ),
        save=mock.Mock(),
    )
    return point, provider


def _not_found(operation="HeadObject"):
    return ClientError({"Error": {"Code": "404"}}, operation)


class S3CompatibleStorageAdapterContractTests(SimpleTestCase):
    def test_every_adapter_uses_verified_upload_and_bounded_boto_client(self):
        for spec in ADAPTERS:
            with self.subTest(provider=spec.module):
                module_name = f"apps._tasks.integration.storage.{spec.module}"
                module = importlib.import_module(module_name)
                point, _provider_config = _stored_backup(spec)
                client = mock.Mock(name=f"{spec.module}-client")

                with ExitStack() as stack:
                    boto_client = stack.enter_context(
                        mock.patch(f"{module_name}.boto3.client", return_value=client)
                    )
                    stack.enter_context(
                        mock.patch(
                            f"{module_name}.bs_decrypt",
                            side_effect=lambda value, _key: value.decode(),
                        )
                    )
                    verified_upload = stack.enter_context(
                        mock.patch(f"{module_name}.upload_verified_s3")
                    )
                    getattr(module, spec.function)(point)

                boto_kwargs = boto_client.call_args.kwargs
                self.assertEqual(boto_client.call_args.args, ("s3",))
                self.assertEqual(boto_kwargs["endpoint_url"], spec.endpoint)
                if spec.region_name is not None:
                    self.assertEqual(boto_kwargs["region_name"], spec.region_name)

                config = boto_kwargs["config"]
                self.assertEqual(config.connect_timeout, spec.connect_timeout)
                self.assertEqual(config.read_timeout, spec.read_timeout)
                self.assertEqual(config.retries["max_attempts"], spec.max_attempts)
                self.assertEqual(config.retries["mode"], "standard")
                self.assertEqual(config.request_checksum_calculation, "when_required")
                self.assertEqual(config.response_checksum_validation, "when_required")

                expected_key = "backups/backup-uuid.zip"
                if spec.key_uses_node:
                    expected_key = "backups/website-node/backup-uuid.zip"
                expected_upload = {
                    "client": client,
                    "bucket": "test-bucket",
                    "key": expected_key,
                    "local_path": "_storage/backup-uuid.zip",
                    "metadata_key": spec.metadata_key,
                    "supports_checksum": False,
                }
                if spec.extra_args:
                    expected_upload["extra_args"] = spec.extra_args
                verified_upload.assert_called_once_with(
                    point,
                    **expected_upload,
                )

    def test_compatibility_specific_client_settings_are_preserved(self):
        checks = {
            "cloudflare": {"signature_version": "s3v4"},
            "ionos": {"signature_version": "s3v4"},
            "tencent": {
                "signature_version": "s3v4",
                "addressing_style": "virtual",
            },
            "alibaba": {
                "signature_version": "s3v4",
                "addressing_style": "virtual",
            },
            "ibm": {"signature_version": "s3v4"},
        }
        for spec in (item for item in ADAPTERS if item.module in checks):
            with self.subTest(provider=spec.module):
                module_name = f"apps._tasks.integration.storage.{spec.module}"
                module = importlib.import_module(module_name)
                point, _provider_config = _stored_backup(spec)
                with mock.patch(f"{module_name}.boto3.client") as boto_client, mock.patch(
                    f"{module_name}.bs_decrypt", return_value="secret"
                ), mock.patch(f"{module_name}.upload_verified_s3"):
                    getattr(module, spec.function)(point)

                config = boto_client.call_args.kwargs["config"]
                self.assertEqual(
                    config.signature_version,
                    checks[spec.module]["signature_version"],
                )
                addressing_style = checks[spec.module].get("addressing_style")
                if addressing_style:
                    self.assertEqual(config.s3["addressing_style"], addressing_style)

    def test_missing_local_archive_keeps_file_not_found_semantics(self):
        spec = ADAPTERS[0]
        module_name = "apps._tasks.integration.storage.do_spaces"
        module = importlib.import_module(module_name)
        point, _provider_config = _stored_backup(spec)
        with mock.patch(f"{module_name}.boto3.client"), mock.patch(
            f"{module_name}.bs_decrypt", return_value="secret"
        ), mock.patch(
            f"{module_name}.upload_verified_s3", side_effect=FileNotFoundError
        ):
            module.storage_do_spaces(point)

        self.assertEqual(point.status, "file_not_found")
        point.save.assert_called_once_with(update_fields=["status", "modified"])

    def test_digitalocean_provider_errors_keep_their_specific_types(self):
        spec = ADAPTERS[0]
        module_name = "apps._tasks.integration.storage.do_spaces"
        module = importlib.import_module(module_name)
        cases = (
            ("BucketDeleted", NodeDigitalOceanSpacesBucketDeletedError),
            ("NoSuchBucket", NodeDigitalOceanSpacesNoSuchBucketError),
            ("AccessDenied", StorageDOSpacesUploadFailedError),
        )
        for message, expected_error in cases:
            with self.subTest(message=message):
                point, _provider_config = _stored_backup(spec)
                with mock.patch(f"{module_name}.boto3.client"), mock.patch(
                    f"{module_name}.bs_decrypt", return_value="secret"
                ), mock.patch(
                    f"{module_name}.upload_verified_s3",
                    side_effect=ClientError(
                        {
                            "Error": {
                                "Code": message,
                                "Message": "provider body with secret-canary",
                            },
                            "ResponseMetadata": {
                                "HTTPStatusCode": 404
                                if message != "AccessDenied"
                                else 403
                            },
                        },
                        "PutObject",
                    ),
                ):
                    with self.assertRaises(expected_error):
                        module.storage_do_spaces(point)

    def test_filebase_quota_error_keeps_specific_type(self):
        spec = next(item for item in ADAPTERS if item.module == "filebase")
        module_name = "apps._tasks.integration.storage.filebase"
        module = importlib.import_module(module_name)
        point, _provider_config = _stored_backup(spec)
        with mock.patch(f"{module_name}.boto3.client"), mock.patch(
            f"{module_name}.bs_decrypt", return_value="secret"
        ), mock.patch(
            f"{module_name}.upload_verified_s3",
            side_effect=ClientError(
                {
                    "Error": {
                        "Code": "QuotaExceeded",
                        "Message": "provider body with secret-canary",
                    },
                    "ResponseMetadata": {"HTTPStatusCode": 507},
                },
                "PutObject",
            ),
        ):
            with self.assertRaises(StorageFilebaseQuotaExceededError):
                module.storage_filebase(point)

    def test_legacy_spaces_and_wasabi_delete_paths_are_preserved(self):
        cases = (
            ("do_spaces", "storage_do_spaces_delete", "storage_do_spaces"),
            ("wasabi", "storage_wasabi_delete", "storage_wasabi"),
        )
        for module_suffix, function_name, relation in cases:
            with self.subTest(provider=module_suffix):
                module_name = f"apps._tasks.integration.storage.{module_suffix}"
                module = importlib.import_module(module_name)
                provider = _provider(ADAPTERS[0])
                backup = SimpleNamespace(
                    id=42,
                    storage_byo=SimpleNamespace(**{relation: provider}),
                    storage_file_id="backups/backup-uuid.zip",
                )
                node = SimpleNamespace(
                    type=CoreNode.Type.WEBSITE,
                    connection=SimpleNamespace(
                        account=SimpleNamespace(
                            get_encryption_key=lambda: b"encryption-key"
                        )
                    ),
                )
                client = mock.Mock()
                with mock.patch.object(
                    module.CoreWebsiteBackup.objects, "get", return_value=backup
                ) as lookup, mock.patch.object(
                    module, "_s3_client", return_value=client
                ) as client_factory:
                    client.head_object.return_value = {
                        "VersionId": "version-1",
                        "Metadata": {"backupsheep-backup-id": "42"},
                    }
                    getattr(module, function_name)(node, "backup-uuid")

                lookup.assert_called_once_with(uuid="backup-uuid")
                client_factory.assert_called_once_with(provider, b"encryption-key")
                client.head_object.assert_called_once_with(
                    Bucket="test-bucket",
                    Key="backups/backup-uuid.zip",
                )
                client.delete_object.assert_called_once_with(
                    Bucket="test-bucket",
                    Key="backups/backup-uuid.zip",
                    VersionId="version-1",
                )

    def test_upcloud_backup_delete_reuses_normalized_upload_client_factory(self):
        spec = next(item for item in ADAPTERS if item.module == "upcloud")
        provider = _provider(spec)
        account = SimpleNamespace(
            id=7,
            get_encryption_key=lambda: b"encryption-key",
            create_storage_log=mock.Mock(),
        )
        storage = SimpleNamespace(
            id=11,
            name="UpCloud storage",
            type=SimpleNamespace(id=12, code="upcloud", name="UpCloud"),
            account=account,
            storage_upcloud=provider,
            is_air_gapped=False,
        )
        backup = SimpleNamespace(
            id=42,
            uuid_str="backup-uuid",
            node=SimpleNamespace(name="website-node"),
        )
        client = mock.Mock(name="upcloud-s3-client")
        point = SimpleNamespace(
            id=43,
            backup=backup,
            storage=storage,
            storage_file_id="backups/backup-uuid.zip",
            metadata={},
            Status=CoreWebsiteBackupStoragePoints.Status,
            save=mock.Mock(),
            delete_owned_s3_object=mock.Mock(),
        )

        with mock.patch(
            "apps._tasks.integration.storage.upcloud._s3_client",
            return_value=client,
        ) as factory:
            self.assertTrue(CoreWebsiteBackupStoragePoints.soft_delete(point))

        factory.assert_called_once_with(provider, b"encryption-key")
        point.delete_owned_s3_object.assert_called_once_with(
            client,
            Bucket="test-bucket",
            Key="backups/backup-uuid.zip",
        )


class DigitalOceanSpacesVerifiedUploadTests(SimpleTestCase):
    def setUp(self):
        super().setUp()
        self.spec = ADAPTERS[0]
        self.point, self.provider = _stored_backup(self.spec)
        self.point.backup.uuid = f"t{uuid.uuid4().hex}"
        self.point.backup.uuid_str = self.point.backup.uuid
        self.local_zip = f"_storage/{self.point.backup.uuid}.zip"
        os.makedirs("_storage", exist_ok=True)
        self.addCleanup(
            lambda: os.path.exists(self.local_zip) and os.remove(self.local_zip)
        )

    def _write_payload(self, payload):
        self.payload = payload
        self.sha256 = hashlib.sha256(payload).hexdigest()
        with open(self.local_zip, "wb") as archive:
            archive.write(payload)

    def _verified_head(self):
        return {
            "ContentLength": len(self.payload),
            "ETag": '"provider-etag"',
            "VersionId": "version-1",
            "Metadata": {
                "backupsheep-backup-id": str(self.point.backup_id),
                "backupsheep-sha256": self.sha256,
                "backupsheep-bytes": str(len(self.payload)),
            },
        }

    def _run(self, client):
        module_name = "apps._tasks.integration.storage.do_spaces"
        module = importlib.import_module(module_name)
        with mock.patch(
            f"{module_name}.boto3.client", return_value=client
        ), mock.patch(f"{module_name}.bs_decrypt", return_value="secret"):
            module.storage_do_spaces(self.point)

    def test_success_persists_verified_identity_and_artifact(self):
        self._write_payload(b"verified spaces payload\n")
        client = mock.MagicMock()
        client.head_object.side_effect = [_not_found(), self._verified_head()]

        self._run(client)

        state = self.point.metadata["do_spaces_s3_object"]
        self.assertEqual(state["phase"], "committed")
        self.assertEqual(state["sha256"], self.sha256)
        self.assertEqual(state["size_bytes"], len(self.payload))
        self.assertEqual(state["etag"], '"provider-etag"')
        self.assertEqual(state["version_id"], "version-1")
        self.assertEqual(self.point.status, "complete")
        self.point.backup.record_artifact_integrity.assert_called_once()

    @override_settings(
        S3_MULTIPART_THRESHOLD_BYTES=1,
        S3_MULTIPART_PART_SIZE_BYTES=5 * 1024 * 1024,
    )
    def test_worker_crash_resumes_persisted_multipart_upload(self):
        self._write_payload((b"a" * (5 * 1024 * 1024)) + (b"b" * 1024))
        client = mock.MagicMock()
        client.head_object.side_effect = [
            _not_found(),
            _not_found(),
            self._verified_head(),
        ]
        client.list_multipart_uploads.return_value = {
            "Uploads": [],
            "IsTruncated": False,
        }
        client.create_multipart_upload.return_value = {"UploadId": "upload-1"}
        client.list_parts.side_effect = [
            {"Parts": [], "IsTruncated": False},
            {
                "Parts": [
                    {
                        "PartNumber": 1,
                        "ETag": '"part-1"',
                        "Size": 5 * 1024 * 1024,
                    }
                ],
                "IsTruncated": False,
            },
            {
                "Parts": [
                    {
                        "PartNumber": 1,
                        "ETag": '"part-1"',
                        "Size": 5 * 1024 * 1024,
                    },
                    {
                        "PartNumber": 2,
                        "ETag": '"part-2"',
                        "Size": 1024,
                    },
                ],
                "IsTruncated": False,
            },
        ]
        client.upload_part.side_effect = [
            {"ETag": '"part-1"'},
            ConnectionError("worker crashed"),
            {"ETag": '"part-2"'},
        ]

        with self.assertRaises(StorageDOSpacesUploadFailedError):
            self._run(client)
        state = self.point.metadata["do_spaces_s3_object"]
        self.assertEqual(state["multipart"]["upload_id"], "upload-1")

        self._run(client)

        client.create_multipart_upload.assert_called_once()
        client.complete_multipart_upload.assert_called_once()
        state = self.point.metadata["do_spaces_s3_object"]
        self.assertEqual(state["phase"], "committed")
        self.assertNotIn("multipart", state)
        self.assertEqual(self.point.status, "complete")
