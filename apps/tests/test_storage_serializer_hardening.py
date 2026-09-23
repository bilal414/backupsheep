from importlib import import_module
from unittest import mock

from cryptography.fernet import Fernet
from django.test import SimpleTestCase

from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt


PROVIDER_SERIALIZERS = (
    ("alibaba", "CoreStorageAliBaba"),
    ("aws_s3", "CoreStorageAWSS3"),
    ("azure", "CoreStorageAzure"),
    ("backblaze_b2", "CoreStorageBackBlazeB2"),
    ("cloudflare", "CoreStorageCloudflare"),
    ("do_spaces", "CoreStorageDoSpaces"),
    ("exoscale", "CoreStorageExoscale"),
    ("filebase", "CoreStorageFilebase"),
    ("google_cloud", "CoreStorageGoogleCloud"),
    ("ibm", "CoreStorageIBM"),
    ("idrive", "CoreStorageIDrive"),
    ("ionos", "CoreStorageIonos"),
    ("leviia", "CoreStorageLeviia"),
    ("linode", "CoreStorageLinode"),
    ("oracle", "CoreStorageOracle"),
    ("rackcorp", "CoreStorageRackCorp"),
    ("scaleway", "CoreStorageScaleway"),
    ("tencent", "CoreStorageTencent"),
    ("upcloud", "CoreStorageUpCloud"),
    ("vultr", "CoreStorageVultr"),
    ("wasabi", "CoreStorageWasabi"),
)


def serializer_classes(module_name, class_prefix):
    module = import_module(f"apps.api.v1.storage.{module_name}.serializers")
    return (
        getattr(module, f"{class_prefix}ReadSerializer"),
        getattr(module, f"{class_prefix}WriteSerializer"),
    )


class StorageSerializerNonDisclosureTests(SimpleTestCase):
    def setUp(self):
        self.encryption_key = Fernet.generate_key()
        self.canary = "BACKUPSHEEP_STORAGE_SECRET_CANARY"

    def test_every_provider_read_serializer_redacts_credentials(self):
        for module_name, class_prefix in PROVIDER_SERIALIZERS:
            with self.subTest(provider=module_name):
                read_serializer, _ = serializer_classes(module_name, class_prefix)
                instance = read_serializer.Meta.model()
                credential_fields = tuple(read_serializer.credential_fields)
                for field_name in credential_fields:
                    setattr(instance, field_name, self.canary.encode())

                for field_name, value in (
                    ("bucket_name", "safe-bucket"),
                    ("prefix", "safe-prefix/"),
                    ("endpoint", "https://safe.example.invalid"),
                    ("namespace", "safe-namespace"),
                    ("account_id", "safe-account"),
                    ("expected_bucket_owner", "123456789012"),
                ):
                    if any(
                        field.name == field_name for field in instance._meta.fields
                    ):
                        setattr(instance, field_name, value)

                output = read_serializer(
                    instance,
                    context={"encryption_key": self.encryption_key},
                ).data

                self.assertNotIn(self.canary, repr(output))
                for field_name in credential_fields:
                    self.assertNotIn(field_name, output)
                    self.assertIs(output[f"{field_name}_configured"], True)
                model_field_names = {field.name for field in instance._meta.fields}
                if "bucket_name" in model_field_names:
                    self.assertEqual(output["bucket_name"], "safe-bucket")
                if "prefix" in model_field_names:
                    self.assertEqual(output["prefix"], "safe-prefix/")

    def test_every_provider_write_serializer_marks_credentials_write_only(self):
        for module_name, class_prefix in PROVIDER_SERIALIZERS:
            with self.subTest(provider=module_name):
                _, write_serializer = serializer_classes(module_name, class_prefix)
                serializer = write_serializer()
                for field_name in serializer.credential_fields:
                    self.assertTrue(serializer.fields[field_name].write_only)

    def test_every_access_key_provider_rejects_incomplete_pair_replacement(self):
        for module_name, class_prefix in PROVIDER_SERIALIZERS:
            _, write_serializer = serializer_classes(module_name, class_prefix)
            if set(write_serializer.credential_fields) != {"access_key", "secret_key"}:
                continue
            with self.subTest(provider=module_name):
                serializer = write_serializer(
                    instance=write_serializer.Meta.model(),
                    data={"access_key": "replacement-access"},
                    partial=True,
                    context={"encryption_key": self.encryption_key},
                )
                self.assertFalse(serializer.is_valid())
                self.assertIn("credentials", serializer.errors)


class StorageSerializerPatchTests(SimpleTestCase):
    def setUp(self):
        self.encryption_key = Fernet.generate_key()

    def _assert_prefix_patch_preserves_credentials(
        self, module_name, class_prefix, credentials, metadata
    ):
        _, write_serializer = serializer_classes(module_name, class_prefix)
        model = write_serializer.Meta.model
        encrypted = {
            name: bs_encrypt(value, self.encryption_key)
            for name, value in credentials.items()
        }
        instance = model(prefix="old-prefix/", **metadata, **encrypted)
        original_ciphertexts = {
            name: getattr(instance, name) for name in credentials
        }
        serializer = write_serializer(
            instance=instance,
            data={"prefix": "new-prefix/"},
            partial=True,
            context={"encryption_key": self.encryption_key},
        )

        with mock.patch.object(model, "validate", return_value=True), mock.patch.object(
            instance, "save"
        ):
            self.assertTrue(serializer.is_valid(), serializer.errors)
            for name in credentials:
                self.assertNotIn(name, serializer.validated_data)
            updated = serializer.save()

        self.assertEqual(updated.prefix, "new-prefix/")
        for name, ciphertext in original_ciphertexts.items():
            self.assertEqual(getattr(updated, name), ciphertext)

    def test_patch_preserves_omitted_s3_credential_pair(self):
        self._assert_prefix_patch_preserves_credentials(
            "vultr",
            "CoreStorageVultr",
            {"access_key": "old-access", "secret_key": "old-secret"},
            {
                "bucket_name": "safe-bucket",
                "endpoint": "https://ewr1.vultrobjects.com",
                "no_delete": False,
            },
        )

    def test_real_nested_patch_preserves_omitted_credentials(self):
        module = import_module("apps.api.v1.storage.vultr.serializers")
        provider_model = module.CoreStorageVultrWriteSerializer.Meta.model
        storage_model = module.CoreStorageWriteSerializer.Meta.model
        storage = storage_model(name="Original storage")
        provider = provider_model(
            storage=storage,
            access_key=bs_encrypt("old-access", self.encryption_key),
            secret_key=bs_encrypt("old-secret", self.encryption_key),
            bucket_name="safe-bucket",
            endpoint="https://ewr1.vultrobjects.com",
            prefix="old-prefix/",
            no_delete=False,
        )
        original_access = provider.access_key
        original_secret = provider.secret_key
        serializer = module.CoreStorageWriteSerializer(
            instance=storage,
            data={"storage_vultr": {"prefix": "nested-prefix/"}},
            partial=True,
            context={"encryption_key": self.encryption_key},
        )

        with mock.patch.object(
            provider_model, "validate", return_value=True
        ), mock.patch.object(provider, "save"), mock.patch.object(storage, "save"):
            self.assertTrue(serializer.is_valid(), serializer.errors)
            updated = serializer.save()

        self.assertEqual(updated.storage_vultr.prefix, "nested-prefix/")
        self.assertEqual(updated.storage_vultr.access_key, original_access)
        self.assertEqual(updated.storage_vultr.secret_key, original_secret)

    def test_patch_preserves_omitted_connection_string(self):
        self._assert_prefix_patch_preserves_credentials(
            "azure",
            "CoreStorageAzure",
            {"connection_string": "old-connection-string"},
            {"bucket_name": "safe-container", "no_delete": False},
        )

    def test_patch_preserves_omitted_service_json_and_legacy_tokens(self):
        self._assert_prefix_patch_preserves_credentials(
            "google_cloud",
            "CoreStorageGoogleCloud",
            {
                "service_key": '{"private_key":"old-private-material"}',
                "access_token": "old-access-token",
                "refresh_token": "old-refresh-token",
            },
            {"bucket_name": "safe-bucket", "no_delete": False},
        )

    def test_explicit_pair_replacement_is_encrypted(self):
        _, write_serializer = serializer_classes("vultr", "CoreStorageVultr")
        model = write_serializer.Meta.model
        instance = model(
            access_key=bs_encrypt("old-access", self.encryption_key),
            secret_key=bs_encrypt("old-secret", self.encryption_key),
            bucket_name="safe-bucket",
            endpoint="https://ewr1.vultrobjects.com",
            prefix="safe-prefix/",
            no_delete=False,
        )
        serializer = write_serializer(
            instance=instance,
            data={
                "access_key": "new-access",
                "secret_key": "new-secret",
            },
            partial=True,
            context={"encryption_key": self.encryption_key},
        )

        with mock.patch.object(model, "validate", return_value=True), mock.patch.object(
            instance, "save"
        ):
            self.assertTrue(serializer.is_valid(), serializer.errors)
            updated = serializer.save()

        self.assertEqual(
            bs_decrypt(updated.access_key, self.encryption_key), "new-access"
        )
        self.assertEqual(
            bs_decrypt(updated.secret_key, self.encryption_key), "new-secret"
        )
