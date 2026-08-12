"""Offline safety tests for the Oracle live UI support harness."""

import tempfile
import os
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import oci
from django.test import SimpleTestCase

from scripts.oracle_live_ui_e2e import (
    E2E_KIND_TAG,
    E2E_OWNED_TAG,
    E2E_RUN_TAG,
    HarnessConfig,
    HarnessError,
    OracleLiveUIHarness,
    SOURCE_BLOCK_DEVICE,
    main,
)


def response(data=None, *, status=200, next_page=None):
    return SimpleNamespace(
        data=data,
        status=status,
        opc_next_page=next_page,
        headers={},
    )


class OracleLiveUIHarnessSafetyTests(SimpleTestCase):
    compartment_id = "ocid1.compartment.oc1..backupsheeptest"
    tenancy_id = "ocid1.tenancy.oc1..backupsheeptest"
    availability_domain = "AD-1"
    run_id = "bs-oracle-e2e-0001"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def config(self, *, apply=False, cleanup=False):
        return HarnessConfig(
            run_id=self.run_id,
            ledger_path=self.root / "oracle-ledger.json",
            profile="BACKUPSHEEP_E2E",
            config_file=self.root / "oci-config",
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            apply=apply,
            cleanup=cleanup,
            poll_seconds=2,
            timeout_seconds=60,
        )

    @staticmethod
    def clients():
        return {
            "_config": {
                "tenancy": OracleLiveUIHarnessSafetyTests.tenancy_id,
                "region": "us-chicago-1",
            },
            "identity": mock.MagicMock(),
            "compute": mock.MagicMock(),
            "block": mock.MagicMock(),
            "network": mock.MagicMock(),
            "object": mock.MagicMock(),
        }

    def harness(self, *, apply=False, cleanup=False, clients=None, environment=None):
        return OracleLiveUIHarness(
            self.config(apply=apply, cleanup=cleanup),
            clients=clients or self.clients(),
            environment=environment or {},
            sleep=lambda _seconds: None,
        )

    def storage_secret(self, harness, *, bucket="bucket", user_ocid=None):
        user_ocid = user_ocid or "ocid1.user.oc1..backupsheeptest"
        return {
            "access_key_id": "A" * 40,
            "secret_access_key": "credential-canary",
            "bucket": bucket,
            "namespace": "namespace",
            "region": "us-chicago-1",
            "endpoint": "https://namespace.compat.objectstorage.us-chicago-1.oraclecloud.com",
            "prefix": f"{self.run_id}/",
            "user_ocid": user_ocid,
            "tenancy_ocid": self.tenancy_id,
            "compartment_ocid": self.compartment_id,
        }

    def establish_storage_scope(self, harness, *, bucket_name="bucket"):
        bucket = SimpleNamespace(
            id="ocid1.bucket.oc1.iad.backupsheeptest",
            name=bucket_name,
            compartment_id=self.compartment_id,
            lifecycle_state="ACTIVE",
            versioning="Enabled",
            freeform_tags=harness._storage_tags("object_bucket"),
        )
        user = self._iam_user(harness)
        harness._record_storage(
            "object_bucket",
            bucket,
            resource_id=bucket.id,
            name=bucket.name,
            compartment_id=self.compartment_id,
            tags=bucket.freeform_tags,
        )
        harness._record_storage(
            "iam_user",
            user,
            resource_id=user.id,
            name=user.name,
            compartment_id=self.tenancy_id,
            tags=user.freeform_tags,
        )
        scope = harness._storage_scope(
            bucket_name=bucket.name,
            namespace="namespace",
            region="us-chicago-1",
            user_ocid=user.id,
        )
        harness._persist_storage_scope(scope)
        return bucket, user, scope

    def test_plan_is_inert_and_does_not_load_oci_profile_or_clients(self):
        harness = self.harness()
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("live call")
        ):
            result = harness.plan()
        self.assertFalse(result["live_calls"])
        self.assertEqual(result["compartment_id"], self.compartment_id)

    def test_cli_plan_short_circuits_before_config_profile_ledger_or_harness(self):
        output = StringIO()
        with (
            mock.patch.object(
                HarnessConfig,
                "from_environment",
                side_effect=AssertionError("config must not load"),
            ),
            mock.patch.object(
                OracleLiveUIHarness,
                "__init__",
                side_effect=AssertionError("harness must not initialize"),
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(main(["--phase", "plan"], environment={}), 0)
        result = __import__("json").loads(output.getvalue())
        self.assertFalse(result["live_calls"])
        self.assertFalse(result["config_loaded"])
        self.assertFalse(result["profile_loaded"])
        self.assertFalse(result["ledger_initialized"])
        self.assertFalse(result["harness_initialized"])
        self.assertFalse(result["client_initialized"])

    def test_provision_and_cleanup_have_independent_fail_closed_gates(self):
        harness = self.harness(apply=False, cleanup=True)
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("live call")
        ):
            with self.assertRaisesRegex(HarnessError, "APPLY"):
                harness.provision()
            with self.assertRaisesRegex(HarnessError, "APPLY"):
                harness.cleanup()

        harness = self.harness(apply=True, cleanup=False)
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("live call")
        ):
            with self.assertRaisesRegex(HarnessError, "CLEANUP"):
                harness.cleanup()

    def test_environment_requires_two_exact_compartment_confirmations(self):
        environment = {
            "BACKUPSHEEP_E2E_RUN_ID": self.run_id,
            "BACKUPSHEEP_E2E_LEDGER_PATH": str(self.root / "ledger.json"),
            "OCI_CLI_PROFILE": "BACKUPSHEEP_E2E",
            "OCI_CLI_CONFIG_FILE": str(self.root / "config"),
            "ORACLE_E2E_COMPARTMENT_OCID": self.compartment_id,
            "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID": "ocid1.compartment.oc1..foreign",
            "ORACLE_E2E_AVAILABILITY_DOMAIN": self.availability_domain,
        }
        with self.assertRaisesRegex(HarnessError, "must match exactly"):
            HarnessConfig.from_environment(environment)

        environment["ORACLE_E2E_ALLOWED_COMPARTMENT_OCID"] = self.compartment_id
        environment["OCI_CLI_CONFIG_FILE"] = str(self.root / "_docs" / "oracle.txt")
        with self.assertRaisesRegex(HarnessError, "must not point inside _docs"):
            HarnessConfig.from_environment(environment)

    def test_scope_check_does_not_send_pagination_to_unpaged_ad_endpoint(self):
        clients = self.clients()
        clients["identity"].get_compartment.return_value = response(
            SimpleNamespace(
                id=self.compartment_id,
                lifecycle_state="ACTIVE",
            )
        )
        clients["identity"].list_availability_domains.return_value = response(
            [SimpleNamespace(name=self.availability_domain)]
        )
        harness = self.harness(clients=clients)

        harness._validate_scope()

        kwargs = clients["identity"].list_availability_domains.call_args.kwargs
        self.assertNotIn("limit", kwargs)
        self.assertNotIn("page", kwargs)

    def test_attachment_device_must_be_exact_and_provider_available(self):
        clients = self.clients()
        clients["compute"].list_instance_devices.return_value = response(
            [
                SimpleNamespace(name=SOURCE_BLOCK_DEVICE, is_available=True),
                SimpleNamespace(name="/dev/oracleoci/oraclevdc", is_available=False),
            ]
        )
        harness = self.harness(clients=clients)
        instance_id = "ocid1.instance.oc1.iad.backupsheeptest"
        self.assertEqual(
            harness._require_attachment_device(instance_id, SOURCE_BLOCK_DEVICE),
            SOURCE_BLOCK_DEVICE,
        )
        with self.assertRaisesRegex(HarnessError, "not available"):
            harness._require_attachment_device(
                instance_id, "/dev/oracleoci/oraclevdc"
            )
        with self.assertRaisesRegex(HarnessError, "safe allowlist"):
            harness._require_attachment_device(instance_id, "/dev/sdb")

    def _volume(self, harness, *, tags=None, state="AVAILABLE"):
        return SimpleNamespace(
            id="ocid1.volume.oc1.iad.backupsheeptest",
            display_name=harness.names["source_block_volume"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state=state,
            freeform_tags=tags
            if tags is not None
            else {
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "source_block_volume",
            },
            source_details=None,
        )

    def test_foreign_same_name_blocks_create(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        clients["block"].list_volumes.return_value = response(
            [self._volume(harness, tags={E2E_RUN_TAG: "foreign-run"})]
        )

        with self.assertRaisesRegex(HarnessError, "foreign"):
            harness._provision_block_volume()

        clients["block"].create_volume.assert_not_called()

    def test_unresolved_mutation_intent_blocks_blind_replay(self):
        harness = self.harness(apply=True)
        harness._put_intent(
            "source_block_volume",
            operation="create",
            name=harness.names["source_block_volume"],
        )

        with self.assertRaisesRegex(HarnessError, "unresolved durable mutation"):
            harness._put_intent(
                "source_block_volume",
                operation="create",
                name=harness.names["source_block_volume"],
            )

    def _iam_user(self, harness):
        return SimpleNamespace(
            id="ocid1.user.oc1..backupsheeptest",
            name=harness.names["iam_user"],
            compartment_id=self.tenancy_id,
            lifecycle_state="ACTIVE",
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "iam_user",
            },
        )

    def test_identity_domain_user_create_has_reserved_primary_email(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        user = self._iam_user(harness)
        clients["identity"].list_users.return_value = response([])
        clients["identity"].create_user.return_value = response(user)
        clients["identity"].get_user.return_value = response(user)

        created = harness._provision_iam_named(
            kind="iam_user",
            tenancy_id=self.tenancy_id,
            list_method=clients["identity"].list_users,
            create_method=clients["identity"].create_user,
            details_class=oci.identity.models.CreateUserDetails,
        )

        self.assertEqual(created.id, user.id)
        details = clients["identity"].create_user.call_args.kwargs[
            "create_user_details"
        ]
        self.assertEqual(details.email, f"{self.run_id}@example.invalid")
        self.assertIsNone(harness.intents.get("iam_user"))

    def test_definite_iam_rejection_clears_intent_after_exact_absence(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        clients["identity"].list_users.return_value = response([])
        rejected = RuntimeError("sensitive provider detail")
        rejected.status = 400
        rejected.code = "IdcsConversionError"
        clients["identity"].create_user.side_effect = rejected

        with self.assertRaisesRegex(HarnessError, "PROVIDER_REQUEST_FAILED"):
            harness._provision_iam_named(
                kind="iam_user",
                tenancy_id=self.tenancy_id,
                list_method=clients["identity"].list_users,
                create_method=clients["identity"].create_user,
                details_class=oci.identity.models.CreateUserDetails,
            )

        self.assertIsNone(harness.intents.get("iam_user"))

    def test_oci_mutation_definitive_4xx_categories_clear_only_their_intent(self):
        for status in (400, 403, 404, 429):
            with self.subTest(status=status):
                clients = self.clients()
                harness = self.harness(apply=True, clients=clients)
                clients["identity"].create_user.return_value = response(
                    status=status
                )
                harness._put_intent(
                    "iam_user",
                    operation="create",
                    name=harness.names["iam_user"],
                )
                with self.assertRaises(HarnessError) as raised:
                    harness._mutation_call(
                        "iam_user", clients["identity"].create_user
                    )
                self.assertTrue(raised.exception.definitive_rejection)
                self.assertFalse(raised.exception.mutation_outcome_unknown)
                self.assertIsNone(harness.intents.get("iam_user"))

    def test_oci_mutation_transient_and_unknown_categories_retain_intent(self):
        cases = (
            ("408", 408, None),
            ("500", 500, None),
            ("504", 504, None),
            ("timeout", None, TimeoutError("lost response")),
            ("connection", None, ConnectionError("lost response")),
            ("unknown", None, RuntimeError("unclassified SDK failure")),
        )
        for label, status, exception in cases:
            with self.subTest(category=label):
                clients = self.clients()
                harness = self.harness(apply=True, clients=clients)
                if exception is not None:
                    clients["identity"].create_user.side_effect = exception
                else:
                    clients["identity"].create_user.return_value = response(
                        status=status
                    )
                intent_key = f"iam_user_{label}"
                harness._put_intent(
                    intent_key,
                    operation="create",
                    name=harness.names["iam_user"],
                )
                with self.assertRaises(HarnessError) as raised:
                    harness._mutation_call(
                        intent_key, clients["identity"].create_user
                    )
                self.assertFalse(raised.exception.definitive_rejection)
                self.assertTrue(raised.exception.mutation_outcome_unknown)
                self.assertIsNotNone(harness.intents.get(intent_key))

    def test_ambiguous_iam_timeout_keeps_intent_after_exact_absence(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        clients["identity"].list_users.return_value = response([])
        clients["identity"].create_user.side_effect = TimeoutError("lost response")

        with self.assertRaisesRegex(HarnessError, "outcome may be unknown"):
            harness._provision_iam_named(
                kind="iam_user",
                tenancy_id=self.tenancy_id,
                list_method=clients["identity"].list_users,
                create_method=clients["identity"].create_user,
                details_class=oci.identity.models.CreateUserDetails,
            )

        self.assertIsNotNone(harness.intents.get("iam_user"))

    def test_lost_block_create_response_adopts_one_exact_match(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        volume = self._volume(harness)
        clients["block"].list_volumes.side_effect = [
            response([]),
            response([volume]),
        ]
        clients["block"].create_volume.side_effect = oci.exceptions.RequestException(
            "credential-canary"
        )
        clients["block"].get_volume.return_value = response(volume)

        adopted = harness._provision_block_volume()

        self.assertEqual(adopted.id, volume.id)
        clients["block"].create_volume.assert_called_once()
        row = harness.ledger.get("source_block_volume", volume.id)
        self.assertEqual(row["resource_id"], volume.id)
        self.assertNotIn("credential-canary", repr(row))

    def test_cleanup_refuses_changed_ownership_before_delete(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        clients["block"].list_volumes.return_value = response(
            [self._volume(harness, tags={E2E_RUN_TAG: "foreign-run"})]
        )

        with self.assertRaisesRegex(HarnessError, "ownership tags"):
            harness._cleanup_graph_kind("source_block_volume")

        clients["block"].delete_volume.assert_not_called()

    def test_cleanup_blocks_incomplete_instance_dependency_ledger(self):
        harness = self.harness(apply=True, cleanup=True)
        instance = SimpleNamespace(
            id="ocid1.instance.oc1.iad.backupsheeptest",
            display_name=harness.names["source_instance"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="RUNNING",
            image_id="ocid1.image.oc1.iad.base",
            source_details=None,
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "source_instance",
            },
        )
        proof = harness._expected_proof(
            name=instance.display_name,
            tags=instance.freeform_tags,
            availability_domain=self.availability_domain,
            source_id=instance.image_id,
        )
        harness._record(
            "source_instance",
            instance,
            proof,
            source_id=instance.image_id,
        )

        with self.assertRaisesRegex(HarnessError, "incomplete dependency ledger"):
            harness._assert_cleanup_graph_complete()

    def _boot_verifier_resources(self, harness):
        boot_id = "ocid1.bootvolume.oc1.iad.restoredboot"
        instance_id = "ocid1.instance.oc1.iad.bootverifier"
        restored_boot = SimpleNamespace(id=boot_id)
        instance = SimpleNamespace(
            id=instance_id,
            display_name=harness.names["ui_boot_verify_instance"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="RUNNING",
            # OCI retains the original image here even when launch source was an
            # existing boot volume. The attachment is the authoritative witness.
            image_id="ocid1.image.oc1.iad.originalimage",
            source_details=None,
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "ui_boot_verify_instance",
            },
        )
        attachment = SimpleNamespace(
            id="ocid1.bootvolumeattachment.oc1.iad.bootverifier",
            instance_id=instance_id,
            boot_volume_id=boot_id,
            lifecycle_state="ATTACHED",
        )
        return restored_boot, instance, attachment

    def test_boot_verifier_uses_exact_attachment_not_original_image_as_source(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        restored_boot, instance, attachment = self._boot_verifier_resources(harness)
        clients["compute"].list_instances.return_value = response([instance])
        clients["compute"].get_instance.return_value = response(instance)
        clients["compute"].list_boot_volume_attachments.return_value = response(
            [attachment]
        )

        observed = harness._launch_boot_verifier(
            restored_boot,
            subnet_id="ocid1.subnet.oc1.iad.testsubnet",
            shape="VM.Standard.E2.1",
        )

        self.assertEqual(observed.id, instance.id)
        clients["compute"].launch_instance.assert_not_called()
        row = harness.ledger.get("ui_boot_verify_instance", instance.id)
        self.assertEqual(row["source_witness"], restored_boot.id)
        self.assertEqual(row["ownership"]["source_id"], restored_boot.id)

        # A resumed verifier validates the same provider relationship and does
        # not regress to comparing the instance's original image ID.
        resumed = harness._launch_boot_verifier(
            restored_boot,
            subnet_id="ocid1.subnet.oc1.iad.testsubnet",
            shape="VM.Standard.E2.1",
        )
        self.assertEqual(resumed.id, instance.id)

    def test_boot_verifier_refuses_a_different_attached_boot_volume(self):
        clients = self.clients()
        harness = self.harness(apply=True, clients=clients)
        restored_boot, instance, attachment = self._boot_verifier_resources(harness)
        attachment.boot_volume_id = "ocid1.bootvolume.oc1.iad.foreignboot"
        clients["compute"].list_instances.return_value = response([instance])
        clients["compute"].get_instance.return_value = response(instance)
        clients["compute"].list_boot_volume_attachments.return_value = response(
            [attachment]
        )

        with self.assertRaisesRegex(HarnessError, "different boot volume"):
            harness._launch_boot_verifier(
                restored_boot,
                subnet_id="ocid1.subnet.oc1.iad.testsubnet",
                shape="VM.Standard.E2.1",
            )

        clients["compute"].launch_instance.assert_not_called()
        self.assertIsNone(
            harness.ledger.get("ui_boot_verify_instance", instance.id)
        )

    def test_secret_file_is_outside_repo_chmod_600_and_not_reported(self):
        secret_path = self.root / "runtime" / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)

        written = harness._write_storage_secret(secret)

        self.assertEqual(written, secret_path)
        self.assertEqual(written.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("credential-canary", repr(harness.plan()))
        self.assertEqual(harness._read_storage_secret(), secret)

    def test_secret_loader_requires_exact_0600_exact_keys_and_no_symlink(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)
        harness._write_storage_secret(secret)

        os.chmod(secret_path, 0o640)
        with self.assertRaisesRegex(HarnessError, "0600"):
            harness._read_storage_secret()

        os.chmod(secret_path, 0o600)
        with self.assertRaisesRegex(HarnessError, "unsupported or incomplete"):
            harness._write_storage_secret({**secret, "unexpected": "value"})

        secret_path.unlink()
        target = self.root / "target-secret.json"
        target.write_text(__import__("json").dumps(secret), encoding="utf-8")
        os.chmod(target, 0o600)
        secret_path.symlink_to(target)
        with self.assertRaisesRegex(HarnessError, "symlink"):
            harness._read_storage_secret()

        secret_path.unlink()
        secret_path.mkdir(mode=0o700)
        os.chmod(secret_path, 0o600)
        with self.assertRaisesRegex(HarnessError, "regular 0600 file"):
            harness._read_storage_secret()

    def test_storage_s3_use_requires_durable_scope_and_rejects_scope_drift(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)
        harness._write_storage_secret(secret)
        with mock.patch("boto3.client") as client:
            with self.assertRaisesRegex(HarnessError, "durable storage scope"):
                harness._storage_s3_client()
        client.assert_not_called()

        self.establish_storage_scope(harness)
        changed = dict(secret, bucket="other-bucket")
        harness._write_storage_secret(changed)
        with mock.patch("boto3.client") as client:
            with self.assertRaisesRegex(HarnessError, "scope does not match"):
                harness._storage_s3_client()
        client.assert_not_called()

    def test_storage_scope_change_in_durable_evidence_fails_closed_before_s3(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        self.establish_storage_scope(harness)
        harness._write_storage_secret(self.storage_secret(harness))
        harness.evidence.update("storage_scope", bucket="foreign-bucket")

        with mock.patch("boto3.client") as client:
            with self.assertRaisesRegex(
                HarnessError, "does not match (durable ownership|OCI configuration)"
            ):
                harness._storage_s3_client()
        client.assert_not_called()

    def test_provider_error_messages_are_sanitized_and_statuses_are_classified(self):
        harness = self.harness(apply=True)
        with self.assertRaises(HarnessError) as raised:
            harness._call(
                mock.Mock(side_effect=RuntimeError("Authorization: Bearer secret-canary")),
                mutation=True,
            )
        self.assertNotIn("secret-canary", str(raised.exception))
        self.assertEqual(raised.exception.code, "PROVIDER_REQUEST_FAILED")

        for status, code in (
            (404, "PROVIDER_NOT_FOUND"),
            (429, "PROVIDER_RATE_LIMIT"),
            (500, "PROVIDER_TRANSIENT_OUTAGE"),
        ):
            with self.subTest(status=status):
                with self.assertRaises(HarnessError) as raised:
                    harness._call(mock.Mock(return_value=response(status=status)), mutation=True)
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(raised.exception.mutation_outcome_unknown, status == 500)

    def test_customer_secret_key_uses_oci_access_key_id_not_ocid(self):
        harness = self.harness(apply=True)
        key_id = "A" * 40
        key = SimpleNamespace(
            id=key_id,
            display_name=harness.names["customer_secret_key"],
            user_id="ocid1.user.oc1..backupsheeptest",
            lifecycle_state="ACTIVE",
        )

        row = harness._record_storage(
            "customer_secret_key",
            key,
            resource_id=key_id,
            name=key.display_name,
            compartment_id="",
            relationships={"user_id": key.user_id},
        )

        self.assertEqual(row["resource_id"], key_id)
        with self.assertRaisesRegex(HarnessError, "ID is malformed"):
            harness._record_storage(
                "customer_secret_key",
                key,
                resource_id="not-an-access-key",
                name=key.display_name,
                compartment_id="",
                relationships={"user_id": key.user_id},
            )

    def test_oracle_s3_client_disables_unsupported_aws_chunked_checksums(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        self.establish_storage_scope(harness)
        secret = self.storage_secret(harness)
        secret_path.write_text(
            __import__("json").dumps(
                secret
            ),
            encoding="utf-8",
        )
        os.chmod(secret_path, 0o600)
        with mock.patch("boto3.client", return_value=mock.sentinel.client) as client:
            created, _secret = harness._storage_s3_client(secret_path)

        self.assertIs(created, mock.sentinel.client)
        config = client.call_args.kwargs["config"]
        self.assertEqual(config.request_checksum_calculation, "when_required")
        self.assertEqual(config.response_checksum_validation, "when_required")

    def test_hash_mismatch_never_persists_restore_or_seed_success(self):
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_DATA_BYTES": "4096"},
        )
        payload, digest, byte_count = harness._payload()
        ssh = mock.MagicMock()
        expected = {"sha256": digest, "byte_count": byte_count}
        mismatched = {"sha256": "0" * 64, "byte_count": byte_count}
        with mock.patch.object(harness, "_ssh_client", return_value=ssh), mock.patch.object(
            harness, "_upload_payload", return_value="/tmp/payload"
        ), mock.patch.object(harness, "_ssh_run", return_value=""), mock.patch.object(
            harness, "_mount_volume"
        ), mock.patch.object(
            harness, "_remote_evidence", side_effect=[expected, mismatched]
        ):
            with self.assertRaisesRegex(HarnessError, "hash evidence"):
                harness._seed_data(
                    mock.MagicMock(),
                    mock.MagicMock(),
                    instance_id="ocid1.instance.oc1.iad.instance",
                    block_volume_id="ocid1.volume.oc1.iad.volume",
                    boot_volume_id="ocid1.bootvolume.oc1.iad.boot",
                )
        self.assertEqual(len(payload), byte_count)
        self.assertIsNone(harness.evidence.get("payload"))

    def test_storage_verification_requires_versioned_hash_witness_before_get(self):
        secret_path = self.root / "oracle-storage.json"
        harness = self.harness(
            apply=True,
            environment={"ORACLE_E2E_SECRET_FILE": str(secret_path)},
        )
        secret = self.storage_secret(harness)
        harness._write_storage_secret(secret)
        s3 = mock.MagicMock()
        manifest = {
            "objects": [
                {
                    "kind": "website",
                    "key": f"{self.run_id}/website.zip",
                    "sha256": "a" * 64,
                    "byte_count": 10,
                    "etag": "etag",
                    "version_id": "",
                },
                {
                    "kind": "database",
                    "key": f"{self.run_id}/database.zip",
                    "sha256": "b" * 64,
                    "byte_count": 10,
                    "etag": "etag",
                    "version_id": "version-two",
                },
            ]
        }
        with mock.patch.object(
            harness, "_storage_s3_client", return_value=(s3, secret)
        ):
            with self.assertRaisesRegex(HarnessError, "witness failed"):
                harness._verify_storage_objects(manifest)
        s3.get_object.assert_not_called()

    def test_graph_delete_lost_response_adopts_exact_absence_without_replay(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        clients["block"].list_volumes.side_effect = [
            response([volume]),
            response([]),
        ]
        clients["block"].delete_volume.side_effect = TimeoutError("lost response")

        self.assertEqual(harness._cleanup_graph_kind("source_block_volume"), "DELETED")
        clients["block"].delete_volume.assert_called_once()
        self.assertEqual(
            harness.ledger.get("source_block_volume", volume.id)["cleanup_state"],
            "deleted",
        )
        self.assertFalse(
            any(key.startswith("cleanup:") for key in harness.intents.pending())
        )

    def test_graph_unknown_response_with_live_resource_is_manual_and_never_replayed(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        clients["block"].list_volumes.return_value = response([volume])
        clients["block"].delete_volume.side_effect = TimeoutError("accepted-but-lost")

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_graph_kind("source_block_volume")
        self.assertEqual(
            harness.ledger.get("source_block_volume", volume.id)["cleanup_state"],
            "manual_review",
        )
        clients["block"].delete_volume.assert_called_once()

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_graph_kind("source_block_volume")
        clients["block"].delete_volume.assert_called_once()

    def test_prepared_cleanup_intent_is_fail_closed_before_provider_call(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        volume = self._volume(harness)
        proof = harness._expected_proof(
            name=volume.display_name,
            tags=volume.freeform_tags,
            availability_domain=self.availability_domain,
        )
        harness._record("source_block_volume", volume, proof)
        key = harness._cleanup_intent_key(
            "source_block_volume", volume.id, "delete_volume"
        )
        harness.intents.put(
            key,
            {
                "operation": "delete_volume",
                "kind": "source_block_volume",
                "name": volume.display_name,
                "marker": self.run_id,
                "provider_resource_id": volume.id,
                "state": "prepared",
            },
        )
        clients["block"].list_volumes.return_value = response([volume])

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_graph_kind("source_block_volume")
        clients["block"].delete_volume.assert_not_called()

    def test_graph_success_polls_accepted_termination_to_terminal_state(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        instance = SimpleNamespace(
            id="ocid1.instance.oc1.iad.backupsheeptest",
            display_name=harness.names["source_instance"],
            compartment_id=self.compartment_id,
            availability_domain=self.availability_domain,
            lifecycle_state="RUNNING",
            image_id="ocid1.image.oc1.iad.backupsheeptest",
            source_details=None,
            freeform_tags=harness._source_tags("source_instance"),
        )
        proof = harness._expected_proof(
            name=instance.display_name,
            tags=instance.freeform_tags,
            availability_domain=self.availability_domain,
            source_id=instance.image_id,
        )
        harness._record(
            "source_instance", instance, proof, source_id=instance.image_id
        )
        terminated = SimpleNamespace(**{**vars(instance), "lifecycle_state": "TERMINATED"})
        clients["compute"].list_instances.side_effect = [
            response([instance]),
            response([terminated]),
        ]
        clients["compute"].terminate_instance.return_value = response(status=202)

        self.assertEqual(harness._cleanup_graph_kind("source_instance"), "DELETED")
        clients["compute"].terminate_instance.assert_called_once_with(
            instance_id=instance.id,
            preserve_boot_volume=True,
        )

    def test_graph_detach_persists_intent_and_adopts_detached_attachment(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        attachment = SimpleNamespace(
            id="ocid1.volumeattachment.oc1.iad.backupsheeptest",
            display_name=harness.names["source_block_attachment"],
            compartment_id=self.compartment_id,
            lifecycle_state="ATTACHED",
        )
        proof = harness._expected_proof(
            name=attachment.display_name,
            tags={},
        )
        harness._record("source_block_attachment", attachment, proof)
        clients["compute"].list_volume_attachments.side_effect = [
            response([attachment]),
            response([]),
        ]
        clients["compute"].detach_volume.return_value = response(status=202)
        with mock.patch.object(harness, "_unmount_test_attachment") as unmount:
            self.assertEqual(
                harness._cleanup_graph_kind("source_block_attachment"), "DELETED"
            )
        unmount.assert_called_once_with("source_block_attachment")
        clients["compute"].detach_volume.assert_called_once_with(
            volume_attachment_id=attachment.id
        )

    def test_iam_delete_lost_response_adopts_exact_absence_without_replay(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        user = self._iam_user(harness)
        harness._record_storage(
            "iam_user",
            user,
            resource_id=user.id,
            name=user.name,
            compartment_id=self.tenancy_id,
            tags=user.freeform_tags,
        )
        clients["identity"].list_users.side_effect = [
            response([user]),
            response([]),
        ]
        clients["identity"].delete_user.side_effect = TimeoutError("lost response")

        self.assertEqual(
            harness._cleanup_storage_kind(
                "iam_user", tenancy_id=self.tenancy_id, namespace="namespace"
            ),
            "DELETED",
        )
        clients["identity"].delete_user.assert_called_once_with(user_id=user.id)
        self.assertEqual(
            harness.ledger.get("iam_user", user.id)["cleanup_state"], "deleted"
        )

    def test_iam_unknown_response_is_manual_and_never_replayed(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        user = self._iam_user(harness)
        harness._record_storage(
            "iam_user",
            user,
            resource_id=user.id,
            name=user.name,
            compartment_id=self.tenancy_id,
            tags=user.freeform_tags,
        )
        clients["identity"].list_users.return_value = response([user])
        clients["identity"].delete_user.side_effect = TimeoutError("accepted-but-lost")

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_storage_kind(
                "iam_user", tenancy_id=self.tenancy_id, namespace="namespace"
            )
        clients["identity"].delete_user.assert_called_once()
        self.assertEqual(
            harness.ledger.get("iam_user", user.id)["cleanup_state"],
            "manual_review",
        )
        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_storage_kind(
                "iam_user", tenancy_id=self.tenancy_id, namespace="namespace"
            )
        clients["identity"].delete_user.assert_called_once()

    def test_object_version_delete_lost_response_reconciles_before_bucket_delete(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        bucket, _user, _scope = self.establish_storage_scope(harness)
        key = f"{self.run_id}/website.zip"
        version = SimpleNamespace(name=key, version_id="version-one")
        current = SimpleNamespace(name=key)
        clients["object"].get_bucket.side_effect = [
            response(bucket),
            response(status=404),
        ]
        clients["object"].list_object_versions.side_effect = [
            response([version]),
            response([]),
            response([]),
        ]
        clients["object"].list_objects.side_effect = [
            response(SimpleNamespace(objects=[current], next_start_with=None)),
            response(SimpleNamespace(objects=[], next_start_with=None)),
            response(SimpleNamespace(objects=[], next_start_with=None)),
        ]
        clients["object"].delete_object.side_effect = TimeoutError("lost response")
        clients["object"].delete_bucket.return_value = response(status=204)

        self.assertEqual(
            harness._cleanup_bucket(
                harness.ledger.get("object_bucket", bucket.id),
                namespace="namespace",
            ),
            "DELETED",
        )
        clients["object"].delete_object.assert_called_once()
        clients["object"].delete_bucket.assert_called_once()
        self.assertEqual(
            harness.ledger.get("object_bucket", bucket.id)["cleanup_state"],
            "deleted",
        )

    def test_object_version_unknown_response_is_manual_and_never_replayed(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        bucket, _user, _scope = self.establish_storage_scope(harness)
        key_name = f"{self.run_id}/website.zip"
        version = SimpleNamespace(name=key_name, version_id="version-one")
        current = SimpleNamespace(name=key_name)
        clients["object"].get_bucket.return_value = response(bucket)
        clients["object"].list_object_versions.return_value = response([version])
        clients["object"].list_objects.return_value = response(
            SimpleNamespace(objects=[current], next_start_with=None)
        )
        clients["object"].delete_object.side_effect = TimeoutError("lost response")
        row = harness.ledger.get("object_bucket", bucket.id)

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_bucket(row, namespace="namespace")
        clients["object"].delete_object.assert_called_once()
        clients["object"].delete_bucket.assert_not_called()
        self.assertEqual(
            harness.ledger.get("object_bucket", bucket.id)["cleanup_state"],
            "manual_review",
        )

        with self.assertRaisesRegex(HarnessError, "will not be replayed"):
            harness._cleanup_bucket(row, namespace="namespace")
        clients["object"].delete_object.assert_called_once()

    def test_bucket_cleanup_refuses_any_object_outside_exact_run_prefix(self):
        clients = self.clients()
        harness = self.harness(apply=True, cleanup=True, clients=clients)
        bucket = SimpleNamespace(
            id="ocid1.bucket.oc1.iad.backupsheeptest",
            name=harness.names["object_bucket"],
            compartment_id=self.compartment_id,
            lifecycle_state="ACTIVE",
            versioning="Enabled",
            freeform_tags={
                E2E_RUN_TAG: self.run_id,
                E2E_OWNED_TAG: "true",
                E2E_KIND_TAG: "object_bucket",
            },
        )
        harness._record_storage(
            "object_bucket",
            bucket,
            resource_id=bucket.id,
            name=bucket.name,
            compartment_id=self.compartment_id,
            tags=bucket.freeform_tags,
        )
        clients["object"].list_buckets.return_value = response([bucket])
        clients["object"].get_bucket.return_value = response(bucket)
        clients["object"].list_object_versions.return_value = response(
            SimpleNamespace(
                items=[
                    SimpleNamespace(
                        name="foreign-prefix/do-not-delete.zip",
                        version_id="version-one",
                        is_delete_marker=False,
                    )
                ],
                prefixes=[],
            )
        )
        clients["object"].list_objects.return_value = response(
            SimpleNamespace(objects=[], next_start_with=None)
        )
        row = harness.ledger.get("object_bucket", bucket.id)

        with self.assertRaisesRegex(HarnessError, "outside the run prefix"):
            harness._cleanup_bucket(row, namespace="safe_namespace")

        clients["object"].delete_object.assert_not_called()
        clients["object"].delete_bucket.assert_not_called()
