"""Deterministic, zero-network safety tests for the AWS live E2E runners."""

import ast
import os
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from botocore.exceptions import ClientError

from scripts import aws_ec2_ebs_e2e as ec2_harness
from scripts import aws_s3_dynamodb_rds_e2e as relational_harness


ROOT = Path(__file__).resolve().parents[2]


class AWSE2ENetworkSafetyTests(TestCase):
    @staticmethod
    def _client_error(code, status):
        return ClientError(
            {
                "Error": {"Code": code, "Message": "offline-test"},
                "ResponseMetadata": {"HTTPStatusCode": status},
            },
            "OfflineTest",
        )

    def test_instance_readback_carries_reservation_account_identity(self):
        response = {
            "Reservations": [
                {
                    "OwnerId": "123456789012",
                    "Instances": [{"InstanceId": "i-owned"}],
                }
            ]
        }
        self.assertEqual(
            ec2_harness._flatten_instances(response),
            [{"InstanceId": "i-owned", "OwnerId": "123456789012"}],
        )

    def test_cleanup_readback_outage_never_becomes_absence(self):
        ledger = mock.Mock()
        ledger.cleanup_eligible.return_value = True
        ledger.get.return_value = {
            "ownership": {
                "tag_key": ec2_harness.OWNERSHIP_TAG,
                "tag_value": "bs-e2e-test-1234",
                "role": "source-data-volume",
            }
        }
        resource = {
            "VolumeId": "vol-owned",
            "Tags": [
                {"Key": ec2_harness.OWNERSHIP_TAG, "Value": "bs-e2e-test-1234"},
                {"Key": ec2_harness.ROLE_TAG, "Value": "source-data-volume"},
            ],
        }
        readback = mock.Mock(side_effect=[resource, TimeoutError("provider timeout")])
        report = []

        ec2_harness._cleanup_resource(
            ledger,
            "source_data_volume",
            "vol-owned",
            readback,
            ec2_harness._entry_matches,
            mock.Mock(side_effect=TimeoutError("lost delete response")),
            report,
        )

        self.assertEqual(report[0]["state"], "manual_review")
        self.assertNotIn("absent", [item.get("state") for item in report])
        ledger.mark_cleanup.assert_called_once()
        self.assertEqual(ledger.mark_cleanup.call_args.kwargs["state"], "manual_review")

    def test_dynamodb_ownership_readback_distinguishes_absence_from_outage(self):
        missing = mock.Mock()
        missing.describe_table.side_effect = self._client_error(
            "ResourceNotFoundException", 400
        )
        self.assertIsNone(
            relational_harness._ddb_description_owned(missing, "owned-table")
        )

        outage = mock.Mock()
        outage.describe_table.side_effect = self._client_error(
            "ServiceUnavailable", 503
        )
        with self.assertRaises(ClientError):
            relational_harness._ddb_description_owned(outage, "owned-table")

        malformed = mock.Mock()
        malformed.describe_table.return_value = {}
        with self.assertRaises(relational_harness.HarnessError):
            relational_harness._ddb_description_owned(malformed, "owned-table")

    def test_rds_snapshot_cleanup_waits_for_provider_absence(self):
        rds = mock.Mock()
        rds.describe_db_snapshots.side_effect = [
            {"DBSnapshots": [{"Status": "deleting"}]},
            self._client_error("DBSnapshotNotFound", 404),
        ]
        with mock.patch.object(relational_harness, "_sleep"):
            relational_harness._delete_rds_snapshot(rds, "owned-snapshot")

        rds.delete_db_snapshot.assert_called_once_with(
            DBSnapshotIdentifier="owned-snapshot"
        )
        self.assertEqual(rds.describe_db_snapshots.call_count, 2)

    def test_recovery_point_cleanup_waits_for_provider_absence(self):
        backup_client = mock.Mock()
        backup_client.describe_recovery_point.side_effect = [
            {"Status": "DELETING"},
            self._client_error("ResourceNotFoundException", 404),
        ]
        with mock.patch.object(relational_harness, "_sleep"):
            relational_harness._delete_recovery_point(
                backup_client,
                "owned-vault",
                "arn:aws:backup:us-east-2:123456789012:recovery-point:owned",
            )

        backup_client.delete_recovery_point.assert_called_once()
        self.assertEqual(backup_client.describe_recovery_point.call_count, 2)

    def test_valid_ipv4_and_ipv6_host_cidrs_are_preserved(self):
        expected = ("192.0.2.7/32", "2001:db8::7/128")
        self.assertEqual(
            relational_harness._validated_cidrs(
                "192.0.2.7/32,2001:db8::7/128", "AWS_E2E_RDS_CIDRS"
            ),
            expected,
        )
        self.assertEqual(
            ec2_harness._validated_cidrs(
                "192.0.2.7/32,2001:db8::7/128", "AWS_E2E_WEB_CIDRS"
            ),
            expected,
        )

    def test_world_open_and_malformed_cidrs_fail_closed(self):
        cases = (
            "0.0.0.0/0",
            "::/0",
            "192.0.2.7",
            "2001:db8::7/129",
            "not-a-cidr",
            "192.0.2.7/32,",
        )
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(relational_harness.HarnessError):
                    relational_harness._validated_cidrs(value, "AWS_E2E_RDS_CIDRS")
                with self.assertRaises(ec2_harness.HarnessError):
                    ec2_harness._validated_cidrs(value, "AWS_E2E_SSH_CIDRS")

    def test_security_group_permissions_split_ipv4_and_ipv6_safely(self):
        cidrs = ("192.0.2.7/32", "2001:db8::7/128")
        relational = relational_harness._security_group_permission(
            5432, 5432, cidrs, "RDS test runner"
        )
        native = ec2_harness._security_group_permission(
            80, 80, cidrs, "web test runner"
        )

        for permission, port, description in (
            (relational, 5432, "RDS test runner"),
            (native, 80, "web test runner"),
        ):
            self.assertEqual(permission["FromPort"], port)
            self.assertEqual(permission["ToPort"], port)
            self.assertEqual(permission["IpRanges"], [{"CidrIp": cidrs[0], "Description": description}])
            self.assertEqual(permission["Ipv6Ranges"], [{"CidrIpv6": cidrs[1], "Description": description}])
            self.assertNotIn("0.0.0.0/0", repr(permission))
            self.assertNotIn("::/0", repr(permission))

    def test_observed_world_open_web_or_ssh_rule_is_rejected(self):
        group = {
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        }
        with self.assertRaises(ec2_harness.HarnessError):
            ec2_harness._security_group_rule_cidrs(group, 80, 80)

        group["IpPermissions"][0].update(
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        )
        with self.assertRaises(ec2_harness.HarnessError):
            ec2_harness._security_group_rule_cidrs(group, 22, 22)

    def test_runners_have_no_unauthenticated_ip_discovery_or_world_open_rule(self):
        for name in (
            "scripts/aws_s3_dynamodb_rds_e2e.py",
            "scripts/aws_ec2_ebs_e2e.py",
        ):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("checkip.amazonaws.com", source)
            self.assertNotIn("0.0.0.0/0", source)
            self.assertNotIn("::/0", source)

    def test_boto_client_allowlists_reject_unsupported_services_without_network(self):
        for harness, allowed in (
            (relational_harness, "s3"),
            (ec2_harness, "ec2"),
        ):
            calls = []

            def fake_client(service_name, *args, **kwargs):
                calls.append(service_name)
                return object()

            with mock.patch.object(harness.boto3, "client", side_effect=fake_client):
                with harness._aws_client_guard():
                    harness.boto3.client(allowed)
                    with self.assertRaises(harness.HarnessError):
                        harness.boto3.client("lightsail")
            self.assertEqual(calls, [allowed])

    def test_relational_runner_refuses_cleanup_without_apply_before_aws_client(self):
        with mock.patch.object(
            relational_harness, "CLEANUP", True
        ), mock.patch.object(
            relational_harness, "APPLY", False
        ), mock.patch.object(
            relational_harness.boto3,
            "client",
            side_effect=AssertionError("AWS client must not be constructed"),
        ), mock.patch("builtins.print"):
            self.assertEqual(relational_harness.main(), 1)

    def test_relational_runner_requires_explicit_credentials_before_aws_client(self):
        with mock.patch.dict(
            os.environ,
            {"AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": ""},
            clear=False,
        ), mock.patch.object(
            relational_harness, "CLEANUP", False
        ), mock.patch.object(
            relational_harness, "APPLY", False
        ), mock.patch.object(
            relational_harness.boto3,
            "client",
            side_effect=AssertionError("AWS client must not be constructed"),
        ), mock.patch("builtins.print"):
            self.assertEqual(relational_harness.main(), 1)

    def test_client_construction_is_static_allowlisted(self):
        expected = {
            "scripts/aws_s3_dynamodb_rds_e2e.py": {
                "rds",
                "ec2",
                "s3",
                "dynamodb",
                "backup",
                "iam",
                "sts",
            },
            "scripts/aws_ec2_ebs_e2e.py": {"ec2", "sts"},
        }
        for name, services_expected in expected.items():
            source = (ROOT / name).read_text(encoding="utf-8")
            tree = ast.parse(source)
            services = set()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func
                if (
                    isinstance(function, ast.Attribute)
                    and function.attr == "client"
                    and isinstance(function.value, ast.Name)
                    and function.value.id == "boto3"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                ):
                    services.add(node.args[0].value)
            self.assertEqual(services, services_expected)
            self.assertNotIn("boto3.client(\"lightsail\"", source.lower())

    def test_rds_and_ec2_main_validate_cidrs_before_first_provider_write(self):
        with tempfile.TemporaryDirectory() as directory:
            clients = {
                service: mock.Mock(name=f"{service}_client")
                for service in relational_harness._ALLOWED_AWS_CLIENT_SERVICES
            }
            clients["sts"].get_caller_identity.return_value = {
                "Account": "123456789012",
                "Arn": "arn:aws:iam::123456789012:user/e2e",
            }
            with mock.patch.dict(
                os.environ,
                {
                    "AWS_E2E_RDS_CIDRS": "",
                    "AWS_ACCESS_KEY_ID": "offline-test-access-key",
                    "AWS_SECRET_ACCESS_KEY": "offline-test-secret-key",
                    "BACKUPSHEEP_E2E_RUN_ID": "bs-e2e-test-1234",
                    "BACKUPSHEEP_E2E_LEDGER_PATH": str(Path(directory) / "aws.json"),
                },
                clear=False,
            ), mock.patch.object(
                relational_harness.boto3,
                "client",
                side_effect=lambda service, *args, **kwargs: clients[service],
            ), mock.patch.object(
                relational_harness, "PREFIX", "bs-e2e-test-1234"
            ), mock.patch.object(
                relational_harness, "APPLY", True
            ), mock.patch.object(
                relational_harness, "RESUME", False
            ), mock.patch.object(
                relational_harness, "CLEANUP", False
            ), mock.patch.object(
                relational_harness, "_exact_preflight", return_value={}
            ), mock.patch("builtins.print"):
                self.assertEqual(relational_harness.main(), 1)
            clients["iam"].create_role.assert_not_called()
            clients["backup"].create_backup_vault.assert_not_called()
            clients["ec2"].create_security_group.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            sts = mock.Mock()
            sts.get_caller_identity.return_value = {
                "Account": "123456789012",
                "Arn": "arn:aws:iam::123456789012:user/e2e",
            }
            ec2 = mock.Mock()
            with mock.patch.dict(
                os.environ,
                {
                    "AWS_E2E_WEB_CIDRS": "0.0.0.0/0",
                    "AWS_E2E_SSH_CIDRS": "192.0.2.7/32",
                    "AWS_ACCESS_KEY_ID": "offline-test-access-key",
                    "AWS_SECRET_ACCESS_KEY": "offline-test-secret-key",
                    "BACKUPSHEEP_E2E_RUN_ID": "bs-e2e-test-1234",
                    "BACKUPSHEEP_E2E_LEDGER_PATH": str(Path(directory) / "aws.json"),
                },
                clear=False,
            ), mock.patch.object(
                ec2_harness.boto3,
                "client",
                side_effect=lambda service, *args, **kwargs: {
                    "sts": sts,
                    "ec2": ec2,
                }[service],
            ), mock.patch.object(ec2_harness, "APPLY", True), mock.patch.object(
                ec2_harness, "CLEANUP", False
            ), mock.patch.object(
                ec2_harness,
                "_preflight",
                return_value=("vpc-test", "subnet-test", "us-east-2a", {}),
            ):
                exit_code, report = ec2_harness.main()
                self.assertEqual(exit_code, 1)
                self.assertEqual(report["status"], "FAIL")
                self.assertIn("world-open CIDR", report["error"])
            ec2.create_security_group.assert_not_called()
            ec2.authorize_security_group_ingress.assert_not_called()

    def test_read_only_and_cleanup_modes_do_not_require_runner_cidrs(self):
        # CIDRs authorize only new ingress. Their absence must not block a
        # read-only baseline or ownership-scoped cleanup after the runner moves.
        source = (ROOT / "scripts/aws_ec2_ebs_e2e.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        main = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        validation_lines = [
            node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_validated_cidrs"
        ]
        read_only_branch = next(
            node
            for node in ast.walk(main)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.UnaryOp)
            and isinstance(node.test.op, ast.Not)
            and isinstance(node.test.operand, ast.Name)
            and node.test.operand.id == "APPLY"
        )
        cleanup_branch = next(
            node
            for node in ast.walk(main)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "CLEANUP"
        )
        self.assertEqual(len(validation_lines), 2)
        # Both validations are deliberately below the early read-only and
        # cleanup return branches in source order.
        self.assertGreater(min(validation_lines), read_only_branch.end_lineno)
        self.assertGreater(min(validation_lines), cleanup_branch.end_lineno)

        with tempfile.TemporaryDirectory() as directory:
            clients = {
                service: mock.Mock(name=f"{service}_client")
                for service in relational_harness._ALLOWED_AWS_CLIENT_SERVICES
            }
            clients["sts"].get_caller_identity.return_value = {
                "Account": "123456789012",
                "Arn": "arn:aws:iam::123456789012:user/e2e",
            }
            with mock.patch.dict(
                os.environ,
                {
                    "AWS_E2E_RDS_CIDRS": "",
                    "AWS_ACCESS_KEY_ID": "offline-test-access-key",
                    "AWS_SECRET_ACCESS_KEY": "offline-test-secret-key",
                    "BACKUPSHEEP_E2E_RUN_ID": "bs-e2e-test-1234",
                    "BACKUPSHEEP_E2E_LEDGER_PATH": str(Path(directory) / "aws.json"),
                },
                clear=False,
            ), mock.patch.object(
                relational_harness.boto3,
                "client",
                side_effect=lambda service, *args, **kwargs: clients[service],
            ), mock.patch.object(
                relational_harness, "PREFIX", "bs-e2e-test-1234"
            ), mock.patch.object(
                relational_harness, "APPLY", False
            ), mock.patch.object(
                relational_harness, "RESUME", False
            ), mock.patch.object(
                relational_harness, "CLEANUP", False
            ), mock.patch.object(
                relational_harness, "_exact_preflight", return_value={}
            ), mock.patch("builtins.print"):
                self.assertEqual(relational_harness.main(), 0)
            clients["iam"].create_role.assert_not_called()
