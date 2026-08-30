"""Offline safety tests for the Oracle fixture compartment/network harness."""

import io
import json
import hashlib
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from scripts.oracle_test_compartment_e2e import (
    DEFAULT_DATABASE_PORTS,
    KIND_COMPARTMENT,
    KIND_DEFAULT_DHCP_OPTIONS,
    KIND_DEFAULT_ROUTE_TABLE,
    KIND_DEFAULT_SECURITY_LIST,
    KIND_INTERNET_GATEWAY,
    KIND_ROUTE_TABLE,
    KIND_SECURITY_LIST,
    KIND_SUBNET,
    KIND_VCN,
    TAG_KIND,
    TAG_OWNED,
    TAG_RUN,
    HarnessConfig,
    HarnessError,
    OracleTestCompartmentHarness,
    _write_output,
    iter_oci_pages,
    main,
)


def response(data=None, *, status=200, next_page=None):
    return SimpleNamespace(data=data, status=status, opc_next_page=next_page, headers={})


class FakeNotFound(Exception):
    status = 404
    code = "NotFound"


class FakeTimeout(Exception):
    status = 504
    code = ""


class FakeModel:
    def __init__(self, **values):
        self.__dict__.update(values)


FAKE_MODELS = SimpleNamespace(
    CreateCompartmentDetails=FakeModel,
    CreateVcnDetails=FakeModel,
    CreateInternetGatewayDetails=FakeModel,
    CreateRouteTableDetails=FakeModel,
    RouteRule=FakeModel,
    CreateSecurityListDetails=FakeModel,
    IngressSecurityRule=FakeModel,
    EgressSecurityRule=FakeModel,
    TcpOptions=FakeModel,
    UdpOptions=FakeModel,
    PortRange=FakeModel,
    CreateSubnetDetails=FakeModel,
)


class MemoryIdentity:
    def __init__(self, tenancy_id, *, availability_domain="AD-1"):
        self.tenancy_id = tenancy_id
        self.availability_domain = availability_domain
        self.compartments = {}
        self.create_calls = 0
        self.delete_calls = []
        self.lose_next_create_response = False

    def get_tenancy(self, tenancy_id):
        if tenancy_id != self.tenancy_id:
            raise FakeNotFound()
        return response(SimpleNamespace(id=self.tenancy_id, name="Personal"))

    def list_availability_domains(self, compartment_id):
        assert compartment_id == self.tenancy_id
        return response([SimpleNamespace(name=self.availability_domain)])

    def list_compartments(self, compartment_id, **_kwargs):
        return response(
            [
                value
                for value in self.compartments.values()
                if value.compartment_id == compartment_id
            ]
        )

    def list_policies(self, compartment_id, **_kwargs):
        return response([])

    def list_users(self, compartment_id, **_kwargs):
        return response([])

    def list_groups(self, compartment_id, **_kwargs):
        return response([])

    def list_user_group_memberships(self, compartment_id, **_kwargs):
        return response([])

    def list_customer_secret_keys(self, user_id):
        return response([])

    def get_compartment(self, compartment_id):
        if compartment_id == self.tenancy_id:
            return response(SimpleNamespace(id=self.tenancy_id, name="Personal"))
        try:
            return response(self.compartments[compartment_id])
        except KeyError as error:
            raise FakeNotFound() from error

    def create_compartment(self, *, create_compartment_details, **_kwargs):
        self.create_calls += 1
        resource = SimpleNamespace(
            id="ocid1.compartment.oc1..fixturechild",
            name=create_compartment_details.name,
            compartment_id=create_compartment_details.compartment_id,
            lifecycle_state="ACTIVE",
            freeform_tags=create_compartment_details.freeform_tags,
        )
        self.compartments[resource.id] = resource
        if self.lose_next_create_response:
            self.lose_next_create_response = False
            raise FakeTimeout("lost response")
        return response(resource, status=200)

    def delete_compartment(self, *, compartment_id):
        self.delete_calls.append(compartment_id)
        self.compartments.pop(compartment_id, None)
        return response(None, status=202)


class MemoryNetwork:
    def __init__(self):
        self.resources = {
            KIND_VCN: {},
            KIND_INTERNET_GATEWAY: {},
            KIND_ROUTE_TABLE: {},
            KIND_SECURITY_LIST: {},
            KIND_SUBNET: {},
            KIND_DEFAULT_ROUTE_TABLE: {},
            KIND_DEFAULT_SECURITY_LIST: {},
            KIND_DEFAULT_DHCP_OPTIONS: {},
        }
        self.create_calls = {
            kind: 0
            for kind in (
                KIND_VCN,
                KIND_INTERNET_GATEWAY,
                KIND_ROUTE_TABLE,
                KIND_SECURITY_LIST,
                KIND_SUBNET,
            )
        }
        self.delete_calls = []
        self.default_delete_calls = []
        self.cascade_defaults_on_vcn_delete = True
        self.inject_foreign_vcn_on_first_list = False
        self.foreign_vcn_name = "bs-e2e-foreign-vcn"
        self._foreign_added = False
        self.lose_next_create_kind = None
        self.id_by_kind = {
            KIND_VCN: "ocid1.vcn.oc1.iad..fixturevcn",
            KIND_INTERNET_GATEWAY: "ocid1.internetgateway.oc1.iad..fixtureigw",
            KIND_ROUTE_TABLE: "ocid1.routetable.oc1.iad..fixturert",
            KIND_SECURITY_LIST: "ocid1.securitylist.oc1.iad..fixturesl",
            KIND_SUBNET: "ocid1.subnet.oc1.iad..fixturesubnet",
            KIND_DEFAULT_ROUTE_TABLE: "ocid1.routetable.oc1.iad..defaultfixture",
            KIND_DEFAULT_SECURITY_LIST: "ocid1.securitylist.oc1.iad..defaultfixture",
            KIND_DEFAULT_DHCP_OPTIONS: "ocid1.dhcpoptions.oc1.iad..defaultfixture",
        }

    def _list(self, kind, *, compartment_id, vcn_id=None, **_kwargs):
        if (
            kind == KIND_VCN
            and self.inject_foreign_vcn_on_first_list
            and not self._foreign_added
        ):
            self._foreign_added = True
            foreign = SimpleNamespace(
                id="ocid1.vcn.oc1.iad..foreignvcn",
                display_name=self.foreign_vcn_name,
                compartment_id=compartment_id,
                lifecycle_state="AVAILABLE",
                cidr_blocks=["10.249.0.0/16"],
                freeform_tags={TAG_RUN: "foreign-run", TAG_OWNED: "true", TAG_KIND: KIND_VCN},
            )
            self.resources[KIND_VCN][foreign.id] = foreign
        rows = list(self.resources[kind].values())
        rows = [row for row in rows if row.compartment_id == compartment_id]
        if vcn_id is not None:
            rows = [row for row in rows if getattr(row, "vcn_id", None) == vcn_id]
        return response(rows)

    def list_vcns(self, *, compartment_id, **kwargs):
        return self._list(KIND_VCN, compartment_id=compartment_id, **kwargs)

    def list_internet_gateways(self, *, compartment_id, **kwargs):
        return self._list(KIND_INTERNET_GATEWAY, compartment_id=compartment_id, **kwargs)

    def list_route_tables(self, *, compartment_id, **kwargs):
        rows = self._list(KIND_ROUTE_TABLE, compartment_id=compartment_id, **kwargs).data
        defaults = self._list(KIND_DEFAULT_ROUTE_TABLE, compartment_id=compartment_id, **kwargs).data
        return response(rows + defaults)

    def list_security_lists(self, *, compartment_id, **kwargs):
        rows = self._list(KIND_SECURITY_LIST, compartment_id=compartment_id, **kwargs).data
        defaults = self._list(KIND_DEFAULT_SECURITY_LIST, compartment_id=compartment_id, **kwargs).data
        return response(rows + defaults)

    def list_subnets(self, *, compartment_id, **kwargs):
        return self._list(KIND_SUBNET, compartment_id=compartment_id, **kwargs)

    def list_dhcp_options(self, *, compartment_id, **kwargs):
        return self._list(KIND_DEFAULT_DHCP_OPTIONS, compartment_id=compartment_id, **kwargs)

    def list_nat_gateways(self, *, compartment_id, **_kwargs):
        return response([])

    def list_service_gateways(self, *, compartment_id, **_kwargs):
        return response([])

    def list_local_peering_gateways(self, *, compartment_id, **_kwargs):
        return response([])

    def list_network_security_groups(self, *, compartment_id, **_kwargs):
        return response([])

    def list_drgs(self, *, compartment_id, **_kwargs):
        return response([])

    def list_drg_attachments(self, *, compartment_id, **_kwargs):
        return response([])

    def list_ip_sec_connections(self, *, compartment_id, **_kwargs):
        return response([])

    def list_virtual_circuits(self, *, compartment_id, **_kwargs):
        return response([])

    def list_public_ips(self, *, compartment_id, scope, **_kwargs):
        return response([])

    def _get(self, kind, resource_id):
        try:
            return response(self.resources[kind][resource_id])
        except KeyError as error:
            raise FakeNotFound() from error

    def get_vcn(self, *, vcn_id):
        return self._get(KIND_VCN, vcn_id)

    def get_internet_gateway(self, *, ig_id):
        return self._get(KIND_INTERNET_GATEWAY, ig_id)

    def get_route_table(self, *, rt_id):
        if rt_id in self.resources[KIND_DEFAULT_ROUTE_TABLE]:
            return self._get(KIND_DEFAULT_ROUTE_TABLE, rt_id)
        return self._get(KIND_ROUTE_TABLE, rt_id)

    def get_security_list(self, *, security_list_id):
        if security_list_id in self.resources[KIND_DEFAULT_SECURITY_LIST]:
            return self._get(KIND_DEFAULT_SECURITY_LIST, security_list_id)
        return self._get(KIND_SECURITY_LIST, security_list_id)

    def get_subnet(self, *, subnet_id):
        return self._get(KIND_SUBNET, subnet_id)

    def get_dhcp_options(self, *, dhcp_id):
        return self._get(KIND_DEFAULT_DHCP_OPTIONS, dhcp_id)

    def _create(self, kind, details):
        self.create_calls[kind] += 1
        values = {
            "id": self.id_by_kind[kind],
            "display_name": details.display_name,
            "compartment_id": details.compartment_id,
            "lifecycle_state": "AVAILABLE",
            "freeform_tags": details.freeform_tags,
        }
        if kind == KIND_VCN:
            values["cidr_blocks"] = details.cidr_blocks
        elif kind == KIND_INTERNET_GATEWAY:
            values.update(vcn_id=details.vcn_id, is_enabled=details.is_enabled)
        elif kind == KIND_ROUTE_TABLE:
            values.update(vcn_id=details.vcn_id, route_rules=details.route_rules)
        elif kind == KIND_SECURITY_LIST:
            values.update(
                vcn_id=details.vcn_id,
                ingress_security_rules=details.ingress_security_rules,
                egress_security_rules=details.egress_security_rules,
            )
        elif kind == KIND_SUBNET:
            values.update(
                vcn_id=details.vcn_id,
                cidr_block=details.cidr_block,
                route_table_id=details.route_table_id,
                security_list_ids=details.security_list_ids,
                prohibit_public_ip_on_vnic=details.prohibit_public_ip_on_vnic,
            )
        resource = SimpleNamespace(**values)
        if kind == KIND_VCN:
            default_values = {
                KIND_DEFAULT_ROUTE_TABLE: {
                    "display_name": f"Default Route Table for {details.display_name}",
                    "route_rules": [],
                },
                KIND_DEFAULT_SECURITY_LIST: {
                    "display_name": f"Default Security List for {details.display_name}",
                    "ingress_security_rules": [],
                    "egress_security_rules": [],
                },
                KIND_DEFAULT_DHCP_OPTIONS: {
                    "display_name": f"Default DHCP Options for {details.display_name}",
                },
            }
            for default_kind, default_fields in default_values.items():
                default = SimpleNamespace(
                    id=self.id_by_kind[default_kind],
                    compartment_id=details.compartment_id,
                    vcn_id=resource.id,
                    lifecycle_state="AVAILABLE",
                    freeform_tags={},
                    **default_fields,
                )
                self.resources[default_kind][default.id] = default
        self.resources[kind][resource.id] = resource
        if self.lose_next_create_kind == kind:
            self.lose_next_create_kind = None
            raise FakeTimeout("lost response")
        return response(resource, status=200)

    def create_vcn(self, *, create_vcn_details, **_kwargs):
        return self._create(KIND_VCN, create_vcn_details)

    def create_internet_gateway(self, *, create_internet_gateway_details, **_kwargs):
        return self._create(KIND_INTERNET_GATEWAY, create_internet_gateway_details)

    def create_route_table(self, *, create_route_table_details, **_kwargs):
        return self._create(KIND_ROUTE_TABLE, create_route_table_details)

    def create_security_list(self, *, create_security_list_details, **_kwargs):
        return self._create(KIND_SECURITY_LIST, create_security_list_details)

    def create_subnet(self, *, create_subnet_details, **_kwargs):
        return self._create(KIND_SUBNET, create_subnet_details)

    def _delete(self, kind, resource_id):
        self.delete_calls.append((kind, resource_id))
        self.resources[kind].pop(resource_id, None)
        return response(None, status=202)

    def delete_vcn(self, *, vcn_id):
        result = self._delete(KIND_VCN, vcn_id)
        if self.cascade_defaults_on_vcn_delete:
            for kind in (
                KIND_DEFAULT_ROUTE_TABLE,
                KIND_DEFAULT_SECURITY_LIST,
                KIND_DEFAULT_DHCP_OPTIONS,
            ):
                self.resources[kind].clear()
        return result

    def delete_internet_gateway(self, *, ig_id):
        return self._delete(KIND_INTERNET_GATEWAY, ig_id)

    def delete_route_table(self, *, rt_id):
        if rt_id in self.resources[KIND_DEFAULT_ROUTE_TABLE]:
            self.default_delete_calls.append((KIND_DEFAULT_ROUTE_TABLE, rt_id))
            raise AssertionError("OCI default route tables cannot be deleted directly")
        return self._delete(KIND_ROUTE_TABLE, rt_id)

    def delete_security_list(self, *, security_list_id):
        if security_list_id in self.resources[KIND_DEFAULT_SECURITY_LIST]:
            self.default_delete_calls.append(
                (KIND_DEFAULT_SECURITY_LIST, security_list_id)
            )
            raise AssertionError("OCI default security lists cannot be deleted directly")
        return self._delete(KIND_SECURITY_LIST, security_list_id)

    def delete_subnet(self, *, subnet_id):
        return self._delete(KIND_SUBNET, subnet_id)

    def delete_dhcp_options(self, *, dhcp_id):
        self.default_delete_calls.append((KIND_DEFAULT_DHCP_OPTIONS, dhcp_id))
        raise AssertionError("OCI default DHCP options cannot be deleted directly")


class OracleTestCompartmentHarnessTests(SimpleTestCase):
    tenancy_id = "ocid1.tenancy.oc1..backupsheeptest"
    run_id = "bs-oracle-net-0001"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = MemoryIdentity(self.tenancy_id)
        self.network = MemoryNetwork()

    def environment(self, **overrides):
        values = {
            "BACKUPSHEEP_E2E_RUN_ID": self.run_id,
            "BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH": str(self.root / "network-ledger.json"),
            "BACKUPSHEEP_E2E_LEDGER_PATH": str(self.root / "ui-ledger.json"),
            "ORACLE_E2E_RUNTIME_SCOPE_FILE": str(self.root / "runtime-scope.json"),
            "ORACLE_E2E_UI_CLEANUP_RECEIPT": str(self.root / "ui-cleanup-receipt.json"),
            "BACKUPSHEEP_E2E_APPLY": "YES",
            "BACKUPSHEEP_E2E_CLEANUP": "YES",
            "OCI_CLI_PROFILE": "BACKUPSHEEP_E2E",
            "OCI_CLI_CONFIG_FILE": str(self.root / "oci-config"),
            "ORACLE_E2E_ALLOWED_TENANCY_OCID": self.tenancy_id,
            "ORACLE_E2E_AVAILABILITY_DOMAIN": "AD-1",
            "ORACLE_E2E_CALLER_CIDRS": "198.51.100.10/32,2001:db8::10/128",
            "ORACLE_E2E_DATABASE_PORTS": "1521,3306,5432",
        }
        values.update(overrides)
        return values

    def config(self, **overrides):
        return HarnessConfig.from_environment(self.environment(**overrides))

    def clients(self):
        empty = mock.MagicMock()
        for name in (
            "list_instances",
            "list_images",
            "list_vnic_attachments",
            "list_volume_attachments",
            "list_boot_volume_attachments",
            "list_volumes",
            "list_boot_volumes",
            "list_volume_backups",
            "list_boot_volume_backups",
            "list_buckets",
            "list_db_systems",
            "list_autonomous_databases",
            "list_load_balancers",
            "list_network_load_balancers",
            "list_file_systems",
            "list_mount_targets",
            "list_clusters",
            "list_node_pools",
            "list_container_instances",
            "list_applications",
            "list_tables",
        ):
            getattr(empty, name).return_value = response([])
        empty.get_namespace.return_value = response("namespace")
        return {
            "_config": {"tenancy": self.tenancy_id, "region": "us-ashburn-1"},
            "_models": FAKE_MODELS,
            "identity": self.identity,
            "network": self.network,
            "compute": empty,
            "block": empty,
            "object": empty,
            "database": empty,
            "mysql": empty,
            "postgresql": empty,
            "load_balancer": empty,
            "network_load_balancer": empty,
            "file_storage": empty,
            "container_engine": empty,
            "container_instances": empty,
            "functions": empty,
            "nosql": empty,
        }

    def harness(self, **overrides):
        return OracleTestCompartmentHarness(
            self.config(**overrides),
            clients=self.clients(),
            sleep=lambda _seconds: None,
        )

    def authorize_network_cleanup(self, harness, *, retained_credentials=False):
        runtime_path = harness.config.runtime_scope_path
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        terminal = [
            {
                "kind": "source_instance",
                "resource_id": "ocid1.instance.oc1.iad.terminal",
                "state": "deleted",
            }
        ]
        retained_rows = []
        if retained_credentials:
            retained_specs = [
                (
                    "iam_user",
                    "ocid1.user.oc1..retained",
                    "retained-user",
                    {"compartment_id": self.tenancy_id, "tags": {TAG_RUN: self.run_id}},
                ),
                (
                    "iam_group",
                    "ocid1.group.oc1..retained",
                    "retained-group",
                    {"compartment_id": self.tenancy_id, "tags": {TAG_RUN: self.run_id}},
                ),
                (
                    "iam_policy",
                    "ocid1.policy.oc1..retained",
                    "retained-policy",
                    {"compartment_id": runtime["compartment_id"], "tags": {TAG_RUN: self.run_id}},
                ),
                (
                    "iam_membership",
                    "ocid1.usergroupmembership.oc1..retained",
                    "",
                    {
                        "compartment_id": self.tenancy_id,
                        "relationships": {
                            "user_id": "ocid1.user.oc1..retained",
                            "group_id": "ocid1.group.oc1..retained",
                        },
                    },
                ),
                (
                    "customer_secret_key",
                    "A" * 40,
                    "retained-key",
                    {
                        "compartment_id": "",
                        "relationships": {
                            "user_id": "ocid1.user.oc1..retained"
                        },
                    },
                ),
            ]
            for kind, resource_id, name, ownership in retained_specs:
                terminal.append(
                    {
                        "kind": kind,
                        "resource_id": resource_id,
                        "state": "user_retained",
                    }
                )
                retained_rows.append(
                    {
                        "kind": kind,
                        "resource_id": resource_id,
                        "name": name,
                        "ownership": ownership,
                        "source_witness": "retained",
                        "created_at": "2026-08-15T00:00:00+00:00",
                        "cleanup_state": "eligible",
                        "cleanup_error": "",
                    }
                )
        ui_ledger = {
            "schema": 1,
            "provider": "oracle_cloud",
            "run_id": self.run_id,
            "scope": (
                f"oci:{harness.config.profile}:{runtime['compartment_id']}:"
                f"{harness.config.availability_domain}"
            ),
            "created_at": "2026-08-15T00:00:00+00:00",
            "resources": [
                {
                    **terminal[0],
                    "name": "terminal",
                    "ownership": {"run_id": self.run_id},
                    "source_witness": "source",
                    "created_at": "2026-08-15T00:00:00+00:00",
                    "cleanup_state": "deleted",
                    "cleanup_error": "",
                },
                *retained_rows,
            ],
        }
        ui_path = harness.config.ui_ledger_path
        ui_path.write_text(json.dumps(ui_ledger), encoding="utf-8")
        os.chmod(ui_path, 0o600)
        ui_digest = hashlib.sha256(ui_path.read_bytes()).hexdigest()
        runtime_digest = hashlib.sha256(
            json.dumps(runtime, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        receipt = {
            "schema": 1,
            "run_id": self.run_id,
            "tenancy_id": self.tenancy_id,
            "compartment_id": runtime["compartment_id"],
            "runtime_scope_digest": runtime_digest,
            "ui_ledger_path": str(ui_path),
            "ui_ledger_digest": ui_digest,
            "terminal_resources": terminal,
        }
        receipt_path = harness.config.ui_cleanup_receipt_path
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        os.chmod(receipt_path, 0o600)
        return receipt_path

    def test_plan_is_inert_and_does_not_load_profile_or_initialize_ledger(self):
        harness = self.harness(BACKUPSHEEP_E2E_APPLY="NO")
        with mock.patch.object(harness, "_load_clients", side_effect=AssertionError("provider call")):
            result = harness.plan()
        self.assertFalse(result["live_calls"])
        self.assertFalse(result["profile_loaded"])
        self.assertFalse(result["ledger_initialized"])
        self.assertFalse((self.root / "network-ledger.json").exists())

    def test_cli_empty_environment_plan_short_circuits_config_and_harness(self):
        output = io.StringIO()
        with mock.patch.object(
            HarnessConfig,
            "from_environment",
            side_effect=AssertionError("config must not load during plan"),
        ), mock.patch.object(
            OracleTestCompartmentHarness,
            "__init__",
            side_effect=AssertionError("harness must not construct during plan"),
        ), redirect_stdout(output):
            status = main(["--phase", "plan"], environment={})
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["phase"], "PLAN")
        self.assertFalse(result["live_calls"])
        self.assertFalse(result["config_loaded"])
        self.assertFalse(result["sdk_constructed"])

    def test_generic_output_is_create_only_protected_symlink_safe_and_parent_pinned(self):
        output_path = self.root / "plan-output.json"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(
                main(
                    ["--phase", "plan", "--output", str(output_path)],
                    environment={},
                ),
                0,
            )
        before = output_path.read_bytes()
        self.assertEqual(os.stat(output_path).st_mode & 0o777, 0o600)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    ["--phase", "plan", "--output", str(output_path)],
                    environment={},
                ),
                2,
            )
        self.assertEqual(output_path.read_bytes(), before)

        nested_output = self.root / "new-output-parent" / "nested" / "result.json"
        _write_output(nested_output, {"phase": "PLAN"})
        self.assertEqual(nested_output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(nested_output.parent.stat().st_mode & 0o777, 0o700)

        protected = self.root / "protected-ledger.json"
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    ["--phase", "plan", "--output", str(protected)],
                    environment={
                        "BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH": str(protected)
                    },
                ),
                2,
            )
        self.assertFalse(protected.exists())

        real_parent = self.root / "real-output-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked-output-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "--phase",
                        "plan",
                        "--output",
                        str(linked_parent / "result.json"),
                    ],
                    environment={},
                ),
                2,
            )

        swap_parent = self.root / "parent-swap"
        swap_parent.mkdir(mode=0o700)
        swap_target = swap_parent / "result.json"
        real_stat = os.stat
        checks = {"count": 0}

        def swapped(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if Path(path) == swap_parent and kwargs.get("follow_symlinks") is False:
                checks["count"] += 1
                if checks["count"] == 2:
                    return SimpleNamespace(
                        st_mode=result.st_mode,
                        st_dev=result.st_dev + 1,
                        st_ino=result.st_ino,
                    )
            return result

        with mock.patch(
            "scripts.oracle_test_compartment_e2e.os.stat", side_effect=swapped
        ):
            with self.assertRaisesRegex(HarnessError, "parent directory changed"):
                _write_output(swap_target, {"phase": "PLAN"})
        self.assertFalse(swap_target.exists())

    def test_cidr_parser_rejects_world_and_broad_networks(self):
        for value in ("0.0.0.0/0", "198.51.100.0/24", "2001:db8::/64"):
            with self.subTest(value=value), self.assertRaisesRegex(HarnessError, "host"):
                self.config(ORACLE_E2E_CALLER_CIDRS=value)

    def test_cidr_parser_accepts_only_exact_ipv4_and_ipv6_hosts(self):
        config = self.config(ORACLE_E2E_CALLER_CIDRS="198.51.100.11/32,2001:db8::11/128")
        self.assertEqual(config.caller_cidrs, ("198.51.100.11/32", "2001:db8::11/128"))

    def test_config_rejects_wrong_region_and_repo_ledger(self):
        with self.assertRaisesRegex(HarnessError, "us-ashburn-1"):
            self.config(ORACLE_E2E_REGION="us-phoenix-1")
        with self.assertRaisesRegex(HarnessError, "outside the repository"):
            self.config(BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH=str(Path(__file__).parents[2] / "unsafe.json"))
        with self.assertRaisesRegex(HarnessError, "four distinct paths"):
            self.config(
                ORACLE_E2E_RUNTIME_SCOPE_FILE=str(self.root / "ui-ledger.json")
            )
        real_parent = self.root / "real-protected-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked-protected-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(HarnessError, "symlinked"):
            self.config(
                BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH=str(
                    linked_parent / "network-ledger.json"
                )
            )

    def test_mutations_require_apply_and_cleanup_requires_cleanup_gate(self):
        harness = self.harness(BACKUPSHEEP_E2E_APPLY="NO")
        with self.assertRaisesRegex(HarnessError, "APPLY"):
            harness.provision()
        harness = self.harness(BACKUPSHEEP_E2E_CLEANUP="NO")
        with self.assertRaisesRegex(HarnessError, "CLEANUP"):
            harness.cleanup()

    def test_profile_tenancy_must_match_before_resource_creation(self):
        clients = self.clients()
        clients["_config"] = {"tenancy": "ocid1.tenancy.oc1..foreign", "region": "us-ashburn-1"}
        harness = OracleTestCompartmentHarness(self.config(), clients=clients, sleep=lambda _seconds: None)
        with self.assertRaisesRegex(HarnessError, "allowed tenancy"):
            harness.provision()
        self.assertEqual(self.identity.create_calls, 0)

    def test_cursor_pagination_is_complete_and_repeated_cursor_fails(self):
        listing = mock.Mock(
            side_effect=[
                response([{"id": "one"}], next_page="cursor-2"),
                response([{"id": "two"}]),
            ]
        )
        self.assertEqual(list(iter_oci_pages(listing, compartment_id="root")), [{"id": "one"}, {"id": "two"}])
        self.assertNotIn("page", listing.call_args_list[0].kwargs)
        self.assertEqual(listing.call_args_list[1].kwargs["page"], "cursor-2")
        repeated = mock.Mock(
            side_effect=[response([], next_page="same"), response([], next_page="same")]
        )
        with self.assertRaisesRegex(HarnessError, "repeated"):
            list(iter_oci_pages(repeated, compartment_id="root"))

    def test_provision_creates_one_exact_owned_network_graph_and_minimal_facts(self):
        harness = self.harness()
        result = harness.provision()
        self.assertEqual(result["phase"], "PROVISIONED")
        self.assertEqual(
            set(result), {"phase", "run_id", "oracle_harness_environment"}
        )
        facts = result["oracle_harness_environment"]
        self.assertEqual(
            set(facts),
            {
                "ORACLE_E2E_ALLOWED_TENANCY_OCID",
                "ORACLE_E2E_COMPARTMENT_OCID",
                "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID",
                "ORACLE_E2E_SUBNET_OCID",
                "ORACLE_E2E_AVAILABILITY_DOMAIN",
            },
        )
        self.assertEqual(len(harness.ledger.entries()), 9)
        self.assertEqual(self.identity.create_calls, 1)
        self.assertEqual(
            self.network.create_calls,
            {
                KIND_VCN: 1,
                KIND_INTERNET_GATEWAY: 1,
                KIND_ROUTE_TABLE: 1,
                KIND_SECURITY_LIST: 1,
                KIND_SUBNET: 1,
            },
        )
        security = next(iter(self.network.resources[KIND_SECURITY_LIST].values()))
        ingress = {
            (rule.source, rule.tcp_options.destination_port_range.min)
            for rule in security.ingress_security_rules
        }
        self.assertEqual(
            ingress,
            {
                (cidr, port)
                for cidr in self.config().caller_cidrs
                for port in (22, *DEFAULT_DATABASE_PORTS)
            },
        )
        tagged_rows = [
            row
            for row in harness.ledger.entries()
            if row["kind"]
            not in {
                KIND_DEFAULT_ROUTE_TABLE,
                KIND_DEFAULT_SECURITY_LIST,
                KIND_DEFAULT_DHCP_OPTIONS,
            }
        ]
        self.assertTrue(
            all(row["ownership"]["tags"][TAG_RUN] == self.run_id for row in tagged_rows)
        )

    def test_provision_writes_exact_private_runtime_scope_and_rejects_drift(self):
        harness = self.harness()
        harness.provision()
        path = harness.config.runtime_scope_path
        payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(
            set(payload),
            {
                "schema",
                "run_id",
                "profile",
                "tenancy_id",
                "compartment_id",
                "subnet_id",
                "availability_domain",
                "region",
                "ui_ledger_path",
                "network_ledger_path",
            },
        )
        self.assertNotIn("key", json.dumps(payload).casefold())
        payload["subnet_id"] = "ocid1.subnet.oc1.iad.foreign"
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(HarnessError, "network graph"):
            harness._load_runtime_scope_for_graph(harness._ledger_specs())
        create_calls = dict(self.network.create_calls)
        with (
            mock.patch.object(
                harness, "_load_clients", side_effect=AssertionError("provider read")
            ),
            self.assertRaisesRegex(HarnessError, "network graph"),
        ):
            harness.provision()
        self.assertEqual(self.network.create_calls, create_calls)

    def test_normalize_runtime_scope_is_local_private_and_refuses_symlinks_or_overwrite(self):
        harness = self.harness()
        source = self.root / "legacy-network-output.json"
        source.write_text(
            json.dumps(
                {
                    "phase": "PROVISIONED",
                    "run_id": self.run_id,
                    "oracle_harness_environment": {
                        "ORACLE_E2E_ALLOWED_TENANCY_OCID": self.tenancy_id,
                        "ORACLE_E2E_COMPARTMENT_OCID": "ocid1.compartment.oc1..fixturechild",
                        "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID": "ocid1.compartment.oc1..fixturechild",
                        "ORACLE_E2E_SUBNET_OCID": "ocid1.subnet.oc1.iad.fixturesubnet",
                        "ORACLE_E2E_AVAILABILITY_DOMAIN": "AD-1",
                    },
                }
            ),
            encoding="utf-8",
        )
        os.chmod(source, 0o600)
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("provider call")
        ):
            result = harness.normalize_runtime_scope(str(source))

        self.assertEqual(result["phase"], "RUNTIME_SCOPE_NORMALIZED")
        self.assertEqual(os.stat(harness.config.runtime_scope_path).st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_digest)
        with self.assertRaisesRegex(HarnessError, "already exists"):
            harness.normalize_runtime_scope(str(source))

        linked_runtime = self.root / "linked-runtime.json"
        linked_source = self.root / "linked-source.json"
        linked_source.symlink_to(source)
        linked_harness = OracleTestCompartmentHarness(
            self.config(
                BACKUPSHEEP_E2E_NETWORK_LEDGER_PATH=str(self.root / "linked-network-ledger.json"),
                BACKUPSHEEP_E2E_LEDGER_PATH=str(self.root / "linked-ui-ledger.json"),
                ORACLE_E2E_RUNTIME_SCOPE_FILE=str(linked_runtime),
                ORACLE_E2E_UI_CLEANUP_RECEIPT=str(self.root / "linked-receipt.json"),
            ),
            clients=self.clients(),
            sleep=lambda _seconds: None,
        )
        with self.assertRaisesRegex(HarnessError, "symlinked"):
            linked_harness.normalize_runtime_scope(str(linked_source))

    def test_lost_create_response_adopts_exact_resource_without_duplicate_create(self):
        self.identity.lose_next_create_response = True
        harness = self.harness()
        result = harness.provision()
        self.assertEqual(result["phase"], "PROVISIONED")
        self.assertEqual(self.identity.create_calls, 1)
        self.assertEqual(len(harness.ledger.entries(KIND_COMPARTMENT)), 1)
        self.assertFalse(harness.intents.pending())

    def test_foreign_reserved_name_blocks_create(self):
        harness = self.harness()
        self.network.foreign_vcn_name = harness.names[KIND_VCN]
        self.network.inject_foreign_vcn_on_first_list = True
        with self.assertRaisesRegex(HarnessError, "foreign"):
            harness.provision()
        self.assertEqual(self.network.create_calls[KIND_VCN], 0)

    def test_cleanup_blocks_foreign_dependency_before_any_delete(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        child_id = next(
            row["resource_id"]
            for row in harness.ledger.entries()
            if row["kind"] == KIND_COMPARTMENT
        )
        self.network.resources[KIND_VCN]["ocid1.vcn.oc1.iad..foreign"] = SimpleNamespace(
            id="ocid1.vcn.oc1.iad..foreign",
            display_name="operator-vcn",
            compartment_id=child_id,
            lifecycle_state="AVAILABLE",
            cidr_blocks=["10.250.0.0/16"],
            freeform_tags={},
        )
        with self.assertRaisesRegex(HarnessError, "unledgered"):
            harness.cleanup()
        self.assertEqual(self.network.delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])

    def test_cleanup_receipt_mismatch_blocks_before_provider_deletes(self):
        harness = self.harness()
        harness.provision()
        receipt_path = self.authorize_network_cleanup(harness)
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["runtime_scope_digest"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        os.chmod(receipt_path, 0o600)

        with self.assertRaisesRegex(HarnessError, "does not match"):
            harness.cleanup()

        self.assertEqual(self.network.delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])

    def test_cleanup_plan_reports_survivor_without_writes_and_cleanup_refuses_it(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        child_id = harness.ledger.entries(KIND_COMPARTMENT)[0]["resource_id"]
        survivor = SimpleNamespace(
            id="ocid1.instance.oc1.iad.unledgered",
            compartment_id=child_id,
            lifecycle_state="RUNNING",
        )
        harness._clients["compute"].list_instances.return_value = response([survivor])
        protected_paths = [
            harness.config.ledger_path,
            harness.config.runtime_scope_path,
            harness.config.ui_ledger_path,
            harness.config.ui_cleanup_receipt_path,
        ]
        before = {
            path: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in protected_paths
        }

        plan = harness.cleanup_plan()

        self.assertFalse(plan["cleanup_allowed"])
        self.assertEqual(
            plan["survivors"],
            [{"kind": "instance", "resource_id": survivor.id}],
        )
        self.assertEqual(
            before,
            {
                path: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
                for path in protected_paths
            },
        )
        with self.assertRaisesRegex(HarnessError, "surviving or unledgered"):
            harness.cleanup()
        self.assertEqual(self.network.delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])

    def test_retained_credential_receipt_allows_network_cleanup_but_keeps_compartment(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness, retained_credentials=True)
        child_id = harness.ledger.entries(KIND_COMPARTMENT)[0]["resource_id"]
        user = SimpleNamespace(
            id="ocid1.user.oc1..retained",
            lifecycle_state="ACTIVE",
            freeform_tags={TAG_RUN: self.run_id},
        )
        group = SimpleNamespace(
            id="ocid1.group.oc1..retained",
            lifecycle_state="ACTIVE",
            freeform_tags={TAG_RUN: self.run_id},
        )
        policy = SimpleNamespace(
            id="ocid1.policy.oc1..retained",
            compartment_id=child_id,
            lifecycle_state="ACTIVE",
            freeform_tags={TAG_RUN: self.run_id},
        )
        membership = SimpleNamespace(
            id="ocid1.usergroupmembership.oc1..retained",
            user_id=user.id,
            group_id=group.id,
            lifecycle_state="ACTIVE",
        )
        customer_key = SimpleNamespace(
            id="A" * 40,
            user_id=user.id,
            lifecycle_state="ACTIVE",
        )
        self.identity.list_users = mock.Mock(return_value=response([user]))
        self.identity.list_groups = mock.Mock(return_value=response([group]))
        self.identity.list_policies = mock.Mock(return_value=response([policy]))
        self.identity.list_user_group_memberships = mock.Mock(
            return_value=response([membership])
        )
        self.identity.list_customer_secret_keys = mock.Mock(
            return_value=response([customer_key])
        )

        plan = harness.cleanup_plan()

        self.assertTrue(plan["cleanup_allowed"])
        self.assertFalse(plan["compartment_delete_allowed"])
        self.assertEqual(plan["survivors"], [])
        self.assertEqual(len(plan["user_retained_resources"]), 5)

        result = harness.cleanup()

        self.assertEqual(
            result["phase"], "CLEANED_WITH_USER_RETAINED_CREDENTIALS"
        )
        self.assertEqual(
            result["results"][KIND_COMPARTMENT],
            "USER_RETAINED_CREDENTIAL_SCOPE",
        )
        self.assertIn(child_id, self.identity.compartments)
        self.assertEqual(self.identity.delete_calls, [])

        repeated = harness.cleanup()
        self.assertEqual(
            repeated["phase"], "CLEANED_WITH_USER_RETAINED_CREDENTIALS"
        )
        self.assertEqual(self.identity.delete_calls, [])

    def test_survivor_sweep_covers_managed_databases_and_fails_closed_on_missing_family(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        child_id = harness.ledger.entries(KIND_COMPARTMENT)[0]["resource_id"]
        database = SimpleNamespace(
            id="ocid1.dbsystem.oc1.iad.unledgered",
            compartment_id=child_id,
            lifecycle_state="AVAILABLE",
        )
        database_client = mock.MagicMock()
        database_client.list_db_systems.return_value = response([database])
        database_client.list_autonomous_databases.return_value = response([])
        harness._clients["database"] = database_client

        plan = harness.cleanup_plan()

        self.assertEqual(
            plan["survivors"],
            [{"kind": "database_system", "resource_id": database.id}],
        )
        with self.assertRaisesRegex(HarnessError, "surviving or unledgered"):
            harness.cleanup()
        self.assertEqual(self.network.delete_calls, [])

        database_client.list_db_systems.return_value = response([])
        harness._clients["nosql"].list_tables = None
        before = harness.config.ledger_path.read_bytes()
        with self.assertRaisesRegex(HarnessError, "required list method"):
            harness.cleanup_plan()
        self.assertEqual(harness.config.ledger_path.read_bytes(), before)

    def test_cleanup_stops_on_ownership_drift_before_delete(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        vcn = next(iter(self.network.resources[KIND_VCN].values()))
        vcn.freeform_tags[TAG_RUN] = "foreign-run"
        with self.assertRaisesRegex(HarnessError, "ownership"):
            harness.cleanup()
        self.assertEqual(self.network.delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])

    def test_cleanup_deletes_only_ledger_graph_and_proves_absence(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        result = harness.cleanup()
        self.assertEqual(result["phase"], "CLEANED")
        self.assertEqual(
            [kind for kind, _resource_id in self.network.delete_calls],
            [
                KIND_SUBNET,
                KIND_SECURITY_LIST,
                KIND_ROUTE_TABLE,
                KIND_INTERNET_GATEWAY,
                KIND_VCN,
            ],
        )
        self.assertEqual(self.network.default_delete_calls, [])
        self.assertEqual(len(self.identity.delete_calls), 1)
        self.assertEqual(self.network.resources, {kind: {} for kind in self.network.resources})
        self.assertEqual(self.identity.compartments, {})
        states = {
            row["kind"]: row["cleanup_state"] for row in harness.ledger.entries()
        }
        self.assertTrue(
            all(states[kind] == "absent" for kind in (
                KIND_DEFAULT_ROUTE_TABLE,
                KIND_DEFAULT_SECURITY_LIST,
                KIND_DEFAULT_DHCP_OPTIONS,
            ))
        )
        self.assertTrue(
            all(
                state == "deleted"
                for kind, state in states.items()
                if kind
                not in {
                    KIND_DEFAULT_ROUTE_TABLE,
                    KIND_DEFAULT_SECURITY_LIST,
                    KIND_DEFAULT_DHCP_OPTIONS,
                }
            )
        )
        with mock.patch.object(
            harness, "_load_clients", side_effect=AssertionError("provider reuse")
        ):
            repeated = harness.cleanup()
        self.assertEqual(repeated["phase"], "ALREADY_CLEANED")
        self.assertFalse(repeated["provider_mutations"])

    def test_cleanup_never_directly_deletes_provider_defaults(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        for kind in (
            KIND_DEFAULT_ROUTE_TABLE,
            KIND_DEFAULT_SECURITY_LIST,
            KIND_DEFAULT_DHCP_OPTIONS,
        ):
            with self.subTest(kind=kind):
                row = harness.ledger.entries(kind)[0]
                with self.assertRaisesRegex(
                    HarnessError,
                    "must never be deleted directly",
                ):
                    harness._delete_kind(kind, row)
                self.assertIn(row["resource_id"], self.network.resources[kind])
        self.assertEqual(self.network.default_delete_calls, [])

    def test_cleanup_stops_before_any_delete_on_provider_default_ownership_drift(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        default_route = next(
            iter(self.network.resources[KIND_DEFAULT_ROUTE_TABLE].values())
        )
        default_route.vcn_id = "ocid1.vcn.oc1.iad..foreign"

        with self.assertRaisesRegex(HarnessError, "ownership verification"):
            harness.cleanup()

        self.assertEqual(self.network.delete_calls, [])
        self.assertEqual(self.network.default_delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])

    def test_cleanup_blocks_compartment_delete_until_vcn_cascade_is_proven(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        self.network.cascade_defaults_on_vcn_delete = False

        with self.assertRaisesRegex(HarnessError, "did not prove provider-default"):
            harness.cleanup()

        self.assertEqual(self.network.default_delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])
        self.assertTrue(self.identity.compartments)
        self.assertTrue(self.network.resources[KIND_DEFAULT_ROUTE_TABLE])

    def test_unresolved_intent_blocks_cleanup_and_cannot_trigger_recreate(self):
        harness = self.harness()
        harness.provision()
        self.authorize_network_cleanup(harness)
        spec = harness._compartment_spec(self.identity)
        harness._put_intent(spec, source_witness=self.tenancy_id)
        with self.assertRaisesRegex(HarnessError, "unresolved"):
            harness.cleanup()
        self.assertEqual(self.identity.create_calls, 1)

    def test_config_and_output_never_include_secret_like_values(self):
        secret = "secret-private-key-canary"
        harness = self.harness()
        result = harness.provision()
        encoded = json.dumps(result)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("OCI_CLI_CONFIG_FILE", encoded)
