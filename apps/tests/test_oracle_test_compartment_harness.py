"""Offline safety tests for the Oracle fixture compartment/network harness."""

import io
import json
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
        return {
            "_config": {"tenancy": self.tenancy_id, "region": "us-ashburn-1"},
            "_models": FAKE_MODELS,
            "identity": self.identity,
            "network": self.network,
        }

    def harness(self, **overrides):
        return OracleTestCompartmentHarness(
            self.config(**overrides),
            clients=self.clients(),
            sleep=lambda _seconds: None,
        )

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

    def test_cleanup_stops_on_ownership_drift_before_delete(self):
        harness = self.harness()
        harness.provision()
        vcn = next(iter(self.network.resources[KIND_VCN].values()))
        vcn.freeform_tags[TAG_RUN] = "foreign-run"
        with self.assertRaisesRegex(HarnessError, "ownership"):
            harness.cleanup()
        self.assertEqual(self.network.delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])

    def test_cleanup_deletes_only_ledger_graph_and_proves_absence(self):
        harness = self.harness()
        harness.provision()
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

    def test_cleanup_never_directly_deletes_provider_defaults(self):
        harness = self.harness()
        harness.provision()
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
        self.network.cascade_defaults_on_vcn_delete = False

        with self.assertRaisesRegex(HarnessError, "did not prove provider-default"):
            harness.cleanup()

        self.assertEqual(self.network.default_delete_calls, [])
        self.assertEqual(self.identity.delete_calls, [])
        self.assertTrue(self.identity.compartments)
        self.assertTrue(self.network.resources[KIND_DEFAULT_ROUTE_TABLE])

    def test_unresolved_intent_blocks_cleanup_and_cannot_trigger_recreate(self):
        harness = self.harness()
        harness._stores_for_mutation()
        spec = harness._compartment_spec(self.identity)
        harness._put_intent(spec, source_witness=self.tenancy_id)
        with self.assertRaisesRegex(HarnessError, "unresolved"):
            harness.cleanup()
        self.assertEqual(self.identity.create_calls, 0)

    def test_config_and_output_never_include_secret_like_values(self):
        secret = "secret-private-key-canary"
        harness = self.harness()
        result = harness.provision()
        encoded = json.dumps(result)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("OCI_CLI_CONFIG_FILE", encoded)
