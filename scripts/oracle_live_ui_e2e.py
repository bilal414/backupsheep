#!/usr/bin/env python3
"""Safety-gated Oracle Cloud source provisioning and UI result verification.

This script is deliberately inert by default.  ``plan`` performs no OCI config
read and no network request.  Provider creates require
``BACKUPSHEEP_E2E_APPLY=YES``.  Provider cleanup additionally requires
``BACKUPSHEEP_E2E_CLEANUP=YES`` and can address only exact OCIDs already stored
in the fsynced run ledger.

The OCI signer is loaded only through the normal OCI CLI/SDK profile selected by
``OCI_CLI_CONFIG_FILE`` and ``OCI_CLI_PROFILE``.  Credential values are never
accepted as arguments, copied into the ledger, or printed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.live_e2e_ledger import (  # noqa: E402
    DurableMutationIntentStore,
    DurableResourceLedger,
    LedgerError,
    require_run_id,
)


class HarnessError(RuntimeError):
    """A bounded, credential-free safety failure."""

    def __init__(
        self,
        message,
        *,
        code="",
        definitive_rejection=False,
        mutation_outcome_unknown=False,
    ):
        super().__init__(message)
        self.code = str(code or "")
        self.mutation_outcome_unknown = bool(mutation_outcome_unknown)
        self.definitive_rejection = bool(definitive_rejection)


OCI_OCID_RE = re.compile(r"^ocid1\.[a-z0-9-]+\.[a-z0-9-]*\.[a-z0-9-]*\..+$")
PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
MAX_PAGES = 100
MAX_ITEMS = 10_000
REQUEST_TIMEOUT = (10.0, 60.0)
SOURCE_BLOCK_DEVICE = "/dev/oracleoci/oraclevdb"
RESTORE_BLOCK_DEVICE = "/dev/oracleoci/oraclevdc"

E2E_RUN_TAG = "BACKUPSHEEP_E2E_RUN"
E2E_OWNED_TAG = "BACKUPSHEEP_E2E_OWNED"
E2E_KIND_TAG = "BACKUPSHEEP_E2E_KIND"

BACKUP_MARKER_TAG = "BACKUPSHEEP__UUID"
BACKUP_SOURCE_TAG = "BACKUPSHEEP__SOURCE"
BACKUP_KIND_TAG = "BACKUPSHEEP__KIND"
BACKUP_REQUEST_TAG = "BACKUPSHEEP__REQUEST"
RESTORE_MARKER_TAG = "BACKUPSHEEP_RESTORE"
RESTORE_SOURCE_TAG = "BACKUPSHEEP_RESTORE_SOURCE"
RESTORE_ORIGIN_TAG = "BACKUPSHEEP_RESTORE_ORIGIN"

SOURCE_KINDS = {
    "source_block_volume",
    "source_block_attachment",
    "source_instance",
    "source_boot_volume",
    "source_vnic",
}
UI_KINDS = {
    "ui_compute_backup",
    "ui_compute_restore",
    "ui_compute_restore_boot_volume",
    "ui_compute_restore_vnic",
    "ui_block_backup",
    "ui_boot_backup",
    "ui_block_restore",
    "ui_block_restore_attachment",
    "ui_boot_restore",
    "ui_boot_verify_instance",
    "ui_boot_verify_vnic",
}
ALL_KINDS = SOURCE_KINDS | UI_KINDS
STORAGE_KINDS = {
    "object_bucket",
    "iam_user",
    "iam_group",
    "iam_policy",
    "iam_membership",
    "customer_secret_key",
}
ALL_KINDS |= STORAGE_KINDS
TAGGABLE_SOURCE_KINDS = {
    "source_block_volume",
    "source_instance",
    "source_boot_volume",
    "source_vnic",
}


def _safe_path(value, *, variable):
    if not value:
        raise HarnessError(f"{variable} is required.")
    path = Path(value).expanduser().resolve()
    if "_docs" in path.parts:
        raise HarnessError(f"{variable} must not point inside _docs.")
    return path


def _required(environment, name):
    value = str(environment.get(name) or "").strip()
    if not value:
        raise HarnessError(f"{name} is required.")
    return value


def _require_ocid(value, *, label, resource_type=None):
    value = str(value or "").strip()
    if not OCI_OCID_RE.fullmatch(value):
        raise HarnessError(f"{label} must be an OCI OCID.")
    if resource_type and not value.startswith(f"ocid1.{resource_type}."):
        raise HarnessError(f"{label} must be an {resource_type} OCID.")
    return value


def _require_customer_secret_key_id(value):
    """Validate the non-OCID access-key identifier returned by OCI S3 auth."""

    value = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{16,128}", value):
        raise HarnessError("customer secret key ID is malformed.")
    return value


def _retry_token(value):
    return "bs-" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:61]


def _data(response):
    return response.get("data") if isinstance(response, dict) else getattr(response, "data", None)


def _status(response):
    value = response.get("status") if isinstance(response, dict) else getattr(response, "status", None)
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _headers(response):
    value = response.get("headers") if isinstance(response, dict) else getattr(response, "headers", None)
    return value if isinstance(value, dict) else {}


def _header(headers, name):
    expected = str(name).casefold()
    for key, value in (headers or {}).items():
        if str(key).casefold() == expected:
            return value
    return None


def _next_page(response):
    value = response.get("opc_next_page") if isinstance(response, dict) else getattr(response, "opc_next_page", None)
    if value is None:
        value = _header(_headers(response), "opc-next-page")
    return str(value).strip() if value not in (None, "") else ""


def _value(resource, name, default=None):
    if isinstance(resource, dict):
        return resource.get(name, default)
    return getattr(resource, name, default)


def _tags(resource):
    value = _value(resource, "freeform_tags", {})
    return {str(key): str(item) for key, item in value.items()} if isinstance(value, dict) else {}


def _source_id(resource):
    details = _value(resource, "source_details")
    for name in ("image_id", "boot_volume_backup_id", "volume_backup_id", "id"):
        value = _value(details, name) if details is not None else None
        if value:
            return str(value)
    return ""


def _provider_error_code(error):
    status = getattr(error, "status", None) or getattr(error, "status_code", None)
    code = str(getattr(error, "code", "") or "").casefold()
    if code == "notauthorizedornotfound":
        return "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED"
    if status in {401, 403} or code in {"notauthenticated", "notauthorized"}:
        return "PROVIDER_AUTH_FAILED"
    if status == 404 or code == "notfound":
        return "PROVIDER_NOT_FOUND"
    if status == 429 or code in {"toomanyrequests", "throttled", "throttling"}:
        return "PROVIDER_RATE_LIMIT"
    name = error.__class__.__name__.casefold()
    if status in {408, 504} or "timeout" in name:
        return "PROVIDER_TIMEOUT"
    if (isinstance(status, int) and status >= 500) or any(
        token in name for token in ("connection", "requestexception")
    ):
        return "PROVIDER_TRANSIENT_OUTAGE"
    return "PROVIDER_REQUEST_FAILED"


def _provider_error_outcome(error):
    """Classify an OCI exception without guessing about unknown outcomes."""

    status = getattr(error, "status", None) or getattr(error, "status_code", None)
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    code = _provider_error_code(error)
    if status in {408, 504} or (
        isinstance(status, int) and status >= 500
    ) or code in {"PROVIDER_TIMEOUT", "PROVIDER_TRANSIENT_OUTAGE"}:
        return "unknown"
    if (
        isinstance(status, int)
        and 400 <= status < 500
        and status != 408
    ) or code in {
        "PROVIDER_AUTH_FAILED",
        "PROVIDER_NOT_FOUND",
        "PROVIDER_NOT_FOUND_OR_UNAUTHORIZED",
        "PROVIDER_RATE_LIMIT",
    }:
        return "definite"
    # A generic SDK/parser/application exception does not prove that the
    # provider rejected the mutation.  Keep the intent for reconciliation.
    return "unknown"


def _checked(response, accepted):
    if _status(response) not in set(accepted):
        raise HarnessError("OCI returned an unexpected response status.")
    return response


def iter_pages(method, **kwargs):
    """Consume OCI ``opc-next-page`` cursors with hard inventory bounds."""

    cursor = ""
    seen = set()
    count = 0
    for _ in range(MAX_PAGES):
        request = dict(kwargs)
        request["limit"] = min(100, MAX_ITEMS - count)
        if cursor:
            request["page"] = cursor
        response = _checked(method(**request), {200})
        items = _data(response)
        if not isinstance(items, (list, tuple)):
            raise HarnessError("OCI returned a malformed inventory page.")
        for item in items:
            count += 1
            if count > MAX_ITEMS:
                raise HarnessError("OCI inventory exceeded the safety limit.")
            yield item
        next_cursor = _next_page(response)
        if not next_cursor:
            return
        if next_cursor in seen:
            raise HarnessError("OCI returned a repeated inventory cursor.")
        seen.add(next_cursor)
        cursor = next_cursor
    raise HarnessError("OCI inventory exceeded the page safety limit.")


@dataclass(frozen=True)
class HarnessConfig:
    run_id: str
    ledger_path: Path
    profile: str
    config_file: Path
    compartment_id: str
    availability_domain: str
    apply: bool
    cleanup: bool
    poll_seconds: int
    timeout_seconds: int

    @classmethod
    def from_environment(cls, environment=None):
        environment = dict(os.environ if environment is None else environment)
        run_id = require_run_id(_required(environment, "BACKUPSHEEP_E2E_RUN_ID"))
        requested = _require_ocid(
            _required(environment, "ORACLE_E2E_COMPARTMENT_OCID"),
            label="ORACLE_E2E_COMPARTMENT_OCID",
            resource_type="compartment",
        )
        allowed = _require_ocid(
            _required(environment, "ORACLE_E2E_ALLOWED_COMPARTMENT_OCID"),
            label="ORACLE_E2E_ALLOWED_COMPARTMENT_OCID",
            resource_type="compartment",
        )
        if requested != allowed:
            raise HarnessError(
                "Requested and explicitly allowed Oracle compartments must match exactly."
            )
        profile = _required(environment, "OCI_CLI_PROFILE")
        if not PROFILE_RE.fullmatch(profile):
            raise HarnessError("OCI_CLI_PROFILE contains unsupported characters.")
        config_file = _safe_path(
            environment.get("OCI_CLI_CONFIG_FILE", "~/.oci/config"),
            variable="OCI_CLI_CONFIG_FILE",
        )
        try:
            poll_seconds = max(int(environment.get("ORACLE_E2E_POLL_SECONDS", "10")), 2)
            timeout_seconds = max(int(environment.get("ORACLE_E2E_TIMEOUT_SECONDS", "1800")), 60)
        except (TypeError, ValueError) as error:
            raise HarnessError("Oracle E2E wait settings must be integers.") from error
        return cls(
            run_id=run_id,
            ledger_path=_safe_path(
                _required(environment, "BACKUPSHEEP_E2E_LEDGER_PATH"),
                variable="BACKUPSHEEP_E2E_LEDGER_PATH",
            ),
            profile=profile,
            config_file=config_file,
            compartment_id=requested,
            availability_domain=_required(environment, "ORACLE_E2E_AVAILABILITY_DOMAIN"),
            apply=environment.get("BACKUPSHEEP_E2E_APPLY") == "YES",
            cleanup=environment.get("BACKUPSHEEP_E2E_CLEANUP") == "YES",
            poll_seconds=poll_seconds,
            timeout_seconds=min(timeout_seconds, 7200),
        )


class OracleLiveUIHarness:
    """Provision exact test sources, verify UI outputs, and clean a run ledger."""

    def __init__(self, config, *, environment=None, clients=None, sleep=time.sleep):
        self.config = config
        self.environment = dict(os.environ if environment is None else environment)
        provided_clients = dict(clients or {})
        self._oci_config = provided_clients.pop("_config", None)
        self._clients = provided_clients
        self._sleep = sleep
        self.names = {
            "source_block_volume": f"{config.run_id}-block-source",
            "source_block_attachment": f"{config.run_id}-block-attachment",
            "source_instance": f"{config.run_id}-boot-source-instance",
            "source_boot_volume": f"{config.run_id}-boot-source",
            "source_vnic": f"{config.run_id}-boot-source-vnic",
            "ui_block_restore_attachment": f"{config.run_id}-block-restore-attachment",
            "ui_boot_verify_instance": f"{config.run_id}-boot-verify-instance",
            "ui_boot_verify_vnic": f"{config.run_id}-boot-verify-vnic",
            "ui_compute_restore_boot_volume": f"{config.run_id}-compute-restore-boot",
            "object_bucket": f"{config.run_id}-objects",
            "iam_user": f"{config.run_id}-s3-user",
            "iam_group": f"{config.run_id}-s3-group",
            "iam_policy": f"{config.run_id}-s3-policy",
            "customer_secret_key": f"{config.run_id}-s3-key",
        }
        scope = f"oci:{config.profile}:{config.compartment_id}:{config.availability_domain}"
        self.ledger = DurableResourceLedger(
            config.ledger_path,
            provider="oracle_cloud",
            run_id=config.run_id,
            scope=scope,
        )
        self.intents = DurableMutationIntentStore(
            config.ledger_path,
            provider="oracle_cloud",
            run_id=config.run_id,
            scope=scope,
            suffix=".oracle-intents.json",
        )
        self.evidence = DurableMutationIntentStore(
            config.ledger_path,
            provider="oracle_cloud",
            run_id=config.run_id,
            scope=scope,
            suffix=".oracle-evidence.json",
        )

    def _source_tags(self, kind):
        if kind not in TAGGABLE_SOURCE_KINDS and kind not in {
            "ui_boot_verify_instance",
            "ui_boot_verify_vnic",
            "ui_compute_restore_boot_volume",
        }:
            raise HarnessError("Unsupported Oracle source kind.")
        return {
            E2E_RUN_TAG: self.config.run_id,
            E2E_OWNED_TAG: "true",
            E2E_KIND_TAG: kind,
        }

    def _load_clients(self):
        if self._clients:
            required = {"identity", "compute", "block", "network", "object"}
            if not required.issubset(self._clients):
                raise HarnessError("Injected OCI clients are incomplete.")
            return self._clients
        try:
            import oci

            config = oci.config.from_file(
                file_location=str(self.config.config_file),
                profile_name=self.config.profile,
            )
            oci.config.validate_config(config)
            retry = oci.retry.NoneRetryStrategy()
            kwargs = {"timeout": REQUEST_TIMEOUT, "retry_strategy": retry}
            self._clients = {
                "identity": oci.identity.IdentityClient(config, **kwargs),
                "compute": oci.core.ComputeClient(config, **kwargs),
                "block": oci.core.BlockstorageClient(config, **kwargs),
                "network": oci.core.VirtualNetworkClient(config, **kwargs),
                "object": oci.object_storage.ObjectStorageClient(config, **kwargs),
            }
            self._oci_config = {
                "tenancy": str(config.get("tenancy") or ""),
                "region": str(config.get("region") or ""),
            }
        except HarnessError:
            raise
        except Exception as error:
            raise HarnessError(
                f"OCI profile loading failed: {_provider_error_code(error)}."
            ) from error
        return self._clients

    def _models(self):
        try:
            import oci

            return oci.core.models
        except Exception as error:
            raise HarnessError("The OCI Python SDK is required.") from error

    def _call(self, method, *args, accepted=(200,), mutation=False, **kwargs):
        try:
            response = method(*args, **kwargs)
            status = _status(response)
            if status not in set(accepted):
                if (
                    isinstance(status, int)
                    and 400 <= status < 500
                    and status != 408
                ):
                    raise HarnessError(
                        "OCI definitively rejected the bounded request.",
                        code=f"PROVIDER_HTTP_{status}",
                        definitive_rejection=True,
                    )
                outcome_unknown = mutation
                raise HarnessError(
                    "OCI returned an unexpected response status; the mutation "
                    "outcome may be unknown.",
                    code="PROVIDER_UNEXPECTED_STATUS",
                    mutation_outcome_unknown=outcome_unknown,
                )
            return response
        except HarnessError:
            raise
        except Exception as error:
            code = _provider_error_code(error)
            outcome = _provider_error_outcome(error)
            definitive = outcome == "definite"
            outcome_unknown = mutation and not definitive
            suffix = " The mutation outcome may be unknown." if outcome_unknown else ""
            raise HarnessError(
                f"OCI request failed: {code}.{suffix}",
                code=code,
                definitive_rejection=definitive,
                mutation_outcome_unknown=outcome_unknown,
            ) from error

    def _require_apply(self):
        if not self.config.apply:
            raise HarnessError(
                "Provider creates require BACKUPSHEEP_E2E_APPLY=YES."
            )

    def _require_cleanup(self):
        if not self.config.cleanup:
            raise HarnessError(
                "Provider cleanup requires BACKUPSHEEP_E2E_CLEANUP=YES."
            )
        self._require_apply()

    def _validate_scope(self):
        clients = self._load_clients()
        compartment = _data(
            self._call(
                clients["identity"].get_compartment,
                compartment_id=self.config.compartment_id,
            )
        )
        if (
            str(_value(compartment, "id") or "") != self.config.compartment_id
            or str(_value(compartment, "lifecycle_state") or "").upper() != "ACTIVE"
        ):
            raise HarnessError("The explicitly allowed compartment is not active.")

        tenancy = (self._oci_config or {}).get("tenancy")
        if tenancy:
            domains = self._list_unpaged(
                clients["identity"].list_availability_domains,
                compartment_id=tenancy,
            )
            matches = [
                item
                for item in domains
                if str(_value(item, "name") or "") == self.config.availability_domain
            ]
            if len(matches) != 1:
                raise HarnessError("The configured availability domain is not exact.")

    def plan(self):
        """Return an inert plan without loading OCI config or making live calls."""

        return {
            "phase": "PLAN",
            "live_calls": False,
            "run_id": self.config.run_id,
            "profile": self.config.profile,
            "compartment_id": self.config.compartment_id,
            "availability_domain": self.config.availability_domain,
            "names": dict(self.names),
            "apply_enabled": self.config.apply,
            "cleanup_enabled": self.config.cleanup,
        }

    @staticmethod
    def inert_plan():
        """Build the CLI plan without reading provider configuration or state."""

        return {
            "phase": "PLAN",
            "live_calls": False,
            "config_loaded": False,
            "profile_loaded": False,
            "ledger_initialized": False,
            "harness_initialized": False,
            "client_initialized": False,
        }

    def _list(self, method, **kwargs):
        try:
            return list(iter_pages(method, **kwargs))
        except HarnessError:
            raise
        except Exception as error:
            raise HarnessError(
                f"OCI inventory failed: {_provider_error_code(error)}."
            ) from error

    def _list_unpaged(self, method, **kwargs):
        rows = _data(self._call(method, **kwargs))
        if not isinstance(rows, (list, tuple)) or len(rows) > MAX_ITEMS:
            raise HarnessError("OCI unpaged inventory is malformed or over limit.")
        return list(rows)

    def _expected_proof(
        self,
        *,
        name,
        tags,
        availability_domain=None,
        source_id="",
    ):
        return {
            "compartment_id": self.config.compartment_id,
            "availability_domain": str(availability_domain or ""),
            "display_name": str(name),
            "tags": {str(key): str(value) for key, value in tags.items()},
            "source_id": str(source_id or ""),
        }

    def _assert_exact(
        self,
        resource,
        *,
        resource_id,
        proof,
        source_id=None,
    ):
        if str(_value(resource, "id") or "") != str(resource_id):
            raise HarnessError("Oracle resource OCID did not match the exact witness.")
        if str(_value(resource, "compartment_id") or "") != proof["compartment_id"]:
            raise HarnessError("Oracle resource escaped the explicitly allowed compartment.")
        if str(_value(resource, "display_name") or "") != proof["display_name"]:
            raise HarnessError("Oracle resource name did not match the exact witness.")
        expected_ad = proof.get("availability_domain") or ""
        if expected_ad and str(_value(resource, "availability_domain") or "") != expected_ad:
            raise HarnessError("Oracle resource availability domain did not match.")
        actual_tags = _tags(resource)
        if any(actual_tags.get(key) != value for key, value in proof["tags"].items()):
            raise HarnessError("Oracle resource ownership tags did not match exactly.")
        for field in (
            "instance_id",
            "volume_id",
            "subnet_id",
            "boot_volume_id",
            "device",
        ):
            expected = str(proof.get(field) or "")
            if expected and str(_value(resource, field) or "") != expected:
                raise HarnessError(f"Oracle resource {field} did not match the ledger.")
        expected_source = str(proof.get("source_id") or "")
        actual_source = (
            str(source_id)
            if source_id is not None
            else str(_value(resource, "image_id") or _source_id(resource) or "")
        )
        if expected_source and actual_source != expected_source:
            raise HarnessError("Oracle resource source witness did not match the ledger.")
        return resource

    def _active_ledger_entry(self, kind):
        rows = [
            row
            for row in self.ledger.entries(kind)
            if row.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        if len(rows) > 1:
            raise HarnessError(f"The Oracle ledger has duplicate {kind} entries.")
        return rows[0] if rows else None

    def _record(
        self,
        kind,
        resource,
        proof,
        *,
        source_witness="",
        source_id=None,
    ):
        if kind not in ALL_KINDS:
            raise HarnessError("Refusing to ledger an unsupported Oracle resource kind.")
        resource_id = _require_ocid(
            _value(resource, "id"), label=f"{kind} provider ID"
        )
        self._assert_exact(
            resource,
            resource_id=resource_id,
            proof=proof,
            source_id=source_id,
        )
        return self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=proof["display_name"],
            ownership=proof,
            source_witness=source_witness,
        )

    def _wait_state(self, fetch, *, resource_id, ready, failed):
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            resource = _data(fetch(resource_id))
            state = str(_value(resource, "lifecycle_state") or "").upper()
            if state in ready:
                return resource
            if state in failed or not state:
                raise HarnessError("Oracle resource entered a failed lifecycle state.")
            if time.monotonic() >= deadline:
                raise HarnessError("Oracle waiter reached its bounded timeout.")
            self._sleep(self.config.poll_seconds)

    def _find_named(self, method, *, name, tags, **kwargs):
        resources = self._list(method, **kwargs)
        named = [
            item for item in resources if str(_value(item, "display_name") or "") == name
        ]
        exact = [
            item
            for item in named
            if str(_value(item, "compartment_id") or "") == self.config.compartment_id
            and all(_tags(item).get(key) == value for key, value in tags.items())
        ]
        if len(exact) > 1:
            raise HarnessError("Multiple exact Oracle resources matched one run witness.")
        if any(item not in exact for item in named):
            raise HarnessError("A foreign Oracle resource uses the reserved E2E name.")
        return exact[0] if exact else None

    def _put_intent(self, kind, *, operation, name):
        current = self.intents.get(kind)
        if current and not current.get("provider_resource_id"):
            raise HarnessError(
                f"Oracle {kind} has an unresolved durable mutation intent; cleanup or manual review is required."
            )
        return self.intents.put(
            kind,
            {
                "operation": operation,
                "kind": kind,
                "name": name,
                "marker": self.config.run_id,
                "mutation_started_at": time.time(),
            },
        )

    def _bind_intent_resource(self, kind, resource_id):
        resource_id = _require_ocid(resource_id, label=f"{kind} intent OCID")
        self.intents.update(kind, provider_resource_id=resource_id)
        return resource_id

    def _clear_definitely_rejected_intent(self, kind, error):
        """Release only intents whose provider response proves no mutation occurred."""

        if (
            getattr(error, "definitive_rejection", False)
            and not getattr(error, "mutation_outcome_unknown", False)
        ):
            self.intents.clear(kind)

    def _mutation_call(self, intent_key, method, *args, **kwargs):
        """Run an OCI mutation and release only a definitively rejected intent."""

        try:
            return self._call(method, *args, mutation=True, **kwargs)
        except HarnessError as error:
            self._clear_definitely_rejected_intent(intent_key, error)
            raise

    def _source_from_ledger(self, kind, getter, id_argument):
        row = self._active_ledger_entry(kind)
        if not row:
            return None
        try:
            resource = _data(
                self._call(
                    getter,
                    **{id_argument: row["resource_id"]},
                )
            )
        except HarnessError:
            raise HarnessError(
                f"Ledgered Oracle {kind} could not be reverified; no replacement will be created."
            )
        self._assert_exact(
            resource,
            resource_id=row["resource_id"],
            proof=row["ownership"],
        )
        return resource

    def _validate_instance_inputs(self):
        subnet_id = _require_ocid(
            _required(self.environment, "ORACLE_E2E_SUBNET_OCID"),
            label="ORACLE_E2E_SUBNET_OCID",
            resource_type="subnet",
        )
        image_id = _require_ocid(
            _required(self.environment, "ORACLE_E2E_IMAGE_OCID"),
            label="ORACLE_E2E_IMAGE_OCID",
            resource_type="image",
        )
        shape = _required(self.environment, "ORACLE_E2E_SHAPE")
        subnet = _data(
            self._call(self._clients["network"].get_subnet, subnet_id=subnet_id)
        )
        if (
            str(_value(subnet, "id") or "") != subnet_id
            or str(_value(subnet, "compartment_id") or "")
            != self.config.compartment_id
            or str(_value(subnet, "lifecycle_state") or "").upper() != "AVAILABLE"
        ):
            raise HarnessError("The supplied subnet is not active in the allowed compartment.")
        image = _data(self._call(self._clients["compute"].get_image, image_id=image_id))
        if (
            str(_value(image, "id") or "") != image_id
            or str(_value(image, "lifecycle_state") or "").upper() != "AVAILABLE"
        ):
            raise HarnessError("The supplied source image is not available.")
        return subnet_id, image_id, shape

    def _provision_block_volume(self):
        client = self._clients["block"]
        existing = self._source_from_ledger(
            "source_block_volume", client.get_volume, "volume_id"
        )
        if existing:
            return existing
        kind = "source_block_volume"
        name = self.names[kind]
        tags = self._source_tags(kind)
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
        )
        candidate = self._find_named(
            client.list_volumes,
            name=name,
            tags=tags,
            compartment_id=self.config.compartment_id,
            availability_domain=self.config.availability_domain,
            display_name=name,
        )
        if candidate is None:
            try:
                size = int(self.environment.get("ORACLE_E2E_BLOCK_SIZE_GBS", "50"))
            except (TypeError, ValueError) as error:
                raise HarnessError("ORACLE_E2E_BLOCK_SIZE_GBS must be an integer.") from error
            if not 50 <= size <= 32_768:
                raise HarnessError("ORACLE_E2E_BLOCK_SIZE_GBS is outside safe bounds.")
            token = _retry_token(f"{self.config.run_id}:{kind}")
            self._put_intent(kind, operation="create", name=name)
            details = self._models().CreateVolumeDetails(
                availability_domain=self.config.availability_domain,
                compartment_id=self.config.compartment_id,
                display_name=name,
                freeform_tags=tags,
                size_in_gbs=size,
            )
            try:
                response = self._mutation_call(
                    kind,
                    client.create_volume,
                    create_volume_details=details,
                    opc_retry_token=token,
                    accepted=(200, 202),
                )
                candidate = _data(response)
            except HarnessError as error:
                candidate = self._find_named(
                    client.list_volumes,
                    name=name,
                    tags=tags,
                    compartment_id=self.config.compartment_id,
                    availability_domain=self.config.availability_domain,
                    display_name=name,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        resource_id = _require_ocid(
            _value(candidate, "id"), label="created block volume", resource_type="volume"
        )
        resource = self._wait_state(
            lambda value: self._call(client.get_volume, volume_id=value),
            resource_id=resource_id,
            ready={"AVAILABLE"},
            failed={"FAULTY", "TERMINATED", "TERMINATING"},
        )
        self._record(kind, resource, proof)
        self.intents.clear(kind)
        return resource

    def _provision_instance(self, subnet_id, image_id, shape):
        client = self._clients["compute"]
        existing = self._source_from_ledger(
            "source_instance", client.get_instance, "instance_id"
        )
        if existing:
            return existing
        kind = "source_instance"
        name = self.names[kind]
        tags = self._source_tags(kind)
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
            source_id=image_id,
        )
        candidate = self._find_named(
            client.list_instances,
            name=name,
            tags=tags,
            compartment_id=self.config.compartment_id,
            display_name=name,
        )
        if candidate is None:
            token = _retry_token(f"{self.config.run_id}:{kind}")
            _private_key, public_key = self._ensure_ssh_key()
            self._put_intent(kind, operation="create", name=name)
            models = self._models()
            details = models.LaunchInstanceDetails(
                availability_domain=self.config.availability_domain,
                compartment_id=self.config.compartment_id,
                display_name=name,
                freeform_tags=tags,
                shape=shape,
                source_details=models.InstanceSourceViaImageDetails(image_id=image_id),
                metadata={"ssh_authorized_keys": public_key},
                create_vnic_details=models.CreateVnicDetails(
                    assign_public_ip=self._assign_public_ip(),
                    display_name=self.names["source_vnic"],
                    freeform_tags=self._source_tags("source_vnic"),
                    subnet_id=subnet_id,
                ),
            )
            try:
                response = self._mutation_call(
                    kind,
                    client.launch_instance,
                    launch_instance_details=details,
                    opc_retry_token=token,
                    accepted=(200, 202),
                )
                candidate = _data(response)
            except HarnessError as error:
                candidate = self._find_named(
                    client.list_instances,
                    name=name,
                    tags=tags,
                    compartment_id=self.config.compartment_id,
                    display_name=name,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        resource_id = _require_ocid(
            _value(candidate, "id"), label="created instance", resource_type="instance"
        )
        resource = self._wait_state(
            lambda value: self._call(client.get_instance, instance_id=value),
            resource_id=resource_id,
            ready={"RUNNING", "STOPPED"},
            failed={"TERMINATED", "TERMINATING"},
        )
        actual_source = str(_value(resource, "image_id") or _source_id(resource))
        if actual_source != image_id:
            raise HarnessError("Created instance image did not match the exact input.")
        self._record(kind, resource, proof, source_witness=image_id)
        self.intents.clear(kind)
        return resource

    def _assign_public_ip(self):
        value = str(self.environment.get("ORACLE_E2E_ASSIGN_PUBLIC_IP", "NO")).upper()
        if value not in {"YES", "NO"}:
            raise HarnessError("ORACLE_E2E_ASSIGN_PUBLIC_IP must be YES or NO.")
        return value == "YES"

    def _key_paths(self):
        private_key = self.config.ledger_path.with_name(
            self.config.ledger_path.name + ".oracle-ssh-key"
        )
        public_key = private_key.with_name(private_key.name + ".pub")
        known_hosts = private_key.with_name(private_key.name + ".known-hosts")
        for path in (private_key, public_key, known_hosts):
            if "_docs" in path.resolve().parts:
                raise HarnessError("Oracle E2E SSH artifacts must not be inside _docs.")
        return private_key, public_key, known_hosts

    @staticmethod
    def _atomic_private_write(path, payload, mode):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _ensure_ssh_key(self):
        private_path, public_path, _known_hosts = self._key_paths()
        if private_path.exists() != public_path.exists():
            raise HarnessError("The run-scoped Oracle SSH key pair is incomplete.")
        if not private_path.exists():
            self._require_apply()
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa

                key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
                private_payload = key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption(),
                )
                public_payload = key.public_key().public_bytes(
                    serialization.Encoding.OpenSSH,
                    serialization.PublicFormat.OpenSSH,
                ) + b"\n"
                self._atomic_private_write(private_path, private_payload, 0o600)
                self._atomic_private_write(public_path, public_payload, 0o600)
            except HarnessError:
                raise
            except Exception as error:
                raise HarnessError("Could not create the run-scoped SSH key.") from error
        private_path.chmod(0o600)
        public = public_path.read_text(encoding="ascii").strip()
        if not public.startswith("ssh-rsa "):
            raise HarnessError("The run-scoped SSH public key is malformed.")
        return private_path, public

    def _provision_vnic(self, instance):
        kind = "source_vnic"
        existing = self._source_from_ledger(
            kind, self._clients["network"].get_vnic, "vnic_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        attachments = self._list(
            self._clients["compute"].list_vnic_attachments,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
        ]
        if len(attachments) != 1:
            raise HarnessError("The source instance does not have one exact VNIC.")
        vnic_id = _require_ocid(
            _value(attachments[0], "vnic_id"), label="source VNIC", resource_type="vnic"
        )
        vnic = _data(
            self._call(self._clients["network"].get_vnic, vnic_id=vnic_id)
        )
        proof = self._expected_proof(
            name=self.names[kind],
            tags=self._source_tags(kind),
        )
        proof["subnet_id"] = _require_ocid(
            _value(vnic, "subnet_id"), label="source VNIC subnet", resource_type="subnet"
        )
        self._record(kind, vnic, proof, source_witness=instance_id)
        return vnic

    def _provision_boot_volume(self, instance):
        client = self._clients["block"]
        kind = "source_boot_volume"
        existing = self._source_from_ledger(kind, client.get_boot_volume, "boot_volume_id")
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        attachments = self._list(
            self._clients["compute"].list_boot_volume_attachments,
            availability_domain=self.config.availability_domain,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
        ]
        if len(attachments) != 1:
            raise HarnessError("The source instance does not have one exact boot volume.")
        boot_id = _require_ocid(
            _value(attachments[0], "boot_volume_id"),
            label="source boot volume",
            resource_type="bootvolume",
        )
        boot = _data(self._call(client.get_boot_volume, boot_volume_id=boot_id))
        if (
            str(_value(boot, "compartment_id") or "") != self.config.compartment_id
            or str(_value(boot, "availability_domain") or "")
            != self.config.availability_domain
        ):
            raise HarnessError("The source boot volume escaped the allowed graph.")
        tags = self._source_tags(kind)
        current_tags = _tags(boot)
        foreign_run = current_tags.get(E2E_RUN_TAG)
        if foreign_run and foreign_run != self.config.run_id:
            raise HarnessError("The source boot volume carries a foreign run tag.")
        if (
            str(_value(boot, "display_name") or "") != self.names[kind]
            or any(current_tags.get(key) != value for key, value in tags.items())
        ):
            self._put_intent(kind, operation="tag", name=self.names[kind])
            details = self._models().UpdateBootVolumeDetails(
                display_name=self.names[kind],
                freeform_tags={**current_tags, **tags},
            )
            self._mutation_call(
                kind,
                client.update_boot_volume,
                boot_volume_id=boot_id,
                update_boot_volume_details=details,
                accepted=(200,),
            )
        boot = self._wait_state(
            lambda value: self._call(client.get_boot_volume, boot_volume_id=value),
            resource_id=boot_id,
            ready={"AVAILABLE"},
            failed={"FAULTY", "TERMINATED", "TERMINATING"},
        )
        proof = self._expected_proof(
            name=self.names[kind],
            tags=tags,
            availability_domain=self.config.availability_domain,
        )
        self._record(kind, boot, proof, source_witness=instance_id)
        self.intents.clear(kind)
        return boot

    def _ledger_compute_restore_boot(self, instance):
        """Tag and ledger the boot volume created with a UI compute restore."""

        kind = "ui_compute_restore_boot_volume"
        existing = self._source_from_ledger(
            kind, self._clients["block"].get_boot_volume, "boot_volume_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        attachments = self._list(
            self._clients["compute"].list_boot_volume_attachments,
            availability_domain=self.config.availability_domain,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        exact = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
        ]
        if len(exact) != 1:
            raise HarnessError("UI compute restore boot-volume relationship is ambiguous.")
        boot_id = _require_ocid(
            _value(exact[0], "boot_volume_id"),
            label="UI compute restore boot volume",
            resource_type="bootvolume",
        )
        boot = _data(
            self._call(
                self._clients["block"].get_boot_volume,
                boot_volume_id=boot_id,
            )
        )
        tags = self._source_tags(kind)
        current = _tags(boot)
        foreign = current.get(E2E_RUN_TAG)
        if foreign and foreign != self.config.run_id:
            raise HarnessError("UI compute restore boot volume has a foreign run tag.")
        self._put_intent(kind, operation="tag", name=self.names[kind])
        details = self._models().UpdateBootVolumeDetails(
            display_name=self.names[kind],
            freeform_tags={**current, **tags},
        )
        self._mutation_call(
            kind,
            self._clients["block"].update_boot_volume,
            boot_volume_id=boot_id,
            update_boot_volume_details=details,
            accepted=(200,),
        )
        boot = _data(
            self._call(
                self._clients["block"].get_boot_volume,
                boot_volume_id=boot_id,
            )
        )
        proof = self._expected_proof(
            name=self.names[kind],
            tags=tags,
            availability_domain=self.config.availability_domain,
        )
        self._record(kind, boot, proof, source_witness=instance_id)
        self.intents.clear(kind)
        return boot

    def _attach_source_block(self, instance, volume):
        client = self._clients["compute"]
        kind = "source_block_attachment"
        existing = self._source_from_ledger(
            kind, client.get_volume_attachment, "volume_attachment_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        volume_id = str(_value(volume, "id") or "")
        attachments = self._list(
            client.list_volume_attachments,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
            volume_id=volume_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "lifecycle_state") or "").upper() != "DETACHED"
        ]
        device = self._require_attachment_device(
            instance_id, SOURCE_BLOCK_DEVICE
        )
        matching = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "volume_id") or "") == volume_id
            and str(_value(item, "display_name") or "") == self.names[kind]
            and str(_value(item, "device") or "") == device
        ]
        if len(matching) > 1 or any(item not in matching for item in attachments):
            raise HarnessError("The source block-volume attachment is ambiguous.")
        candidate = matching[0] if matching else None
        if candidate is None:
            self._put_intent(kind, operation="attach", name=self.names[kind])
            details = self._models().AttachParavirtualizedVolumeDetails(
                display_name=self.names[kind],
                instance_id=instance_id,
                is_read_only=False,
                is_shareable=False,
                device=device,
                volume_id=volume_id,
            )
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        client.attach_volume,
                        attach_volume_details=details,
                        accepted=(200, 202),
                    )
                )
            except HarnessError as error:
                attachments = self._list(
                    client.list_volume_attachments,
                    compartment_id=self.config.compartment_id,
                    instance_id=instance_id,
                    volume_id=volume_id,
                )
                attachments = [
                    item
                    for item in attachments
                    if str(_value(item, "lifecycle_state") or "").upper()
                    != "DETACHED"
                ]
                matching = [
                    item
                    for item in attachments
                    if str(_value(item, "instance_id") or "") == instance_id
                    and str(_value(item, "volume_id") or "") == volume_id
                    and str(_value(item, "display_name") or "") == self.names[kind]
                    and str(_value(item, "device") or "") == device
                ]
                if len(matching) != 1:
                    if not matching:
                        self._clear_definitely_rejected_intent(kind, error)
                    raise
                candidate = matching[0]
        attachment_id = _require_ocid(
            _value(candidate, "id"),
            label="source block attachment",
            resource_type="volumeattachment",
        )
        attachment = self._wait_state(
            lambda value: self._call(
                client.get_volume_attachment, volume_attachment_id=value
            ),
            resource_id=attachment_id,
            ready={"ATTACHED"},
            failed={"DETACHED", "DETACHING"},
        )
        proof = self._expected_proof(name=self.names[kind], tags={})
        proof.update(
            {"instance_id": instance_id, "volume_id": volume_id, "device": device}
        )
        self._record(
            kind,
            attachment,
            proof,
            source_witness=f"{instance_id}:{volume_id}",
        )
        self.intents.clear(kind)
        return attachment

    def _require_attachment_device(self, instance_id, expected):
        if expected not in {SOURCE_BLOCK_DEVICE, RESTORE_BLOCK_DEVICE}:
            raise HarnessError("Oracle attachment device is outside the safe allowlist.")
        devices = self._list_unpaged(
            self._clients["compute"].list_instance_devices,
            instance_id=instance_id,
        )
        matches = [
            item for item in devices if str(_value(item, "name") or "") == expected
        ]
        if len(matches) != 1 or _value(matches[0], "is_available") is not True:
            raise HarnessError(
                "The exact consistent Oracle attachment device is not available."
            )
        return expected

    def _payload(self):
        try:
            byte_count = int(self.environment.get("ORACLE_E2E_DATA_BYTES", "1048576"))
        except (TypeError, ValueError) as error:
            raise HarnessError("ORACLE_E2E_DATA_BYTES must be an integer.") from error
        if not 4096 <= byte_count <= 64 * 1024 * 1024:
            raise HarnessError("ORACLE_E2E_DATA_BYTES is outside safe bounds.")
        chunks = []
        remaining = byte_count
        counter = 0
        while remaining:
            chunk = hashlib.sha256(
                f"{self.config.run_id}:oracle-e2e:{counter}".encode("utf-8")
            ).digest()
            chunks.append(chunk[:remaining])
            remaining -= min(len(chunk), remaining)
            counter += 1
        payload = b"".join(chunks)
        return payload, hashlib.sha256(payload).hexdigest(), byte_count

    def _ssh_client(self, vnic, *, host_variable="ORACLE_E2E_SSH_HOST"):
        try:
            import paramiko
        except Exception as error:
            raise HarnessError("Paramiko is required for Oracle data verification.") from error
        private_path, _public = self._ensure_ssh_key()
        _private, _public_path, known_hosts = self._key_paths()
        addresses = {
            str(_value(vnic, "public_ip") or "").strip(),
            str(_value(vnic, "private_ip") or "").strip(),
        } - {""}
        configured_host = str(
            self.environment.get(host_variable)
            or self.environment.get("ORACLE_E2E_SSH_HOST")
            or ""
        ).strip()
        host = configured_host or str(_value(vnic, "public_ip") or "").strip()
        if not host:
            host = str(_value(vnic, "private_ip") or "").strip()
        if not host or host not in addresses:
            raise HarnessError("SSH host must be an exact provider-reported VNIC address.")
        user = _required(self.environment, "ORACLE_E2E_SSH_USER")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise HarnessError("ORACLE_E2E_SSH_USER is malformed.")
        client = paramiko.SSHClient()
        if known_hosts.exists():
            client.load_host_keys(str(known_hosts))
        first_connection = host not in client.get_host_keys()
        if first_connection:
            # This is trust-on-first-use for a fresh, exact-OCID test instance.
            # Only deterministic non-secret test bytes traverse this connection.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            key = paramiko.RSAKey.from_private_key_file(str(private_path))
            client.connect(
                hostname=host,
                username=user,
                pkey=key,
                allow_agent=False,
                look_for_keys=False,
                timeout=REQUEST_TIMEOUT[0],
                banner_timeout=REQUEST_TIMEOUT[1],
                auth_timeout=REQUEST_TIMEOUT[1],
            )
            if first_connection:
                known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                client.save_host_keys(str(known_hosts))
                known_hosts.chmod(0o600)
            return client
        except Exception as error:
            client.close()
            raise HarnessError("SSH connection to the exact test VNIC failed.") from error

    @staticmethod
    def _ssh_run(client, command):
        try:
            _stdin, stdout, _stderr = client.exec_command(command, timeout=60)
            payload = stdout.read(4096).decode("utf-8", "strict").strip()
            status = stdout.channel.recv_exit_status()
        except Exception as error:
            raise HarnessError("Remote data command failed.") from error
        if status != 0:
            raise HarnessError("Remote data command returned a non-zero status.")
        return payload

    def _upload_payload(self, client, payload):
        remote = f"/tmp/{self.config.run_id}-oracle-payload.bin"
        try:
            sftp = client.open_sftp()
            with sftp.file(remote, "wb") as target:
                target.write(payload)
                target.flush()
            sftp.close()
        except Exception as error:
            raise HarnessError("Could not upload deterministic Oracle test bytes.") from error
        return remote

    def _mount_volume(self, client, attachment, *, mount_path, read_only):
        device = str(_value(attachment, "device") or "")
        if not re.fullmatch(r"/dev/[A-Za-z0-9_./-]{1,120}", device) or ".." in device:
            raise HarnessError("OCI did not return a safe attached-volume device path.")
        quoted_device = shlex.quote(device)
        quoted_mount = shlex.quote(mount_path)
        deadline = time.monotonic() + min(self.config.timeout_seconds, 300)
        while True:
            try:
                self._ssh_run(client, f"sudo test -b {quoted_device}")
                break
            except HarnessError:
                if time.monotonic() >= deadline:
                    raise HarnessError(
                        "The exact OCI attachment device did not appear within the bounded waiter."
                    )
                self._sleep(self.config.poll_seconds)
        filesystem = self._ssh_run(
            client, f"sudo lsblk -no FSTYPE {quoted_device} | head -n 1"
        )
        if read_only:
            if filesystem != "ext4":
                raise HarnessError("Restored block volume does not contain the expected ext4 filesystem.")
        elif not filesystem:
            self._ssh_run(client, f"sudo mkfs.ext4 -F {quoted_device} >/dev/null")
        elif filesystem != "ext4":
            raise HarnessError("Source block volume contains an unexpected filesystem.")
        self._ssh_run(client, f"sudo mkdir -p {quoted_mount}")
        option = "-o ro,noload" if read_only else ""
        self._ssh_run(
            client,
            "if ! mountpoint -q {mount}; then sudo mount {option} {device} {mount}; fi".format(
                mount=quoted_mount,
                option=option,
                device=quoted_device,
            ),
        )
        actual = self._ssh_run(
            client, f"findmnt -n -o SOURCE --target {quoted_mount}"
        )
        if not actual.startswith("/dev/"):
            raise HarnessError("Mounted Oracle volume could not be tied to a block device.")
        expected_real = self._ssh_run(client, f"readlink -f {quoted_device}")
        actual_real = self._ssh_run(client, f"readlink -f {shlex.quote(actual)}")
        if expected_real != actual_real:
            raise HarnessError("Mounted filesystem is not the exact OCI attachment device.")

    def _remote_evidence(self, client, path):
        quoted = shlex.quote(path)
        digest = self._ssh_run(client, f"sudo sha256sum {quoted} | cut -d' ' -f1")
        size = self._ssh_run(client, f"sudo stat -c %s {quoted}")
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise HarnessError("Remote SHA-256 evidence was malformed.")
        try:
            byte_count = int(size)
        except (TypeError, ValueError) as error:
            raise HarnessError("Remote byte-count evidence was malformed.") from error
        return {"sha256": digest, "byte_count": byte_count}

    def _seed_data(self, vnic, source_attachment, *, instance_id, block_volume_id, boot_volume_id):
        payload, expected_sha256, expected_bytes = self._payload()
        client = self._ssh_client(vnic, host_variable="ORACLE_E2E_SOURCE_SSH_HOST")
        boot_path = f"/var/lib/backupsheep-e2e/{self.config.run_id}/payload.bin"
        mount_path = f"/mnt/backupsheep-e2e-{self.config.run_id}"
        block_path = f"{mount_path}/payload.bin"
        try:
            remote = self._upload_payload(client, payload)
            self._ssh_run(
                client,
                f"sudo mkdir -p {shlex.quote(str(Path(boot_path).parent))}",
            )
            self._ssh_run(
                client,
                f"sudo install -m 0600 {shlex.quote(remote)} {shlex.quote(boot_path)}",
            )
            self._mount_volume(
                client,
                source_attachment,
                mount_path=mount_path,
                read_only=False,
            )
            self._ssh_run(
                client,
                f"sudo install -m 0600 {shlex.quote(remote)} {shlex.quote(block_path)}",
            )
            self._ssh_run(client, "sudo sync")
            boot = self._remote_evidence(client, boot_path)
            block = self._remote_evidence(client, block_path)
        finally:
            client.close()
        expected = {"sha256": expected_sha256, "byte_count": expected_bytes}
        if boot != expected or block != expected:
            raise HarnessError("Seeded Oracle data did not match local hash evidence.")
        evidence = {
            "operation": "evidence",
            "kind": "payload",
            "name": self.config.run_id,
            "marker": self.config.run_id,
            "sha256": expected_sha256,
            "byte_count": expected_bytes,
            "boot_path": boot_path,
            "block_path": block_path,
            "source_instance_ocid": instance_id,
            "source_block_volume_ocid": block_volume_id,
            "source_boot_volume_ocid": boot_volume_id,
            "filesystem_flushed": True,
        }
        self.evidence.put("payload", evidence)
        return evidence

    def _storage_context(self):
        config = self._oci_config or {}
        tenancy_id = _require_ocid(
            config.get("tenancy"), label="OCI profile tenancy", resource_type="tenancy"
        )
        allowed_tenancy = _require_ocid(
            _required(self.environment, "ORACLE_E2E_ALLOWED_TENANCY_OCID"),
            label="ORACLE_E2E_ALLOWED_TENANCY_OCID",
            resource_type="tenancy",
        )
        if tenancy_id != allowed_tenancy:
            raise HarnessError("OCI profile tenancy does not match the explicit allowlist.")
        region = str(config.get("region") or "").strip()
        if not re.fullmatch(r"[a-z0-9-]{3,64}", region):
            raise HarnessError("OCI profile region is malformed.")
        namespace_response = self._call(
            self._clients["object"].get_namespace,
            compartment_id=tenancy_id,
        )
        namespace = str(_data(namespace_response) or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", namespace):
            raise HarnessError("OCI Object Storage namespace is malformed.")
        return tenancy_id, region, namespace

    def _storage_tags(self, kind):
        return {
            E2E_RUN_TAG: self.config.run_id,
            E2E_OWNED_TAG: "true",
            E2E_KIND_TAG: kind,
        }

    def _record_storage(
        self,
        kind,
        resource,
        *,
        resource_id,
        name,
        compartment_id,
        tags=None,
        relationships=None,
    ):
        if kind not in STORAGE_KINDS:
            raise HarnessError("Unsupported Oracle storage-ledger kind.")
        if kind == "customer_secret_key":
            resource_id = _require_customer_secret_key_id(resource_id)
        else:
            resource_id = _require_ocid(resource_id, label=f"{kind} OCID")
        if str(_value(resource, "id") or "") != resource_id:
            raise HarnessError("OCI IAM/Object Storage OCID did not match.")
        if name and str(
            _value(resource, "name")
            or _value(resource, "display_name")
            or ""
        ) != name:
            raise HarnessError("OCI IAM/Object Storage name did not match.")
        if compartment_id and str(_value(resource, "compartment_id") or "") != compartment_id:
            raise HarnessError("OCI IAM/Object Storage compartment did not match.")
        expected_tags = {str(key): str(value) for key, value in (tags or {}).items()}
        if expected_tags and any(
            _tags(resource).get(key) != value for key, value in expected_tags.items()
        ):
            raise HarnessError("OCI IAM/Object Storage ownership tags did not match.")
        for field, expected in (relationships or {}).items():
            if str(_value(resource, field) or "") != str(expected):
                raise HarnessError(f"OCI {kind} {field} relationship did not match.")
        ownership = {
            "compartment_id": str(compartment_id or ""),
            "name": str(name or ""),
            "tags": expected_tags,
            "relationships": {
                str(key): str(value) for key, value in (relationships or {}).items()
            },
        }
        return self.ledger.record(
            kind=kind,
            resource_id=resource_id,
            name=name,
            ownership=ownership,
            source_witness=json.dumps(ownership["relationships"], sort_keys=True),
        )

    def _find_identity_named(self, method, *, compartment_id, name, tags):
        rows = self._list(method, compartment_id=compartment_id, name=name)
        named = [row for row in rows if str(_value(row, "name") or "") == name]
        exact = [
            row
            for row in named
            if str(_value(row, "compartment_id") or "") == compartment_id
            and all(_tags(row).get(key) == value for key, value in tags.items())
        ]
        if len(exact) > 1:
            raise HarnessError("Multiple exact OCI IAM resources matched one witness.")
        if any(row not in exact for row in named):
            raise HarnessError("A foreign OCI IAM resource uses the reserved name.")
        return exact[0] if exact else None

    def _provision_iam_named(
        self,
        *,
        kind,
        tenancy_id,
        list_method,
        create_method,
        details_class,
    ):
        row = self._active_ledger_entry(kind)
        getter = getattr(self._clients["identity"], f"get_{kind.removeprefix('iam_')}")
        id_argument = f"{kind.removeprefix('iam_')}_id"
        tags = self._storage_tags(kind)
        name = self.names[kind]
        if row:
            resource = _data(self._call(getter, **{id_argument: row["resource_id"]}))
            self._record_storage(
                kind,
                resource,
                resource_id=row["resource_id"],
                name=name,
                compartment_id=tenancy_id,
                tags=tags,
            )
            return resource
        candidate = self._find_identity_named(
            list_method,
            compartment_id=tenancy_id,
            name=name,
            tags=tags,
        )
        if candidate is None:
            self._put_intent(kind, operation="create", name=name)
            details_kwargs = {
                "compartment_id": tenancy_id,
                "description": f"BackupSheep live E2E {self.config.run_id}",
                "freeform_tags": tags,
                "name": name,
            }
            if kind == "iam_user":
                # Tenancies backed by OCI Identity Domains require a primary
                # email.  ``example.invalid`` is reserved and cannot deliver
                # mail, while remaining deterministic for crash adoption.
                details_kwargs["email"] = f"{self.config.run_id}@example.invalid"
            details = details_class(**details_kwargs)
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        create_method,
                        **{f"create_{kind.removeprefix('iam_')}_details": details},
                        opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200,),
                    )
                )
            except HarnessError as error:
                candidate = self._find_identity_named(
                    list_method,
                    compartment_id=tenancy_id,
                    name=name,
                    tags=tags,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        resource_id = _require_ocid(_value(candidate, "id"), label=f"{kind} OCID")
        candidate = _data(self._call(getter, **{id_argument: resource_id}))
        self._record_storage(
            kind,
            candidate,
            resource_id=resource_id,
            name=name,
            compartment_id=tenancy_id,
            tags=tags,
        )
        self.intents.clear(kind)
        return candidate

    def _provision_bucket(self, namespace):
        kind = "object_bucket"
        client = self._clients["object"]
        tags = self._storage_tags(kind)
        name = self.names[kind]
        row = self._active_ledger_entry(kind)
        if row:
            bucket = _data(
                self._call(client.get_bucket, namespace_name=namespace, bucket_name=name)
            )
            self._record_storage(
                kind,
                bucket,
                resource_id=row["resource_id"],
                name=name,
                compartment_id=self.config.compartment_id,
                tags=tags,
            )
            return bucket
        buckets = self._list(
            client.list_buckets,
            namespace_name=namespace,
            compartment_id=self.config.compartment_id,
        )
        named = [item for item in buckets if str(_value(item, "name") or "") == name]
        exact = [
            item
            for item in named
            if str(_value(item, "compartment_id") or "") == self.config.compartment_id
            and all(_tags(item).get(key) == value for key, value in tags.items())
        ]
        if len(exact) > 1 or any(item not in exact for item in named):
            raise HarnessError("The reserved OCI bucket name is ambiguous or foreign.")
        bucket = exact[0] if exact else None
        if bucket is None:
            # Object Storage models live in another SDK namespace.
            import oci

            details = oci.object_storage.models.CreateBucketDetails(
                compartment_id=self.config.compartment_id,
                freeform_tags=tags,
                name=name,
                public_access_type=oci.object_storage.models.CreateBucketDetails.PUBLIC_ACCESS_TYPE_NO_PUBLIC_ACCESS,
                storage_tier=oci.object_storage.models.CreateBucketDetails.STORAGE_TIER_STANDARD,
                versioning=oci.object_storage.models.CreateBucketDetails.VERSIONING_ENABLED,
            )
            self._put_intent(kind, operation="create", name=name)
            try:
                bucket = _data(
                    self._mutation_call(
                        kind,
                        client.create_bucket,
                        namespace_name=namespace,
                        create_bucket_details=details,
                        opc_client_request_id=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200,),
                    )
                )
            except HarnessError as error:
                buckets = self._list(
                    client.list_buckets,
                    namespace_name=namespace,
                    compartment_id=self.config.compartment_id,
                )
                exact = [
                    item
                    for item in buckets
                    if str(_value(item, "name") or "") == name
                    and all(_tags(item).get(key) == value for key, value in tags.items())
                ]
                if len(exact) != 1:
                    if not exact:
                        self._clear_definitely_rejected_intent(kind, error)
                    raise
                bucket = exact[0]
        bucket = _data(
            self._call(client.get_bucket, namespace_name=namespace, bucket_name=name)
        )
        bucket_id = _require_ocid(_value(bucket, "id"), label="bucket OCID", resource_type="bucket")
        if str(_value(bucket, "versioning") or "").upper() != "ENABLED":
            raise HarnessError("The test bucket must have versioning enabled.")
        self._record_storage(
            kind,
            bucket,
            resource_id=bucket_id,
            name=name,
            compartment_id=self.config.compartment_id,
            tags=tags,
        )
        self.intents.clear(kind)
        return bucket

    def _provision_membership(self, tenancy_id, user, group):
        kind = "iam_membership"
        user_id = str(_value(user, "id") or "")
        group_id = str(_value(group, "id") or "")
        row = self._active_ledger_entry(kind)
        if row:
            membership = _data(
                self._call(
                    self._clients["identity"].get_user_group_membership,
                    user_group_membership_id=row["resource_id"],
                )
            )
        else:
            memberships = self._list(
                self._clients["identity"].list_user_group_memberships,
                compartment_id=tenancy_id,
                user_id=user_id,
                group_id=group_id,
            )
            exact = [
                item
                for item in memberships
                if str(_value(item, "user_id") or "") == user_id
                and str(_value(item, "group_id") or "") == group_id
                and str(_value(item, "lifecycle_state") or "").upper() == "ACTIVE"
            ]
            if len(exact) > 1 or any(item not in exact for item in memberships):
                raise HarnessError("OCI IAM group membership is ambiguous.")
            membership = exact[0] if exact else None
            if membership is None:
                import oci

                self._put_intent(kind, operation="create", name=kind)
                details = oci.identity.models.AddUserToGroupDetails(
                    group_id=group_id,
                    user_id=user_id,
                )
                try:
                    membership = _data(
                        self._mutation_call(
                            kind,
                            self._clients["identity"].add_user_to_group,
                            add_user_to_group_details=details,
                            opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                            accepted=(200,),
                        )
                    )
                except HarnessError as error:
                    memberships = self._list(
                        self._clients["identity"].list_user_group_memberships,
                        compartment_id=tenancy_id,
                        user_id=user_id,
                        group_id=group_id,
                    )
                    exact = [
                        item
                        for item in memberships
                        if str(_value(item, "user_id") or "") == user_id
                        and str(_value(item, "group_id") or "") == group_id
                    ]
                    if len(exact) != 1:
                        if not exact:
                            self._clear_definitely_rejected_intent(kind, error)
                        raise
                    membership = exact[0]
        membership_id = _require_ocid(
            _value(membership, "id"), label="IAM membership OCID"
        )
        self._record_storage(
            kind,
            membership,
            resource_id=membership_id,
            name="",
            compartment_id=tenancy_id,
            relationships={"user_id": user_id, "group_id": group_id},
        )
        self.intents.clear(kind)
        return membership

    def _policy_statements(self, group_name):
        bucket_name = self.names["object_bucket"]
        compartment = self.config.compartment_id
        return [
            f"Allow group {group_name} to inspect buckets in compartment id {compartment}",
            (
                f"Allow group {group_name} to manage objects in compartment id "
                f"{compartment} where target.bucket.name = '{bucket_name}'"
            ),
        ]

    def _provision_policy(self, group):
        kind = "iam_policy"
        client = self._clients["identity"]
        name = self.names[kind]
        group_name = str(_value(group, "name") or "")
        statements = self._policy_statements(group_name)
        tags = self._storage_tags(kind)
        row = self._active_ledger_entry(kind)
        if row:
            policy = _data(self._call(client.get_policy, policy_id=row["resource_id"]))
        else:
            policy = self._find_identity_named(
                client.list_policies,
                compartment_id=self.config.compartment_id,
                name=name,
                tags=tags,
            )
            if policy is None:
                import oci

                self._put_intent(kind, operation="create", name=name)
                details = oci.identity.models.CreatePolicyDetails(
                    compartment_id=self.config.compartment_id,
                    description=f"BackupSheep live E2E {self.config.run_id}",
                    freeform_tags=tags,
                    name=name,
                    statements=statements,
                )
                try:
                    policy = _data(
                        self._mutation_call(
                            kind,
                            client.create_policy,
                            create_policy_details=details,
                            opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                            accepted=(200,),
                        )
                    )
                except HarnessError as error:
                    policy = self._find_identity_named(
                        client.list_policies,
                        compartment_id=self.config.compartment_id,
                        name=name,
                        tags=tags,
                    )
                    if policy is None:
                        self._clear_definitely_rejected_intent(kind, error)
                        raise
        policy_id = _require_ocid(_value(policy, "id"), label="IAM policy OCID")
        policy = _data(self._call(client.get_policy, policy_id=policy_id))
        if list(_value(policy, "statements") or []) != statements:
            raise HarnessError("OCI IAM policy statements did not match exactly.")
        self._record_storage(
            kind,
            policy,
            resource_id=policy_id,
            name=name,
            compartment_id=self.config.compartment_id,
            tags=tags,
        )
        self.intents.clear(kind)
        return policy

    def _secret_path(self):
        configured = self.environment.get("ORACLE_E2E_SECRET_FILE")
        if configured:
            path = _safe_path(configured, variable="ORACLE_E2E_SECRET_FILE")
        else:
            path = self.config.ledger_path.with_name(
                self.config.ledger_path.name + ".oracle-object-storage-credentials.json"
            ).resolve()
        try:
            relative = path.relative_to(ROOT)
        except ValueError:
            return path
        if relative.parts and relative.parts[0] == ".git":
            return path
        ignored = subprocess.run(
            ["git", "check-ignore", "--quiet", "--", str(path)],
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
        if not ignored:
            raise HarnessError(
                "ORACLE_E2E_SECRET_FILE must be outside the repository or Git-ignored."
            )
        return path

    def _write_storage_secret(self, payload):
        path = self._secret_path()
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self._atomic_private_write(path, encoded, 0o600)
        if path.stat().st_mode & 0o077:
            raise HarnessError("Oracle storage credential file permissions are unsafe.")
        return path

    def _read_storage_secret(self):
        path = self._secret_path()
        if not path.exists():
            return None
        if path.stat().st_mode & 0o077:
            raise HarnessError("Oracle storage credential file permissions are unsafe.")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise HarnessError("Oracle storage credential file is malformed.") from error
        required = {
            "access_key_id",
            "secret_access_key",
            "bucket",
            "namespace",
            "region",
            "endpoint",
            "prefix",
            "user_ocid",
        }
        if not isinstance(payload, dict) or not required.issubset(payload):
            raise HarnessError("Oracle storage credential file is incomplete.")
        return payload

    def _provision_customer_secret_key(self, user, *, namespace, region, bucket):
        kind = "customer_secret_key"
        client = self._clients["identity"]
        user_id = str(_value(user, "id") or "")
        name = self.names[kind]
        secret_file = self._read_storage_secret()
        keys = self._list_unpaged(client.list_customer_secret_keys, user_id=user_id)
        named = [item for item in keys if str(_value(item, "display_name") or "") == name]
        row = self._active_ledger_entry(kind)
        if len(named) > 1:
            raise HarnessError("Multiple OCI customer secret keys use the run name.")
        if any(str(_value(item, "user_id") or "") != user_id for item in named):
            raise HarnessError("OCI customer secret key ownership is ambiguous.")
        key = named[0] if named else None
        if row:
            if key is None or str(_value(key, "id") or "") != row["resource_id"]:
                raise HarnessError("Ledgered OCI customer secret key could not be reverified.")
            if not secret_file or secret_file.get("access_key_id") != row["resource_id"]:
                raise HarnessError(
                    "The one-time OCI storage secret is unavailable; cleanup is required before reprovisioning."
                )
        elif key is not None:
            if not secret_file or secret_file.get("access_key_id") != str(_value(key, "id") or ""):
                self._record_storage(
                    kind,
                    key,
                    resource_id=_value(key, "id"),
                    name=name,
                    compartment_id="",
                    relationships={"user_id": user_id},
                )
                raise HarnessError(
                    "An exact customer secret key exists but its one-time secret was lost; cleanup is required."
                )
        else:
            import oci

            self._put_intent(kind, operation="create", name=name)
            details = oci.identity.models.CreateCustomerSecretKeyDetails(display_name=name)
            try:
                key = _data(
                    self._mutation_call(
                        kind,
                        client.create_customer_secret_key,
                        create_customer_secret_key_details=details,
                        user_id=user_id,
                        opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200,),
                    )
                )
            except HarnessError as error:
                keys = self._list_unpaged(
                    client.list_customer_secret_keys, user_id=user_id
                )
                exact = [
                    item for item in keys if str(_value(item, "display_name") or "") == name
                ]
                if len(exact) == 1:
                    self._record_storage(
                        kind,
                        exact[0],
                        resource_id=_value(exact[0], "id"),
                        name=name,
                        compartment_id="",
                        relationships={"user_id": user_id},
                    )
                    raise HarnessError(
                        "OCI accepted the customer-secret request but the one-time secret response was lost; cleanup is required."
                    )
                if not exact:
                    self._clear_definitely_rejected_intent(kind, error)
                raise
            secret = str(_value(key, "key") or "")
            key_id = _require_customer_secret_key_id(_value(key, "id"))
            if not secret:
                raise HarnessError("OCI omitted the one-time customer secret value.")
            endpoint = f"https://{namespace}.compat.objectstorage.{region}.oraclecloud.com"
            secret_file = {
                "access_key_id": key_id,
                "secret_access_key": secret,
                "bucket": str(_value(bucket, "name") or ""),
                "namespace": namespace,
                "region": region,
                "endpoint": endpoint,
                "prefix": f"{self.config.run_id}/",
                "user_ocid": user_id,
            }
            self._write_storage_secret(secret_file)
        expected_secret_scope = {
            "bucket": str(_value(bucket, "name") or ""),
            "namespace": namespace,
            "region": region,
            "endpoint": f"https://{namespace}.compat.objectstorage.{region}.oraclecloud.com",
            "prefix": f"{self.config.run_id}/",
            "user_ocid": user_id,
        }
        if not secret_file or any(
            str(secret_file.get(field) or "") != expected
            for field, expected in expected_secret_scope.items()
        ):
            raise HarnessError("Oracle storage credential file scope does not match the run.")
        key_id = _require_customer_secret_key_id(_value(key, "id"))
        self._record_storage(
            kind,
            key,
            resource_id=key_id,
            name=name,
            compartment_id="",
            relationships={"user_id": user_id},
        )
        self.intents.clear(kind)
        return key, self._secret_path()

    def _s3_preflight(self, secret_path):
        client, secret = self._storage_s3_client(secret_path)
        payload = hashlib.sha256(
            f"{self.config.run_id}:oracle-object-storage".encode("utf-8")
        ).digest()
        digest = hashlib.sha256(payload).hexdigest()
        key = f"{secret['prefix']}_harness/preflight.bin"
        deadline = time.monotonic() + min(self.config.timeout_seconds, 300)
        while True:
            try:
                result = client.put_object(
                    Bucket=secret["bucket"],
                    Key=key,
                    Body=payload,
                    ContentLength=len(payload),
                    Metadata={"backupsheep-sha256": digest, "backupsheep-run": self.config.run_id},
                )
                head = client.head_object(Bucket=secret["bucket"], Key=key)
                break
            except Exception as error:
                if time.monotonic() >= deadline:
                    raise HarnessError(
                        "OCI least-privilege S3 credential did not become usable within the bounded waiter."
                    ) from error
                self._sleep(self.config.poll_seconds)
        if (
            int(head.get("ContentLength") or -1) != len(payload)
            or str((head.get("Metadata") or {}).get("backupsheep-sha256") or "")
            != digest
            or not str(result.get("ETag") or head.get("ETag") or "").strip('"')
            or not str(result.get("VersionId") or head.get("VersionId") or "")
        ):
            raise HarnessError("OCI S3 preflight did not return complete integrity/version evidence.")
        evidence = {
            "operation": "evidence",
            "kind": "object_storage_preflight",
            "name": key,
            "marker": self.config.run_id,
            "sha256": digest,
            "byte_count": len(payload),
            "etag": str(result.get("ETag") or head.get("ETag") or "").strip('"'),
            "version_id": str(result.get("VersionId") or head.get("VersionId") or ""),
            "object_key": key,
        }
        self.evidence.put("object_storage_preflight", evidence)
        return evidence

    @staticmethod
    def _storage_s3_client(secret_path):
        try:
            import boto3
            from botocore.config import Config

            secret = json.loads(secret_path.read_text(encoding="utf-8"))
            client = boto3.client(
                "s3",
                aws_access_key_id=secret["access_key_id"],
                aws_secret_access_key=secret["secret_access_key"],
                endpoint_url=secret["endpoint"],
                region_name=secret["region"],
                config=Config(
                    signature_version="s3v4",
                    connect_timeout=REQUEST_TIMEOUT[0],
                    read_timeout=REQUEST_TIMEOUT[1],
                    retries={"max_attempts": 3, "mode": "standard"},
                    s3={"addressing_style": "path"},
                    request_checksum_calculation="when_required",
                    response_checksum_validation="when_required",
                ),
            )
        except Exception as error:
            raise HarnessError("Could not initialize the OCI S3 compatibility client.") from error
        return client, secret

    def _provision_storage(self):
        tenancy_id, region, namespace = self._storage_context()
        import oci

        bucket = self._provision_bucket(namespace)
        user = self._provision_iam_named(
            kind="iam_user",
            tenancy_id=tenancy_id,
            list_method=self._clients["identity"].list_users,
            create_method=self._clients["identity"].create_user,
            details_class=oci.identity.models.CreateUserDetails,
        )
        group = self._provision_iam_named(
            kind="iam_group",
            tenancy_id=tenancy_id,
            list_method=self._clients["identity"].list_groups,
            create_method=self._clients["identity"].create_group,
            details_class=oci.identity.models.CreateGroupDetails,
        )
        membership = self._provision_membership(tenancy_id, user, group)
        policy = self._provision_policy(group)
        key, secret_path = self._provision_customer_secret_key(
            user,
            namespace=namespace,
            region=region,
            bucket=bucket,
        )
        preflight = self._s3_preflight(secret_path)
        return {
            "bucket_ocid": str(_value(bucket, "id") or ""),
            "bucket_name": str(_value(bucket, "name") or ""),
            "namespace": namespace,
            "region": region,
            "prefix": f"{self.config.run_id}/",
            "iam_user_ocid": str(_value(user, "id") or ""),
            "iam_group_ocid": str(_value(group, "id") or ""),
            "iam_membership_ocid": str(_value(membership, "id") or ""),
            "iam_policy_ocid": str(_value(policy, "id") or ""),
            "credential_file": str(secret_path),
            "credential_values_printed": False,
            "preflight": preflight,
        }

    def _load_ui_manifest(self, path):
        path = _safe_path(path, variable="--ui-manifest")
        try:
            if path.stat().st_size > 256 * 1024:
                raise HarnessError("Oracle UI manifest exceeds the safety limit.")
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except HarnessError:
            raise
        except (OSError, ValueError) as error:
            raise HarnessError("Oracle UI manifest is unreadable or malformed.") from error
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") != 1
            or manifest.get("run_id") != self.config.run_id
            or manifest.get("compartment_id") != self.config.compartment_id
        ):
            raise HarnessError("Oracle UI manifest does not match this exact run.")
        for kind in ("compute", "block", "boot"):
            section = manifest.get(kind)
            if not isinstance(section, dict):
                raise HarnessError(f"Oracle UI manifest is missing {kind} evidence.")
            for field in ("source_ocid", "backup", "restore"):
                if field not in section:
                    raise HarnessError(f"Oracle UI manifest {kind}.{field} is required.")
            if not isinstance(section["backup"], dict) or not isinstance(section["restore"], dict):
                raise HarnessError(f"Oracle UI manifest {kind} evidence is malformed.")
        storage = manifest.get("storage")
        if not isinstance(storage, dict) or not isinstance(storage.get("objects"), list):
            raise HarnessError("Oracle UI manifest storage.objects is required.")
        return manifest

    @staticmethod
    def _backup_tags(marker, source_id, kind):
        return {
            BACKUP_MARKER_TAG: marker,
            BACKUP_SOURCE_TAG: source_id,
            BACKUP_KIND_TAG: kind,
            BACKUP_REQUEST_TAG: _retry_token(marker),
        }

    @staticmethod
    def _restore_tags(evidence, *, source_backup_id, source_id, target_type):
        marker = str(evidence.get("marker") or "")
        request_token = str(evidence.get("request_token") or "")
        if not marker or not re.fullmatch(r"bs-[a-f0-9]{61}", request_token):
            raise HarnessError("Oracle UI restore marker/request token is malformed.")
        return {
            RESTORE_MARKER_TAG: marker,
            RESTORE_SOURCE_TAG: source_backup_id,
            RESTORE_ORIGIN_TAG: source_id,
            BACKUP_KIND_TAG: target_type,
            BACKUP_REQUEST_TAG: request_token,
        }

    def _verify_ui_backup(self, kind, section, source_row):
        evidence = section["backup"]
        marker = str(evidence.get("marker") or "")
        if not marker:
            raise HarnessError(f"Oracle UI {kind} backup marker is required.")
        source_id = _require_ocid(section["source_ocid"], label=f"{kind} source OCID")
        if source_id != source_row["resource_id"]:
            raise HarnessError(f"Oracle UI {kind} source OCID is not ledger-owned.")
        backup_id = _require_ocid(evidence.get("ocid"), label=f"{kind} backup OCID")
        if kind == "compute":
            resource = _data(
                self._call(self._clients["compute"].get_image, image_id=backup_id)
            )
            provider_kind = "compute_image"
            ledger_kind = "ui_compute_backup"
            actual_source = _tags(resource).get(BACKUP_SOURCE_TAG)
        elif kind == "boot":
            resource = _data(
                self._call(
                    self._clients["block"].get_boot_volume_backup,
                    boot_volume_backup_id=backup_id,
                )
            )
            provider_kind = "boot"
            ledger_kind = "ui_boot_backup"
            actual_source = _value(resource, "boot_volume_id")
        else:
            resource = _data(
                self._call(
                    self._clients["block"].get_volume_backup,
                    volume_backup_id=backup_id,
                )
            )
            provider_kind = "block"
            ledger_kind = "ui_block_backup"
            actual_source = _value(resource, "volume_id")
        if str(_value(resource, "lifecycle_state") or "").upper() != "AVAILABLE":
            raise HarnessError(f"Oracle UI {kind} backup is not AVAILABLE.")
        tags = self._backup_tags(marker, source_id, provider_kind)
        proof = self._expected_proof(name=marker, tags=tags, source_id=source_id)
        self._record(
            ledger_kind,
            resource,
            proof,
            source_witness=source_id,
            source_id=actual_source,
        )
        return resource

    def _verify_ui_restore(self, kind, section, source_row, backup):
        evidence = section["restore"]
        source_id = source_row["resource_id"]
        backup_id = str(_value(backup, "id") or "")
        restore_id = _require_ocid(evidence.get("ocid"), label=f"{kind} restore OCID")
        name = str(evidence.get("name") or "")
        if not name:
            raise HarnessError(f"Oracle UI {kind} restore name is required.")
        if kind == "compute":
            resource = _data(
                self._call(self._clients["compute"].get_instance, instance_id=restore_id)
            )
            target_type = "instance"
            ledger_kind = "ui_compute_restore"
            ready = {"RUNNING", "STOPPED"}
        elif kind == "boot":
            resource = _data(
                self._call(
                    self._clients["block"].get_boot_volume,
                    boot_volume_id=restore_id,
                )
            )
            target_type = "boot_volume"
            ledger_kind = "ui_boot_restore"
            ready = {"AVAILABLE"}
        else:
            resource = _data(
                self._call(self._clients["block"].get_volume, volume_id=restore_id)
            )
            target_type = "volume"
            ledger_kind = "ui_block_restore"
            ready = {"AVAILABLE"}
        if str(_value(resource, "lifecycle_state") or "").upper() not in ready:
            raise HarnessError(f"Oracle UI {kind} restore is not ready for verification.")
        tags = self._restore_tags(
            evidence,
            source_backup_id=backup_id,
            source_id=source_id,
            target_type=target_type,
        )
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
            source_id=backup_id,
        )
        self._record(
            ledger_kind,
            resource,
            proof,
            source_witness=backup_id,
            source_id=_source_id(resource),
        )
        return resource

    def _record_instance_vnic(self, instance, *, ledger_kind, name, tags):
        instance_id = str(_value(instance, "id") or "")
        row = self._active_ledger_entry(ledger_kind)
        if row:
            vnic = _data(
                self._call(
                    self._clients["network"].get_vnic,
                    vnic_id=row["resource_id"],
                )
            )
        else:
            attachments = self._list(
                self._clients["compute"].list_vnic_attachments,
                compartment_id=self.config.compartment_id,
                instance_id=instance_id,
            )
            exact = [
                item
                for item in attachments
                if str(_value(item, "instance_id") or "") == instance_id
                and str(_value(item, "lifecycle_state") or "").upper() == "ATTACHED"
            ]
            if len(exact) != 1:
                raise HarnessError("Oracle verification instance VNIC is ambiguous.")
            vnic_id = _require_ocid(
                _value(exact[0], "vnic_id"), label="verification VNIC", resource_type="vnic"
            )
            vnic = _data(
                self._call(self._clients["network"].get_vnic, vnic_id=vnic_id)
            )
        proof = self._expected_proof(name=name, tags=tags)
        proof["subnet_id"] = _require_ocid(
            _value(vnic, "subnet_id"), label="verification VNIC subnet", resource_type="subnet"
        )
        self._record(
            ledger_kind,
            vnic,
            proof,
            source_witness=instance_id,
        )
        return vnic

    def _attach_restored_block(self, instance, restored_volume):
        kind = "ui_block_restore_attachment"
        client = self._clients["compute"]
        existing = self._source_from_ledger(
            kind, client.get_volume_attachment, "volume_attachment_id"
        )
        if existing:
            return existing
        instance_id = str(_value(instance, "id") or "")
        volume_id = str(_value(restored_volume, "id") or "")
        attachments = self._list(
            client.list_volume_attachments,
            compartment_id=self.config.compartment_id,
            volume_id=volume_id,
        )
        attachments = [
            item
            for item in attachments
            if str(_value(item, "lifecycle_state") or "").upper() != "DETACHED"
        ]
        device = self._require_attachment_device(
            instance_id, RESTORE_BLOCK_DEVICE
        )
        matching = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "volume_id") or "") == volume_id
            and str(_value(item, "display_name") or "") == self.names[kind]
            and bool(_value(item, "is_read_only"))
            and str(_value(item, "device") or "") == device
        ]
        if len(matching) > 1 or any(item not in matching for item in attachments):
            raise HarnessError("Restored block volume has a foreign or ambiguous attachment.")
        candidate = matching[0] if matching else None
        if candidate is None:
            self._put_intent(kind, operation="attach_read_only", name=self.names[kind])
            details = self._models().AttachParavirtualizedVolumeDetails(
                display_name=self.names[kind],
                instance_id=instance_id,
                is_read_only=True,
                is_shareable=False,
                device=device,
                volume_id=volume_id,
            )
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        client.attach_volume,
                        attach_volume_details=details,
                        accepted=(200, 202),
                    )
                )
            except HarnessError as error:
                attachments = self._list(
                    client.list_volume_attachments,
                    compartment_id=self.config.compartment_id,
                    volume_id=volume_id,
                )
                attachments = [
                    item
                    for item in attachments
                    if str(_value(item, "lifecycle_state") or "").upper()
                    != "DETACHED"
                ]
                matching = [
                    item
                    for item in attachments
                    if str(_value(item, "instance_id") or "") == instance_id
                    and str(_value(item, "volume_id") or "") == volume_id
                    and str(_value(item, "display_name") or "") == self.names[kind]
                    and bool(_value(item, "is_read_only"))
                    and str(_value(item, "device") or "") == device
                ]
                if len(matching) != 1:
                    if not matching:
                        self._clear_definitely_rejected_intent(kind, error)
                    raise
                candidate = matching[0]
        attachment_id = _require_ocid(
            _value(candidate, "id"), label="restored block attachment", resource_type="volumeattachment"
        )
        attachment = self._wait_state(
            lambda value: self._call(
                client.get_volume_attachment, volume_attachment_id=value
            ),
            resource_id=attachment_id,
            ready={"ATTACHED"},
            failed={"DETACHED", "DETACHING"},
        )
        proof = self._expected_proof(name=self.names[kind], tags={})
        proof.update(
            {"instance_id": instance_id, "volume_id": volume_id, "device": device}
        )
        self._record(
            kind,
            attachment,
            proof,
            source_witness=f"{instance_id}:{volume_id}",
        )
        self.intents.clear(kind)
        return attachment

    def _launch_boot_verifier(self, restored_boot, *, subnet_id, shape):
        kind = "ui_boot_verify_instance"
        client = self._clients["compute"]
        boot_id = _require_ocid(
            _value(restored_boot, "id"),
            label="restored boot volume",
            resource_type="bootvolume",
        )
        row = self._active_ledger_entry(kind)
        if row:
            if (
                str(row.get("source_witness") or "") != boot_id
                or str((row.get("ownership") or {}).get("source_id") or "")
                != boot_id
            ):
                raise HarnessError(
                    "The boot verifier ledger source does not match the restored boot volume."
                )
            instance = _data(
                self._call(client.get_instance, instance_id=row["resource_id"])
            )
            self._verify_instance_boot_attachment(row["resource_id"], boot_id)
            self._assert_exact(
                instance,
                resource_id=row["resource_id"],
                proof=row["ownership"],
                source_id=boot_id,
            )
            return instance
        name = self.names[kind]
        tags = self._source_tags(kind)
        candidate = self._find_named(
            client.list_instances,
            name=name,
            tags=tags,
            compartment_id=self.config.compartment_id,
            display_name=name,
        )
        if candidate is None:
            _private, public_key = self._ensure_ssh_key()
            models = self._models()
            details = models.LaunchInstanceDetails(
                availability_domain=self.config.availability_domain,
                compartment_id=self.config.compartment_id,
                create_vnic_details=models.CreateVnicDetails(
                    assign_public_ip=self._assign_public_ip(),
                    display_name=self.names["ui_boot_verify_vnic"],
                    freeform_tags=self._source_tags("ui_boot_verify_vnic"),
                    subnet_id=subnet_id,
                ),
                display_name=name,
                freeform_tags=tags,
                metadata={"ssh_authorized_keys": public_key},
                shape=shape,
                source_details=models.InstanceSourceViaBootVolumeDetails(
                    boot_volume_id=boot_id
                ),
            )
            self._put_intent(kind, operation="launch", name=name)
            try:
                candidate = _data(
                    self._mutation_call(
                        kind,
                        client.launch_instance,
                        launch_instance_details=details,
                        opc_retry_token=_retry_token(f"{self.config.run_id}:{kind}"),
                        accepted=(200, 202),
                    )
                )
            except HarnessError as error:
                candidate = self._find_named(
                    client.list_instances,
                    name=name,
                    tags=tags,
                    compartment_id=self.config.compartment_id,
                    display_name=name,
                )
                if candidate is None:
                    self._clear_definitely_rejected_intent(kind, error)
                    raise
        instance_id = _require_ocid(
            _value(candidate, "id"), label="boot verifier instance", resource_type="instance"
        )
        instance = self._wait_state(
            lambda value: self._call(client.get_instance, instance_id=value),
            resource_id=instance_id,
            ready={"RUNNING", "STOPPED"},
            failed={"TERMINATED", "TERMINATING"},
        )
        self._verify_instance_boot_attachment(instance_id, boot_id)
        proof = self._expected_proof(
            name=name,
            tags=tags,
            availability_domain=self.config.availability_domain,
            source_id=boot_id,
        )
        self._record(
            kind,
            instance,
            proof,
            source_witness=boot_id,
            # OCI reports the original image_id on an instance launched from an
            # existing boot volume. The exact attached boot-volume relationship
            # above is the provider-authoritative source witness.
            source_id=boot_id,
        )
        self.intents.clear(kind)
        return instance

    def _verify_instance_boot_attachment(self, instance_id, expected_boot_id):
        """Require one exact ATTACHED boot volume for a verifier instance."""

        instance_id = _require_ocid(
            instance_id,
            label="boot verifier instance",
            resource_type="instance",
        )
        expected_boot_id = _require_ocid(
            expected_boot_id,
            label="restored boot volume",
            resource_type="bootvolume",
        )
        attachments = self._list(
            self._clients["compute"].list_boot_volume_attachments,
            availability_domain=self.config.availability_domain,
            compartment_id=self.config.compartment_id,
            instance_id=instance_id,
        )
        exact = [
            item
            for item in attachments
            if str(_value(item, "instance_id") or "") == instance_id
            and str(_value(item, "lifecycle_state") or "").upper()
            == "ATTACHED"
        ]
        if len(exact) != 1:
            raise HarnessError(
                "The boot verifier instance attachment graph is ambiguous."
            )
        attached_boot_id = _require_ocid(
            _value(exact[0], "boot_volume_id"),
            label="boot verifier attached volume",
            resource_type="bootvolume",
        )
        if attached_boot_id != expected_boot_id:
            raise HarnessError(
                "The boot verifier instance is attached to a different boot volume."
            )
        return exact[0]

    def _verify_restored_data(
        self,
        *,
        source_instance,
        source_vnic,
        compute_restore,
        block_restore,
        boot_restore,
        compute_restore_tags,
        compute_restore_name,
        subnet_id,
        shape,
    ):
        evidence = self.evidence.get("payload")
        if not isinstance(evidence, dict) or not evidence.get("filesystem_flushed"):
            raise HarnessError("Durable source hash evidence is missing.")
        expected = {
            "sha256": str(evidence.get("sha256") or ""),
            "byte_count": int(evidence.get("byte_count") or -1),
        }
        if not re.fullmatch(r"[a-f0-9]{64}", expected["sha256"]) or expected["byte_count"] <= 0:
            raise HarnessError("Durable source hash evidence is malformed.")

        compute_vnic = self._record_instance_vnic(
            compute_restore,
            ledger_kind="ui_compute_restore_vnic",
            name=f"{compute_restore_name}-vnic"[:255],
            tags=compute_restore_tags,
        )
        self._ledger_compute_restore_boot(compute_restore)
        compute_ssh = self._ssh_client(
            compute_vnic,
            host_variable="ORACLE_E2E_COMPUTE_RESTORE_SSH_HOST",
        )
        try:
            compute_actual = self._remote_evidence(compute_ssh, evidence["boot_path"])
        finally:
            compute_ssh.close()
        if compute_actual != expected:
            raise HarnessError("Compute image restore failed boot-filesystem hash verification.")

        block_attachment = self._attach_restored_block(source_instance, block_restore)
        source_ssh = self._ssh_client(
            source_vnic,
            host_variable="ORACLE_E2E_SOURCE_SSH_HOST",
        )
        restore_mount = f"/mnt/backupsheep-e2e-{self.config.run_id}-restored"
        try:
            self._mount_volume(
                source_ssh,
                block_attachment,
                mount_path=restore_mount,
                read_only=True,
            )
            block_actual = self._remote_evidence(
                source_ssh, f"{restore_mount}/payload.bin"
            )
        finally:
            source_ssh.close()
        if block_actual != expected:
            raise HarnessError("Block-volume restore failed byte/hash verification.")

        boot_instance = self._launch_boot_verifier(
            boot_restore,
            subnet_id=subnet_id,
            shape=shape,
        )
        boot_vnic = self._record_instance_vnic(
            boot_instance,
            ledger_kind="ui_boot_verify_vnic",
            name=self.names["ui_boot_verify_vnic"],
            tags=self._source_tags("ui_boot_verify_vnic"),
        )
        boot_ssh = self._ssh_client(
            boot_vnic,
            host_variable="ORACLE_E2E_BOOT_VERIFY_SSH_HOST",
        )
        try:
            boot_actual = self._remote_evidence(boot_ssh, evidence["boot_path"])
        finally:
            boot_ssh.close()
        if boot_actual != expected:
            raise HarnessError("Boot-volume restore failed byte/hash verification.")
        result = {
            "expected": expected,
            "compute": compute_actual,
            "block": block_actual,
            "boot": boot_actual,
            "all_hashes_match": True,
        }
        self.evidence.put(
            "restore_verification",
            {
                "operation": "evidence",
                "kind": "restore_verification",
                "name": self.config.run_id,
                "marker": self.config.run_id,
                **result,
            },
        )
        return result

    def _verify_storage_objects(self, storage_manifest):
        secret_path = self._secret_path()
        if not secret_path.exists():
            raise HarnessError("Oracle Object Storage credential file is missing.")
        client, secret = self._storage_s3_client(secret_path)
        objects = storage_manifest.get("objects") or []
        kinds = {str(item.get("kind") or "") for item in objects if isinstance(item, dict)}
        if not {"website", "database"}.issubset(kinds):
            raise HarnessError(
                "Oracle storage evidence must include website and database backup objects."
            )
        try:
            maximum = int(
                self.environment.get("ORACLE_E2E_MAX_VERIFY_BYTES", str(20 * 1024**3))
            )
        except (TypeError, ValueError) as error:
            raise HarnessError("ORACLE_E2E_MAX_VERIFY_BYTES must be an integer.") from error
        if not 1 <= maximum <= 1024**4:
            raise HarnessError("ORACLE_E2E_MAX_VERIFY_BYTES is outside safe bounds.")
        verified = []
        seen = set()
        for item in objects:
            if not isinstance(item, dict):
                raise HarnessError("Oracle storage object evidence is malformed.")
            key = str(item.get("key") or "")
            version_id = str(item.get("version_id") or "")
            etag = str(item.get("etag") or "").strip('"')
            checksum = str(item.get("sha256") or "").lower()
            try:
                byte_count = int(item.get("byte_count"))
            except (TypeError, ValueError) as error:
                raise HarnessError("Oracle storage byte-count evidence is malformed.") from error
            identity = (key, version_id)
            if identity in seen:
                raise HarnessError("Oracle storage manifest contains a duplicate object version.")
            seen.add(identity)
            if (
                not key.startswith(secret["prefix"])
                or ".." in Path(key).parts
                or not version_id
                or version_id == "null"
                or not etag
                or not re.fullmatch(r"[a-f0-9]{64}", checksum)
                or byte_count < 0
                or byte_count > maximum
            ):
                raise HarnessError("Oracle storage object witness failed validation.")
            try:
                head = client.head_object(
                    Bucket=secret["bucket"], Key=key, VersionId=version_id
                )
                result = client.get_object(
                    Bucket=secret["bucket"], Key=key, VersionId=version_id
                )
                digest = hashlib.sha256()
                observed = 0
                while True:
                    chunk = result["Body"].read(1024 * 1024)
                    if not chunk:
                        break
                    observed += len(chunk)
                    if observed > maximum:
                        raise HarnessError("Oracle storage object exceeded the byte safety limit.")
                    digest.update(chunk)
                result["Body"].close()
            except HarnessError:
                raise
            except Exception as error:
                raise HarnessError("Oracle storage object verification failed.") from error
            metadata = head.get("Metadata") or {}
            if (
                str(head.get("VersionId") or "") != version_id
                or str(head.get("ETag") or "").strip('"') != etag
                or int(head.get("ContentLength") or -1) != byte_count
                or str(metadata.get("backupsheep-sha256") or "").lower() != checksum
                or str(metadata.get("backupsheep-bytes") or "") != str(byte_count)
                or observed != byte_count
                or digest.hexdigest() != checksum
            ):
                raise HarnessError("Oracle storage object failed hash/version/size verification.")
            record = {
                "kind": str(item.get("kind") or ""),
                "key": key,
                "version_id": version_id,
                "etag": etag,
                "sha256": checksum,
                "byte_count": byte_count,
            }
            self.evidence.put(
                f"storage-{hashlib.sha256(f'{key}:{version_id}'.encode()).hexdigest()[:24]}",
                {
                    "operation": "evidence",
                    "kind": "storage_object",
                    "name": key,
                    "marker": self.config.run_id,
                    **record,
                },
            )
            verified.append(record)
        return {"objects_verified": len(verified), "objects": verified}

    def provision(self):
        """Create only run-owned sources and destination fixtures under APPLY."""

        self._require_apply()
        self._load_clients()
        self._validate_scope()
        subnet_id, image_id, shape = self._validate_instance_inputs()
        self._ensure_ssh_key()
        block = self._provision_block_volume()
        instance = self._provision_instance(subnet_id, image_id, shape)
        vnic = self._provision_vnic(instance)
        boot = self._provision_boot_volume(instance)
        attachment = self._attach_source_block(instance, block)
        data = self._seed_data(
            vnic,
            attachment,
            instance_id=str(_value(instance, "id") or ""),
            block_volume_id=str(_value(block, "id") or ""),
            boot_volume_id=str(_value(boot, "id") or ""),
        )
        storage = self._provision_storage()
        return {
            "phase": "PROVISIONED",
            "run_id": self.config.run_id,
            "compartment_id": self.config.compartment_id,
            "availability_domain": self.config.availability_domain,
            "ui_attachment": {
                "compute_instance_ocid": str(_value(instance, "id") or ""),
                "block_volume_ocid": str(_value(block, "id") or ""),
                "boot_volume_ocid": str(_value(boot, "id") or ""),
            },
            "source_graph": {
                "vnic_ocid": str(_value(vnic, "id") or ""),
                "block_attachment_ocid": str(_value(attachment, "id") or ""),
            },
            "data_evidence": {
                "sha256": data["sha256"],
                "byte_count": data["byte_count"],
                "filesystem_flushed": data["filesystem_flushed"],
            },
            "object_storage": storage,
        }

    def verify(self, manifest_path):
        """Verify UI outputs, including exact resource identity and payload bytes."""

        # Block attach and boot verifier launch are provider mutations.  They are
        # never hidden inside a read-only verification invocation.
        self._require_apply()
        self._load_clients()
        self._validate_scope()
        subnet_id, _image_id, shape = self._validate_instance_inputs()
        manifest = self._load_ui_manifest(manifest_path)
        source_rows = {
            "compute": self._active_ledger_entry("source_instance"),
            "block": self._active_ledger_entry("source_block_volume"),
            "boot": self._active_ledger_entry("source_boot_volume"),
        }
        if any(row is None for row in source_rows.values()):
            raise HarnessError("All Oracle source OCIDs must exist in the durable ledger.")
        source_instance = self._source_from_ledger(
            "source_instance", self._clients["compute"].get_instance, "instance_id"
        )
        source_vnic = self._source_from_ledger(
            "source_vnic", self._clients["network"].get_vnic, "vnic_id"
        )
        backups = {
            kind: self._verify_ui_backup(kind, manifest[kind], source_rows[kind])
            for kind in ("compute", "block", "boot")
        }
        restores = {
            kind: self._verify_ui_restore(
                kind,
                manifest[kind],
                source_rows[kind],
                backups[kind],
            )
            for kind in ("compute", "block", "boot")
        }
        compute_restore_evidence = manifest["compute"]["restore"]
        compute_tags = self._restore_tags(
            compute_restore_evidence,
            source_backup_id=str(_value(backups["compute"], "id") or ""),
            source_id=source_rows["compute"]["resource_id"],
            target_type="instance",
        )
        data = self._verify_restored_data(
            source_instance=source_instance,
            source_vnic=source_vnic,
            compute_restore=restores["compute"],
            block_restore=restores["block"],
            boot_restore=restores["boot"],
            compute_restore_tags=compute_tags,
            compute_restore_name=str(compute_restore_evidence["name"]),
            subnet_id=subnet_id,
            shape=shape,
        )
        storage = self._verify_storage_objects(manifest["storage"])
        return {
            "phase": "VERIFIED",
            "run_id": self.config.run_id,
            "backup_ocids": {
                kind: str(_value(resource, "id") or "")
                for kind, resource in backups.items()
            },
            "restore_ocids": {
                kind: str(_value(resource, "id") or "")
                for kind, resource in restores.items()
            },
            "data_evidence": data,
            "storage_evidence": storage,
            "metadata_only": False,
        }

    def _graph_inventory(self, kind):
        compute = self._clients["compute"]
        block = self._clients["block"]
        network = self._clients["network"]
        compartment = self.config.compartment_id
        availability_domain = self.config.availability_domain
        if kind in {"source_instance", "ui_compute_restore", "ui_boot_verify_instance"}:
            return self._list(compute.list_instances, compartment_id=compartment)
        if kind in {"source_block_volume", "ui_block_restore"}:
            return self._list(
                block.list_volumes,
                compartment_id=compartment,
                availability_domain=availability_domain,
            )
        if kind in {
            "source_boot_volume",
            "ui_boot_restore",
            "ui_compute_restore_boot_volume",
        }:
            return self._list(
                block.list_boot_volumes,
                compartment_id=compartment,
                availability_domain=availability_domain,
            )
        if kind == "ui_compute_backup":
            return self._list(compute.list_images, compartment_id=compartment)
        if kind == "ui_block_backup":
            return self._list(block.list_volume_backups, compartment_id=compartment)
        if kind == "ui_boot_backup":
            return self._list(block.list_boot_volume_backups, compartment_id=compartment)
        if kind in {"source_block_attachment", "ui_block_restore_attachment"}:
            return self._list(
                compute.list_volume_attachments,
                compartment_id=compartment,
            )
        if kind in {"source_vnic", "ui_compute_restore_vnic", "ui_boot_verify_vnic"}:
            attachments = self._list(
                compute.list_vnic_attachments,
                compartment_id=compartment,
            )
            resources = []
            seen = set()
            for attachment in attachments:
                if str(_value(attachment, "lifecycle_state") or "").upper() in {
                    "DETACHED",
                    "DETACHING",
                }:
                    continue
                vnic_id = str(_value(attachment, "vnic_id") or "")
                if not vnic_id or vnic_id in seen:
                    continue
                seen.add(vnic_id)
                resources.append(
                    _data(self._call(network.get_vnic, vnic_id=vnic_id))
                )
            return resources
        raise HarnessError(f"Unsupported Oracle cleanup kind: {kind}.")

    def _exact_graph_resource(self, kind, row):
        matches = [
            item
            for item in self._graph_inventory(kind)
            if str(_value(item, "id") or "") == str(row["resource_id"])
        ]
        if len(matches) > 1:
            raise HarnessError("Oracle cleanup inventory contains a duplicate OCID.")
        if not matches:
            return None
        resource = matches[0]
        if kind == "ui_compute_backup":
            source_id = _tags(resource).get(BACKUP_SOURCE_TAG)
        elif kind == "ui_block_backup":
            source_id = _value(resource, "volume_id")
        elif kind == "ui_boot_backup":
            source_id = _value(resource, "boot_volume_id")
        else:
            source_id = None
        self._assert_exact(
            resource,
            resource_id=row["resource_id"],
            proof=row["ownership"],
            source_id=source_id,
        )
        return resource

    def _wait_graph_absent(self, kind, resource_id, *, terminal_ok=False):
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            matches = [
                item
                for item in self._graph_inventory(kind)
                if str(_value(item, "id") or "") == str(resource_id)
            ]
            if not matches:
                return
            if len(matches) > 1:
                raise HarnessError("Oracle cleanup inventory contains a duplicate OCID.")
            state = str(_value(matches[0], "lifecycle_state") or "").upper()
            if terminal_ok and state == "TERMINATED":
                return
            if time.monotonic() >= deadline:
                raise HarnessError("Oracle cleanup waiter reached its bounded timeout.")
            self._sleep(self.config.poll_seconds)

    def _unmount_test_attachment(self, kind):
        if kind not in {"source_block_attachment", "ui_block_restore_attachment"}:
            raise HarnessError("Unsupported Oracle attachment unmount kind.")
        instance_row = self._active_ledger_entry("source_instance")
        vnic_row = self._active_ledger_entry("source_vnic")
        if not instance_row or not vnic_row:
            raise HarnessError(
                "Oracle attachment cleanup lacks its exact instance/VNIC ledger graph."
            )
        instance = self._exact_graph_resource("source_instance", instance_row)
        vnic = self._exact_graph_resource("source_vnic", vnic_row)
        if instance is None or vnic is None:
            raise HarnessError(
                "Oracle attachment cleanup cannot reach its exact test-owned host."
            )
        mount_path = (
            f"/mnt/backupsheep-e2e-{self.config.run_id}"
            if kind == "source_block_attachment"
            else f"/mnt/backupsheep-e2e-{self.config.run_id}-restored"
        )
        client = self._ssh_client(
            vnic,
            host_variable="ORACLE_E2E_SOURCE_SSH_HOST",
        )
        try:
            quoted = shlex.quote(mount_path)
            self._ssh_run(
                client,
                f"if mountpoint -q {quoted}; then sudo umount {quoted}; fi",
            )
            self._ssh_run(client, "sudo sync")
        finally:
            client.close()

    def _cleanup_graph_kind(self, kind):
        row = self._active_ledger_entry(kind)
        if row is None:
            return "NOT_LEDGERED"
        resource = self._exact_graph_resource(kind, row)
        if resource is None:
            self.ledger.mark_cleanup(kind, row["resource_id"], state="absent")
            return "ABSENT"
        resource_id = row["resource_id"]
        try:
            if kind in {"source_block_attachment", "ui_block_restore_attachment"}:
                self._unmount_test_attachment(kind)
                self._call(
                    self._clients["compute"].detach_volume,
                    volume_attachment_id=resource_id,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
                self._wait_graph_absent(kind, resource_id)
            elif kind in {
                "source_instance",
                "ui_compute_restore",
                "ui_boot_verify_instance",
            }:
                self._call(
                    self._clients["compute"].terminate_instance,
                    instance_id=resource_id,
                    preserve_boot_volume=True,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
                self._wait_graph_absent(kind, resource_id, terminal_ok=True)
            elif kind == "ui_compute_backup":
                self._call(
                    self._clients["compute"].delete_image,
                    image_id=resource_id,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
                self._wait_graph_absent(kind, resource_id)
            elif kind == "ui_block_backup":
                self._call(
                    self._clients["block"].delete_volume_backup,
                    volume_backup_id=resource_id,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
                self._wait_graph_absent(kind, resource_id)
            elif kind == "ui_boot_backup":
                self._call(
                    self._clients["block"].delete_boot_volume_backup,
                    boot_volume_backup_id=resource_id,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
                self._wait_graph_absent(kind, resource_id)
            elif kind in {"source_block_volume", "ui_block_restore"}:
                self._call(
                    self._clients["block"].delete_volume,
                    volume_id=resource_id,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
                self._wait_graph_absent(kind, resource_id)
            elif kind in {
                "source_boot_volume",
                "ui_boot_restore",
                "ui_compute_restore_boot_volume",
            }:
                self._call(
                    self._clients["block"].delete_boot_volume,
                    boot_volume_id=resource_id,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
                self._wait_graph_absent(kind, resource_id)
            elif kind in {
                "source_vnic",
                "ui_compute_restore_vnic",
                "ui_boot_verify_vnic",
            }:
                raise HarnessError(
                    "A ledgered VNIC still exists after its exact parent instance was terminated."
                )
            else:
                raise HarnessError("Unsupported Oracle graph cleanup kind.")
        except Exception as error:
            self.ledger.mark_cleanup(
                kind,
                resource_id,
                state="failed",
                error=_provider_error_code(error),
            )
            raise
        self.ledger.mark_cleanup(kind, resource_id, state="deleted")
        return "DELETED"

    def _object_inventory(self, namespace, bucket):
        client = self._clients["object"]
        versions = []
        page = ""
        seen_pages = set()
        for _ in range(MAX_PAGES):
            request = {
                "namespace_name": namespace,
                "bucket_name": bucket,
                "limit": 1000,
            }
            if page:
                request["page"] = page
            response = self._call(client.list_object_versions, **request)
            data = _data(response)
            rows = (
                data
                if isinstance(data, (list, tuple))
                else _value(data, "items", _value(data, "objects"))
            )
            if not isinstance(rows, (list, tuple)):
                raise HarnessError("OCI object-version inventory is malformed.")
            versions.extend(rows)
            if len(versions) > MAX_ITEMS:
                raise HarnessError("OCI object-version inventory exceeded the safety limit.")
            next_page = _next_page(response)
            if not next_page:
                break
            if next_page in seen_pages:
                raise HarnessError("OCI object-version inventory repeated a cursor.")
            seen_pages.add(next_page)
            page = next_page
        else:
            raise HarnessError("OCI object-version inventory exceeded the page limit.")

        objects = []
        start = ""
        seen_starts = set()
        for _ in range(MAX_PAGES):
            request = {
                "namespace_name": namespace,
                "bucket_name": bucket,
                "limit": 1000,
            }
            if start:
                request["start"] = start
            response = self._call(client.list_objects, **request)
            data = _data(response)
            rows = _value(data, "objects")
            if not isinstance(rows, (list, tuple)):
                raise HarnessError("OCI current-object inventory is malformed.")
            objects.extend(rows)
            if len(objects) > MAX_ITEMS:
                raise HarnessError("OCI current-object inventory exceeded the safety limit.")
            next_start = str(_value(data, "next_start_with") or "")
            if not next_start:
                break
            if next_start in seen_starts:
                raise HarnessError("OCI current-object inventory repeated a cursor.")
            seen_starts.add(next_start)
            start = next_start
        else:
            raise HarnessError("OCI current-object inventory exceeded the page limit.")
        return versions, objects

    def _exact_storage_resource(self, kind, row, *, tenancy_id, namespace):
        identity = self._clients["identity"]
        if kind == "object_bucket":
            try:
                response = self._clients["object"].get_bucket(
                    namespace_name=namespace,
                    bucket_name=row["name"],
                )
                items = [_data(_checked(response, {200}))]
            except Exception as error:
                code = _provider_error_code(error)
                if code == "PROVIDER_NOT_FOUND":
                    return None
                raise HarnessError(
                    f"OCI bucket ownership read failed: {code}."
                ) from error
        elif kind == "iam_user":
            items = self._list(identity.list_users, compartment_id=tenancy_id)
        elif kind == "iam_group":
            items = self._list(identity.list_groups, compartment_id=tenancy_id)
        elif kind == "iam_policy":
            items = self._list(
                identity.list_policies,
                compartment_id=self.config.compartment_id,
            )
        elif kind == "iam_membership":
            relationships = row["ownership"].get("relationships") or {}
            items = self._list(
                identity.list_user_group_memberships,
                compartment_id=tenancy_id,
                user_id=relationships.get("user_id"),
                group_id=relationships.get("group_id"),
            )
        elif kind == "customer_secret_key":
            user_id = (row["ownership"].get("relationships") or {}).get("user_id")
            items = self._list_unpaged(
                identity.list_customer_secret_keys, user_id=user_id
            )
        else:
            raise HarnessError("Unsupported OCI storage cleanup kind.")
        matches = [
            item
            for item in items
            if str(_value(item, "id") or "") == str(row["resource_id"])
            and str(_value(item, "lifecycle_state") or "").upper()
            not in {"DELETED", "TERMINATED"}
        ]
        if len(matches) > 1:
            raise HarnessError("OCI IAM/Object Storage inventory contains a duplicate OCID.")
        if not matches:
            return None
        resource = matches[0]
        ownership = row["ownership"]
        if ownership.get("name") and str(
            _value(resource, "name") or _value(resource, "display_name") or ""
        ) != ownership["name"]:
            raise HarnessError("OCI cleanup resource name changed.")
        if ownership.get("compartment_id") and str(
            _value(resource, "compartment_id") or ""
        ) != ownership["compartment_id"]:
            raise HarnessError("OCI cleanup resource compartment changed.")
        expected_tags = ownership.get("tags") or {}
        if any(_tags(resource).get(key) != value for key, value in expected_tags.items()):
            raise HarnessError("OCI cleanup resource ownership tags changed.")
        for field, expected in (ownership.get("relationships") or {}).items():
            if str(_value(resource, field) or "") != str(expected):
                raise HarnessError("OCI cleanup resource relationship changed.")
        if kind == "iam_policy":
            group = self._active_ledger_entry("iam_group")
            if not group:
                raise HarnessError("OCI policy cleanup lacks its group ledger witness.")
            expected = self._policy_statements(group["name"])
            if list(_value(resource, "statements") or []) != expected:
                raise HarnessError("OCI policy statements changed before cleanup.")
        return resource

    def _wait_storage_absent(self, kind, row, *, tenancy_id, namespace):
        deadline = time.monotonic() + self.config.timeout_seconds
        while True:
            if self._exact_storage_resource(
                kind,
                row,
                tenancy_id=tenancy_id,
                namespace=namespace,
            ) is None:
                return
            if time.monotonic() >= deadline:
                raise HarnessError("OCI IAM/Object Storage cleanup waiter timed out.")
            self._sleep(self.config.poll_seconds)

    def _cleanup_bucket(self, row, *, namespace):
        bucket = self._exact_storage_resource(
            "object_bucket",
            row,
            tenancy_id="",
            namespace=namespace,
        )
        if bucket is None:
            self.ledger.mark_cleanup("object_bucket", row["resource_id"], state="absent")
            return "ABSENT"
        bucket_name = row["name"]
        versions, objects = self._object_inventory(namespace, bucket_name)
        prefix = f"{self.config.run_id}/"
        inventory = [*versions, *objects]
        if any(not str(_value(item, "name") or "").startswith(prefix) for item in inventory):
            raise HarnessError(
                "The exact test bucket contains an object outside the run prefix; cleanup is blocked."
            )
        deleted_versions = set()
        for item in versions:
            name = str(_value(item, "name") or "")
            version_id = str(_value(item, "version_id") or "")
            if not name or not version_id:
                raise HarnessError("OCI object-version cleanup witness is malformed.")
            self._call(
                self._clients["object"].delete_object,
                namespace_name=namespace,
                bucket_name=bucket_name,
                object_name=name,
                version_id=version_id,
                accepted=(200, 202, 204),
                mutation=True,
            )
            deleted_versions.add((name, version_id))
        # A versioning-disabled/null object may not appear with a usable version
        # identifier. Delete only current keys inside the exact run prefix.
        versioned_names = {name for name, _version in deleted_versions}
        for item in objects:
            name = str(_value(item, "name") or "")
            if name not in versioned_names:
                self._call(
                    self._clients["object"].delete_object,
                    namespace_name=namespace,
                    bucket_name=bucket_name,
                    object_name=name,
                    accepted=(200, 202, 204),
                    mutation=True,
                )
        remaining_versions, remaining_objects = self._object_inventory(namespace, bucket_name)
        if remaining_versions or remaining_objects:
            raise HarnessError("OCI bucket inventory is not empty after exact object cleanup.")
        self._call(
            self._clients["object"].delete_bucket,
            namespace_name=namespace,
            bucket_name=bucket_name,
            accepted=(200, 202, 204),
            mutation=True,
        )
        self._wait_storage_absent(
            "object_bucket", row, tenancy_id="", namespace=namespace
        )
        self.ledger.mark_cleanup("object_bucket", row["resource_id"], state="deleted")
        return "DELETED"

    def _cleanup_storage_kind(self, kind, *, tenancy_id, namespace):
        row = self._active_ledger_entry(kind)
        if row is None:
            return "NOT_LEDGERED"
        if kind == "object_bucket":
            return self._cleanup_bucket(row, namespace=namespace)
        resource = self._exact_storage_resource(
            kind,
            row,
            tenancy_id=tenancy_id,
            namespace=namespace,
        )
        if resource is None:
            self.ledger.mark_cleanup(kind, row["resource_id"], state="absent")
            return "ABSENT"
        identity = self._clients["identity"]
        try:
            if kind == "customer_secret_key":
                user_id = (row["ownership"].get("relationships") or {})["user_id"]
                self._call(
                    identity.delete_customer_secret_key,
                    user_id=user_id,
                    customer_secret_key_id=row["resource_id"],
                    accepted=(200, 202, 204),
                    mutation=True,
                )
            elif kind == "iam_policy":
                self._call(
                    identity.delete_policy,
                    policy_id=row["resource_id"],
                    accepted=(200, 202, 204),
                    mutation=True,
                )
            elif kind == "iam_membership":
                self._call(
                    identity.remove_user_from_group,
                    user_group_membership_id=row["resource_id"],
                    accepted=(200, 202, 204),
                    mutation=True,
                )
            elif kind == "iam_group":
                self._call(
                    identity.delete_group,
                    group_id=row["resource_id"],
                    accepted=(200, 202, 204),
                    mutation=True,
                )
            elif kind == "iam_user":
                self._call(
                    identity.delete_user,
                    user_id=row["resource_id"],
                    accepted=(200, 202, 204),
                    mutation=True,
                )
            else:
                raise HarnessError("Unsupported OCI IAM cleanup kind.")
            self._wait_storage_absent(
                kind,
                row,
                tenancy_id=tenancy_id,
                namespace=namespace,
            )
        except Exception as error:
            self.ledger.mark_cleanup(
                kind,
                row["resource_id"],
                state="failed",
                error=_provider_error_code(error),
            )
            raise
        self.ledger.mark_cleanup(kind, row["resource_id"], state="deleted")
        return "DELETED"

    def _assert_cleanup_graph_complete(self):
        requirements = {
            "source_instance": {"source_boot_volume", "source_vnic"},
            "ui_compute_restore": {
                "ui_compute_restore_boot_volume",
                "ui_compute_restore_vnic",
            },
            "ui_boot_verify_instance": {"ui_boot_verify_vnic"},
        }
        for parent, dependencies in requirements.items():
            parent_rows = self.ledger.entries(parent)
            if parent_rows and any(not self.ledger.entries(kind) for kind in dependencies):
                raise HarnessError(
                    f"Oracle cleanup is blocked because {parent} has an incomplete dependency ledger."
                )

    def cleanup(self):
        """Delete only exact ledger-owned resources under the separate gate."""

        self._require_cleanup()
        self._load_clients()
        self._validate_scope()
        tenancy_id, _region, namespace = self._storage_context()
        unknown = sorted(
            {
                str(row.get("kind") or "")
                for row in self.ledger.entries()
                if str(row.get("kind") or "") not in ALL_KINDS
            }
        )
        if unknown:
            raise HarnessError("Oracle ledger contains unsupported resource kinds.")
        active_ids = [
            str(row.get("resource_id") or "")
            for row in self.ledger.entries()
            if row.get("cleanup_state") in {"eligible", "failed", "manual_review"}
        ]
        if len(active_ids) != len(set(active_ids)):
            raise HarnessError("Oracle ledger reuses one OCID across active resources.")
        self._assert_cleanup_graph_complete()
        graph_order = [
            "ui_block_restore_attachment",
            "source_block_attachment",
            "ui_boot_verify_instance",
            "ui_boot_verify_vnic",
            "ui_compute_restore",
            "ui_compute_restore_vnic",
            "ui_compute_restore_boot_volume",
            "ui_compute_backup",
            "ui_block_backup",
            "ui_boot_backup",
            "ui_block_restore",
            "ui_boot_restore",
            "source_block_volume",
            "source_instance",
            "source_vnic",
            "source_boot_volume",
        ]
        report = {"graph": {}, "storage": {}, "local_artifacts": {}}
        for kind in graph_order:
            report["graph"][kind] = self._cleanup_graph_kind(kind)

        storage_order = [
            "customer_secret_key",
            "object_bucket",
            "iam_policy",
            "iam_membership",
            "iam_group",
            "iam_user",
        ]
        for kind in storage_order:
            report["storage"][kind] = self._cleanup_storage_kind(
                kind,
                tenancy_id=tenancy_id,
                namespace=namespace,
            )
            if kind == "customer_secret_key":
                secret_path = self._secret_path()
                if secret_path.exists():
                    if report["storage"][kind] not in {"DELETED", "ABSENT"}:
                        raise HarnessError(
                            "Credential file cleanup requires a revoked ledgered key."
                        )
                    secret_path.unlink()
                    report["local_artifacts"]["storage_credentials"] = "DELETED"
                else:
                    report["local_artifacts"]["storage_credentials"] = "ABSENT"

        remaining_graph = [
            row
            for row in self.ledger.entries()
            if row.get("kind") in SOURCE_KINDS | UI_KINDS
            and row.get("cleanup_state") not in {"deleted", "absent"}
        ]
        if not remaining_graph:
            for path in self._key_paths():
                if path.exists():
                    path.unlink()
            report["local_artifacts"]["ssh_material"] = "DELETED"
        else:
            report["local_artifacts"]["ssh_material"] = "RETAINED"
        return {
            "phase": "CLEANED",
            "run_id": self.config.run_id,
            "cleanup": report,
        }


def build_parser():
    parser = argparse.ArgumentParser(
        description="Safety-gated Oracle Cloud live UI support harness."
    )
    parser.add_argument(
        "--phase",
        choices=("plan", "provision", "verify", "cleanup"),
        default="plan",
    )
    parser.add_argument(
        "--ui-manifest",
        help="Exact UI-created OCIDs, markers, and artifact integrity evidence.",
    )
    return parser


def main(argv=None, *, environment=None):
    args = build_parser().parse_args(argv)
    if args.phase == "plan":
        print(json.dumps(OracleLiveUIHarness.inert_plan(), indent=2, sort_keys=True))
        return 0
    environment = dict(os.environ if environment is None else environment)
    try:
        config = HarnessConfig.from_environment(environment)
        harness = OracleLiveUIHarness(config, environment=environment)
        if args.phase == "provision":
            result = harness.provision()
        elif args.phase == "verify":
            if not args.ui_manifest:
                raise HarnessError("--ui-manifest is required for verify.")
            result = harness.verify(args.ui_manifest)
        else:
            result = harness.cleanup()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (HarnessError, LedgerError) as error:
        print(json.dumps({"status": "FAILED_SAFE", "error": str(error)}))
        return 2
    except Exception as error:
        # Never let an SDK/boto/SSH exception render a credential-bearing body.
        print(
            json.dumps(
                {
                    "status": "FAILED_SAFE",
                    "error": f"Oracle harness failed: {_provider_error_code(error)}.",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
