"""Small durable ownership ledger for destructive live E2E harnesses.

The ledger is deliberately independent from Django.  Provider resources become
cleanup-eligible only after a successful create response has been followed by
an exact provider read-back and the resulting ID/witness has been fsynced here.
An attempted create, a generated name, or an inventory match is never enough.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{7,62}$")


class LedgerError(RuntimeError):
    pass


def require_run_id(value):
    run_id = str(value or "").strip()
    if not RUN_ID_RE.fullmatch(run_id):
        raise LedgerError(
            "BACKUPSHEEP_E2E_RUN_ID must be 8-63 lowercase DNS-safe characters."
        )
    return run_id


class DurableResourceLedger:
    """Atomic, locked JSON ledger scoped to one provider test run."""

    def __init__(self, path, *, provider, run_id, scope):
        if not path:
            raise LedgerError(
                "BACKUPSHEEP_E2E_LEDGER_PATH must point to durable storage."
            )
        self.path = Path(path).expanduser().resolve()
        self.provider = str(provider)
        self.run_id = require_run_id(run_id)
        self.scope = str(scope)
        if not self.provider or not self.scope:
            raise LedgerError("Provider and account/project scope are required.")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        with self._locked():
            if self.path.exists():
                self._validate(self._read_unlocked())
            else:
                self._write_unlocked(
                    {
                        "schema": 1,
                        "provider": self.provider,
                        "run_id": self.run_id,
                        "scope": self.scope,
                        "created_at": self._now(),
                        "resources": [],
                    }
                )

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    def _locked(self):
        class _Lock:
            def __init__(inner_self, outer):
                inner_self.outer = outer
                inner_self.handle = None

            def __enter__(inner_self):
                inner_self.handle = open(inner_self.outer._lock_path, "a+", encoding="utf-8")
                os.chmod(inner_self.outer._lock_path, 0o600)
                fcntl.flock(inner_self.handle.fileno(), fcntl.LOCK_EX)
                return inner_self.handle

            def __exit__(inner_self, exc_type, exc, tb):
                fcntl.flock(inner_self.handle.fileno(), fcntl.LOCK_UN)
                inner_self.handle.close()

        return _Lock(self)

    def _validate(self, payload):
        expected = {
            "schema": 1,
            "provider": self.provider,
            "run_id": self.run_id,
            "scope": self.scope,
        }
        if not isinstance(payload, dict) or any(
            payload.get(key) != value for key, value in expected.items()
        ):
            raise LedgerError(
                "The ledger does not match this provider, run ID, or account scope."
            )
        if not isinstance(payload.get("resources"), list):
            raise LedgerError("The resource ledger is malformed.")
        return payload

    def _read_unlocked(self):
        try:
            with open(self.path, encoding="utf-8") as source:
                return json.load(source)
        except (OSError, ValueError) as error:
            raise LedgerError("The durable resource ledger could not be read.") from error

    def _write_unlocked(self, payload):
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(payload, output, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def record(self, *, kind, resource_id, name, ownership, source_witness=None):
        """Persist an exact provider ID only after caller-side read-back proof."""
        resource_id = str(resource_id or "")
        kind = str(kind or "")
        if not resource_id or not kind or not isinstance(ownership, dict) or not ownership:
            raise LedgerError("Resource ID, kind, and ownership proof are required.")
        entry = {
            "kind": kind,
            "resource_id": resource_id,
            "name": str(name or ""),
            "ownership": dict(ownership),
            "source_witness": str(source_witness or ""),
            "created_at": self._now(),
            "cleanup_state": "eligible",
            "cleanup_error": "",
        }
        with self._locked():
            payload = self._validate(self._read_unlocked())
            matches = [
                row
                for row in payload["resources"]
                if row.get("kind") == kind
                and str(row.get("resource_id")) == resource_id
            ]
            if matches:
                comparable = dict(matches[0])
                for key in ("created_at", "cleanup_state", "cleanup_error"):
                    comparable.pop(key, None)
                expected = dict(entry)
                for key in ("created_at", "cleanup_state", "cleanup_error"):
                    expected.pop(key, None)
                if comparable != expected:
                    raise LedgerError("A provider ID is already recorded with another witness.")
                return dict(matches[0])
            payload["resources"].append(entry)
            self._write_unlocked(payload)
        return dict(entry)

    def get(self, kind, resource_id):
        with self._locked():
            payload = self._validate(self._read_unlocked())
        matches = [
            dict(row)
            for row in payload["resources"]
            if row.get("kind") == str(kind)
            and str(row.get("resource_id")) == str(resource_id)
        ]
        if len(matches) > 1:
            raise LedgerError("The durable ledger contains duplicate provider IDs.")
        return matches[0] if matches else None

    def entries(self, kind=None):
        with self._locked():
            payload = self._validate(self._read_unlocked())
        rows = [dict(row) for row in payload["resources"]]
        if kind is not None:
            rows = [row for row in rows if row.get("kind") == str(kind)]
        return rows

    def cleanup_eligible(self, kind, resource_id):
        row = self.get(kind, resource_id)
        return bool(row and row.get("cleanup_state") in {"eligible", "failed"})

    def mark_cleanup(self, kind, resource_id, *, state, error=""):
        if state not in {"deleted", "absent", "failed", "manual_review"}:
            raise LedgerError("Invalid cleanup state.")
        with self._locked():
            payload = self._validate(self._read_unlocked())
            matches = [
                row
                for row in payload["resources"]
                if row.get("kind") == str(kind)
                and str(row.get("resource_id")) == str(resource_id)
            ]
            if len(matches) != 1:
                raise LedgerError("Cleanup cannot update an unrecorded provider resource.")
            matches[0]["cleanup_state"] = state
            matches[0]["cleanup_error"] = str(error or "")[:500]
            matches[0]["cleanup_updated_at"] = self._now()
            self._write_unlocked(payload)
