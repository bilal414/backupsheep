"""Strict, non-secret context binding for backup artifact encryption."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Mapping

from .errors import ArtifactConfigurationError

_INSTALLATION_ID = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_MODEL_LABEL = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
_LANES = frozenset({"database", "files"})
_PURPOSE = "backup-artifact-v1"
_PROVIDER_POLICY_DOMAIN = "BackupSheep/artifact-key-provider/v1"
_PROVIDER_POLICY_GENERATIONS = frozenset({"1", "1-pending-empty"})


def _require_identifier(label: str, value: object) -> str:
    candidate = str(value or "")
    if not _IDENTIFIER.fullmatch(candidate):
        raise ArtifactConfigurationError(
            f"Artifact context {label} must be a bounded non-empty identifier."
        )
    return candidate


def artifact_provider_policy_witness(installation_id: str, generation: str) -> str:
    """Return the non-secret installation/provider/generation drift witness."""

    installation_id = str(installation_id or "")
    generation = str(generation or "")
    if not _INSTALLATION_ID.fullmatch(installation_id):
        raise ArtifactConfigurationError(
            "Artifact provider policy requires a 64-character installation ID."
        )
    if generation not in _PROVIDER_POLICY_GENERATIONS:
        raise ArtifactConfigurationError(
            "Artifact provider policy generation is unsupported."
        )
    return hashlib.sha256(
        (
            f"{_PROVIDER_POLICY_DOMAIN}|{installation_id}|local-file|"
            f"generation={generation}"
        ).encode("ascii")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ArtifactContext:
    """Identity that an artifact and its wrapped data key are bound to.

    Every value is intentionally non-secret inside BackupSheep's custody ledger.
    Its digest is stored only in BSE1 v2's encrypted terminal payload, and the
    same identity is authenticated by the wrapping provider so a data key cannot
    cross installations, backups, or lanes.
    """

    installation_id: str
    account_id: str
    node_id: str
    backup_id: str
    backup_model: str
    lane: str
    purpose: str = _PURPOSE

    def __post_init__(self) -> None:
        if not _INSTALLATION_ID.fullmatch(str(self.installation_id or "")):
            raise ArtifactConfigurationError(
                "Artifact context installation_id must be 64 lowercase hexadecimal characters."
            )
        _require_identifier("account_id", self.account_id)
        _require_identifier("node_id", self.node_id)
        try:
            parsed_backup_id = str(uuid.UUID(str(self.backup_id)))
        except (AttributeError, TypeError, ValueError):
            raise ArtifactConfigurationError(
                "Artifact context backup_id must be a canonical UUID."
            ) from None
        if parsed_backup_id != str(self.backup_id):
            raise ArtifactConfigurationError(
                "Artifact context backup_id must be a canonical UUID."
            )
        if len(str(self.backup_model or "")) > 128 or not _MODEL_LABEL.fullmatch(
            str(self.backup_model or "")
        ):
            raise ArtifactConfigurationError(
                "Artifact context backup_model must be a lowercase Django model label."
            )
        if self.lane not in _LANES:
            raise ArtifactConfigurationError(
                "Artifact context lane must be either 'database' or 'files'."
            )
        if self.purpose != _PURPOSE:
            raise ArtifactConfigurationError(
                "Artifact context purpose is not supported."
            )

    def as_mapping(self) -> dict[str, str]:
        return {
            "account_id": str(self.account_id),
            "backup_id": str(self.backup_id),
            "backup_model": str(self.backup_model),
            "installation_id": str(self.installation_id),
            "lane": str(self.lane),
            "node_id": str(self.node_id),
            "purpose": str(self.purpose),
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_mapping(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def key_provider_context(self) -> dict[str, str]:
        """Return the exact string map available to wrapping providers."""

        values = self.as_mapping()
        return {
            "bse:account-id": values["account_id"],
            "bse:backup-id": values["backup_id"],
            "bse:backup-model": values["backup_model"],
            "bse:context-sha256": self.sha256,
            "bse:installation-id": values["installation_id"],
            "bse:lane": values["lane"],
            "bse:node-id": values["node_id"],
            "bse:purpose": values["purpose"],
        }

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> "ArtifactContext":
        expected = {
            "account_id",
            "backup_id",
            "backup_model",
            "installation_id",
            "lane",
            "node_id",
            "purpose",
        }
        if not isinstance(values, Mapping) or set(values) != expected:
            raise ArtifactConfigurationError(
                "Artifact context must contain exactly the supported identity fields."
            )
        return cls(**{key: str(values[key]) for key in expected})
