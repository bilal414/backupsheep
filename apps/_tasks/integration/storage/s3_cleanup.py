"""Provider bindings for exact-owned S3 multipart cleanup."""

from __future__ import annotations

from importlib import import_module


class UnsupportedMultipartCleanupBackend(RuntimeError):
    pass


_S3_CLEANUP_BACKENDS = {
    "aws_s3": ("aws_s3", "storage_aws_s3", "aws_s3_object", False),
    "wasabi": ("wasabi", "storage_wasabi", "wasabi_s3_object", False),
    "do_spaces": (
        "do_spaces",
        "storage_do_spaces",
        "do_spaces_s3_object",
        False,
    ),
    "filebase": ("filebase", "storage_filebase", "filebase_s3_object", False),
    "backblaze_b2": (
        "backblaze_b2",
        "storage_backblaze_b2",
        "backblaze_b2_s3_object",
        False,
    ),
    "linode": ("linode", "storage_linode", "linode_s3_object", False),
    "vultr": ("vultr", "storage_vultr", "vultr_s3_object", True),
    "upcloud": ("upcloud", "storage_upcloud", "upcloud_s3_object", False),
    "exoscale": ("exoscale", "storage_exoscale", "exoscale_s3_object", False),
    "oracle": ("oracle", "storage_oracle", "oracle_s3_object", False),
    "scaleway": ("scaleway", "storage_scaleway", "scaleway_s3_object", False),
    "cloudflare": (
        "cloudflare",
        "storage_cloudflare",
        "cloudflare_r2_s3_object",
        False,
    ),
    "leviia": ("leviia", "storage_leviia", "leviia_s3_object", False),
    "idrive": ("idrive", "storage_idrive", "idrive_s3_object", False),
    "ionos": ("ionos", "storage_ionos", "ionos_s3_object", False),
    "alibaba": ("alibaba", "storage_alibaba", "alibaba_oss_s3_object", False),
    "tencent": ("tencent", "storage_tencent", "tencent_cos_s3_object", False),
    "rackcorp": ("rackcorp", "storage_rackcorp", "rackcorp_s3_object", False),
    "ibm": ("ibm", "storage_ibm", "ibm_cos_s3_object", False),
}


def multipart_cleanup_metadata_key(storage_type_code):
    spec = _S3_CLEANUP_BACKENDS.get(str(storage_type_code or ""))
    return spec[2] if spec else None


def multipart_cleanup_metadata_keys():
    return tuple(sorted({spec[2] for spec in _S3_CLEANUP_BACKENDS.values()}))


def has_owned_multipart_cleanup_candidate(stored_backup):
    metadata_key = multipart_cleanup_metadata_key(stored_backup.storage.type.code)
    if not metadata_key:
        return False
    state = (stored_backup.metadata or {}).get(metadata_key)
    if not isinstance(state, dict):
        return False
    multipart = state.get("multipart")
    if not isinstance(multipart, dict):
        return False
    proof = multipart.get("creation_proof")
    cleanup = state.get("multipart_cleanup")
    complete_intent = multipart.get("complete_intent")
    unsafe_phases = {
        "committed",
        "verifying",
        "creating_multipart",
        "multipart_create_reconciliation_exhausted",
        "multipart_complete_outcome_unknown",
        "multipart_complete_reconciliation_exhausted",
    }
    cleanup_phase = cleanup.get("phase") if isinstance(cleanup, dict) else ""
    return bool(
        isinstance(proof, dict)
        and proof.get("version") == 1
        and multipart.get("upload_id")
        and state.get("phase") not in unsafe_phases
        and not str(state.get("phase") or "").startswith("put_")
        and not (
            isinstance(complete_intent, dict)
            and complete_intent.get("complete")
        )
        and cleanup_phase not in {"complete", "abort_rejected"}
    )


def multipart_cleanup_context(stored_backup):
    storage = stored_backup.storage
    code = str(storage.type.code or "")
    spec = _S3_CLEANUP_BACKENDS.get(code)
    if not spec:
        raise UnsupportedMultipartCleanupBackend(
            "This storage backend does not use the verified S3 multipart contract."
        )
    module_name, relation_name, metadata_key, client_uses_storage = spec
    module = import_module(
        f"apps._tasks.integration.storage.{module_name}"
    )
    backend = getattr(storage, relation_name)
    encryption_key = storage.account.get_encryption_key()
    client_subject = storage if client_uses_storage else backend
    client = module._s3_client(client_subject, encryption_key)
    expected_owner = (
        (backend.expected_bucket_owner or None) if code == "aws_s3" else None
    )
    return {
        "client": client,
        "bucket": backend.bucket_name,
        "metadata_key": metadata_key,
        "expected_owner": expected_owner,
    }
