from importlib import import_module
from types import SimpleNamespace

from django.test import SimpleTestCase

from apps._tasks.integration.storage.s3_cleanup import (
    _S3_CLEANUP_BACKENDS,
    has_owned_multipart_cleanup_candidate,
    multipart_cleanup_metadata_key,
)


class S3MultipartCleanupRegistryTests(SimpleTestCase):
    def _point(self, *, phase="uploading", complete_intent=None, cleanup=None):
        metadata_key = multipart_cleanup_metadata_key("vultr")
        return SimpleNamespace(
            storage=SimpleNamespace(type=SimpleNamespace(code="vultr")),
            metadata={
                metadata_key: {
                    "phase": phase,
                    "multipart": {
                        "upload_id": "owned-upload",
                        "creation_proof": {"version": 1},
                        "complete_intent": complete_intent,
                    },
                    "multipart_cleanup": cleanup,
                }
            },
        )

    def test_every_registered_adapter_exposes_matching_client_and_metadata_key(self):
        for code, (module_name, _relation, metadata_key, _uses_storage) in (
            _S3_CLEANUP_BACKENDS.items()
        ):
            with self.subTest(code=code):
                module = import_module(
                    f"apps._tasks.integration.storage.{module_name}"
                )
                exported_metadata_keys = {
                    value
                    for name, value in vars(module).items()
                    if name.endswith("_OBJECT_METADATA_KEY")
                }
                self.assertTrue(callable(module._s3_client))
                self.assertIn(metadata_key, exported_metadata_keys)

    def test_only_unfinished_creation_witness_is_a_cleanup_candidate(self):
        self.assertTrue(
            has_owned_multipart_cleanup_candidate(self._point())
        )
        self.assertFalse(
            has_owned_multipart_cleanup_candidate(
                self._point(
                    phase="multipart_complete_outcome_unknown",
                    complete_intent={"complete": True},
                )
            )
        )
        self.assertFalse(
            has_owned_multipart_cleanup_candidate(
                self._point(cleanup={"phase": "complete"})
            )
        )
        self.assertFalse(
            has_owned_multipart_cleanup_candidate(
                self._point(cleanup={"phase": "abort_rejected"})
            )
        )
