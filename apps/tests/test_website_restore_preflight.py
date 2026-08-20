"""Deterministic SFTP website-restore target permission preflight tests."""

import os
import subprocess
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from apps._tasks.exceptions import NodeBackupFailedError
from apps._tasks.integration import restore_website as RW
from apps._tasks.integration.restore_common import RestoreError
from apps._tasks.integration.restore_lease import RestoreLeaseLost
from apps.console.connection.models import CoreAuthWebsite


class _Account:
    def __init__(self):
        self.logs = []

    def create_log(self, data):
        self.logs.append(data)


class WebsiteRestorePreflightTests(SimpleTestCase):
    def setUp(self):
        self.account = _Account()
        self.node = SimpleNamespace(
            id=41,
            name="preflight-node",
            connection=SimpleNamespace(
                id=51,
                name="preflight-connection",
                account=self.account,
            ),
        )
        self.backup = SimpleNamespace(
            uuid="backup-preflight-20260810",
            uuid_str="backup-preflight-20260810",
            attempt_no=1,
            type="on_demand",
        )
        self.restore = SimpleNamespace(
            correlation_id="restore-preflight-correlation",
            execution_metadata={"source_manifest": {"public_html": {}}},
            progress_total=1,
            progress_completed=0,
        )
        self.auth = SimpleNamespace(
            protocol=CoreAuthWebsite.Protocol.SFTP,
            port=22,
            host="sftp.example.invalid",
            verify_ssl=True,
            get_protocol_display=lambda: "SFTP",
        )
        self.website = SimpleNamespace(parallel=2)
        self.username = "restore-user"
        self.password = "restore-password-secret"
        self.ssh_key_path = "/tmp/restore-key"

    def _preflight(self, sources):
        return RW._preflight_restore_target(
            self.node,
            self.backup,
            self.restore,
            self.auth,
            self.website,
            sources,
            "sftp://sftp.example.invalid",
            self.username,
            self.password,
            self.ssh_key_path,
        )

    def _name_preflight(self, sources):
        return RW._preflight_restore_name_fidelity(
            self.node,
            self.backup,
            self.restore,
            self.auth,
            self.website,
            sources,
            "sftp://sftp.example.invalid",
            self.username,
            self.password,
            self.ssh_key_path,
        )

    def _record(self, path="public_html"):
        return {
            "path": path,
            "type": "directory",
            "fingerprint": "f" * 64,
            "source_digest": "d" * 64,
            "local_path": "/tmp/restore-source",
            "files": [],
        }

    def _cleanup_state(self, *, status="cleanup_pending", previous="pending", staging="pending"):
        return {
            "path": "public_html",
            "target_path": "public_html",
            "type": "directory",
            "source_digest": "d" * 64,
            "status": status,
            "files": {},
            "cleanup": {
                "previous_target": previous,
                "staging": staging,
            },
        }

    def _cleanup(self, record, state, run_lftp, checkpoints=None, stage=None):
        expected = stage or RW._expected_restore_stage(self.restore, record)
        checkpoint = None
        if checkpoints is not None:
            def checkpoint(restore, **kwargs):
                checkpoints.append(
                    {
                        "phase": kwargs["phase"],
                        "state": kwargs["records"][0]["state"],
                    }
                )

        with mock.patch.object(RW, "_run_lftp", side_effect=run_lftp), mock.patch.object(
            RW, "_checkpoint", side_effect=checkpoint
        ):
            return RW._restore_published_source_cleanup(
                self.node,
                self.backup,
                self.restore,
                self.auth,
                record,
                self.website,
                "sftp://sftp.example.invalid",
                self.username,
                self.password,
                self.ssh_key_path,
                expected,
                state,
            )

    @staticmethod
    def _local_probe():
        descriptor, path = tempfile.mkstemp(prefix="backupsheep-preflight-")
        with os.fdopen(descriptor, "wb") as probe:
            probe.write(b"probe")
        return path

    def _track_probe(self):
        path = self._local_probe()
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_writable_parent_probes_each_non_root_source_and_not_final_targets(self):
        local_probe = self._track_probe()
        probe_scripts = []

        def run_probe(*args, **kwargs):
            probe_scripts.append(args[4])
            return SimpleNamespace(
                returncode=0,
                stdout="\n".join(RW.RESTORE_NAME_FIDELITY_PROBES),
            )

        with mock.patch.object(
            RW, "_write_restore_probe_file", return_value=local_probe
        ), mock.patch.object(
            RW, "_run_restore_target_probe", side_effect=run_probe
        ), mock.patch.object(
            RW, "_cleanup_restore_target_probe", return_value=True
        ) as cleanup:
            self._preflight(
                [
                    {"path": ".", "type": "directory"},
                    {"path": "public_html", "type": "directory"},
                    {"path": "nested/index.html", "type": "file"},
                ]
            )

        self.assertEqual(len(probe_scripts), 2)
        # Each non-root source is cleaned once before probing (for a crashed
        # predecessor) and once in the finally path.
        self.assertEqual(cleanup.call_count, 4)
        directory_script, file_script = probe_scripts
        self.assertIn("mkdir", directory_script)
        self.assertIn("mv", directory_script)
        for name in RW.RESTORE_NAME_FIDELITY_PROBES:
            self.assertNotIn(name, directory_script)
            self.assertNotIn(name, file_script)
        self.assertNotIn('"public_html"', directory_script)
        self.assertIn("put -P", file_script)
        self.assertIn('"nested/', file_script)
        self.assertNotIn('"nested/index.html"', file_script)
        self.assertFalse(os.path.exists(local_probe))

    def test_name_fidelity_probe_rejects_case_or_unicode_normalization_collision(self):
        for missing_name in (
            "Case-sensitive-name.bin",
            "cafe\u0301-normalization-name.bin",
        ):
            with self.subTest(missing_name=missing_name):
                local_probe = self._track_probe()
                observed = [
                    name
                    for name in RW.RESTORE_NAME_FIDELITY_PROBES
                    if name != missing_name
                ]
                result = SimpleNamespace(
                    returncode=0,
                    stdout="\n".join(observed),
                )
                with mock.patch.object(
                    RW, "_write_restore_probe_file", return_value=local_probe
                ), mock.patch.object(
                    RW, "_run_restore_target_probe", return_value=result
                ), mock.patch.object(
                    RW, "_cleanup_restore_target_probe", return_value=True
                ) as cleanup, mock.patch.object(
                    RW, "_capture_safe"
                ) as capture, mock.patch.object(RW, "_write_log"):
                    with self.assertRaises(RestoreError) as raised:
                        self._name_preflight(
                            [{"path": "public_html", "type": "directory"}]
                        )

                self.assertEqual(
                    raised.exception.code, "RESTORE_TARGET_NAME_COLLISION"
                )
                self.assertFalse(raised.exception.retryable)
                self.assertNotIn(self.password, str(raised.exception))
                self.assertEqual(cleanup.call_count, 2)
                capture.assert_called_with("WEBSITE_TARGET_NAME_COLLISION")
                self.assertFalse(os.path.exists(local_probe))

    def test_name_fidelity_listing_accepts_exact_basenames_with_remote_prefix(self):
        probe = RW._remote_probe_paths(
            self.restore,
            self.backup,
            {"path": "public_html", "type": "directory"},
        )
        output = "\n".join(
            f"{probe['root']}/{name}"
            for name in RW.RESTORE_NAME_FIDELITY_PROBES
        )

        self.assertTrue(RW._probe_preserves_distinct_names(output, probe))
        self.assertFalse(
            RW._probe_preserves_distinct_names(
                output.replace("Case-sensitive-name.bin\n", ""), probe
            )
        )

    def test_root_all_paths_gets_owned_probe_while_non_sftp_keeps_legacy_semantics(self):
        local_probe = self._track_probe()
        result = SimpleNamespace(
            returncode=0,
            stdout="\n".join(RW.RESTORE_NAME_FIDELITY_PROBES),
        )
        with mock.patch.object(
            RW, "_write_restore_probe_file", return_value=local_probe
        ) as write_probe, mock.patch.object(
            RW, "_run_restore_target_probe", return_value=result
        ) as run_probe, mock.patch.object(
            RW, "_cleanup_restore_target_probe", return_value=True
        ) as cleanup:
            self._preflight([{"path": ".", "type": "directory"}])
            write_probe.assert_not_called()
            run_probe.assert_not_called()
            cleanup.assert_not_called()

            self._name_preflight([{"path": ".", "type": "directory"}])
            self.assertEqual(run_probe.call_count, 1)
            root_script = run_probe.call_args.args[4]
            self.assertIn(".backupsheep_restore_probe_", root_script)
            for name in RW.RESTORE_NAME_FIDELITY_PROBES:
                self.assertIn(name, root_script)
            self.assertEqual(cleanup.call_count, 2)
            self.auth.protocol = CoreAuthWebsite.Protocol.FTP
            self._preflight([{"path": "public_html", "type": "directory"}])
            self._name_preflight(
                [{"path": "public_html", "type": "directory"}]
            )

        write_probe.assert_called_once()
        self.assertEqual(run_probe.call_count, 1)
        self.assertFalse(os.path.exists(local_probe))

    def test_permission_denied_is_actionable_terminal_target_rejection(self):
        secret = "Bearer restore-secret-value"
        result = SimpleNamespace(
            returncode=1,
            stdout=f"mkdir: Access failed: Permission denied\n{secret}",
        )
        with mock.patch.object(
            RW.subprocess, "run", return_value=result
        ), mock.patch.object(
            RW, "_capture_safe"
        ), mock.patch.object(
            RW, "_write_log"
        ) as write_log:
            with self.assertRaises(NodeBackupFailedError) as raised:
                RW._run_restore_target_probe(
                    self.node,
                    self.backup,
                    self.restore,
                    self.auth,
                    "probe-script",
                    self.username,
                    self.password,
                    ".",
                )

        failure = raised.exception
        self.assertEqual(failure.error_code, "RESTORE_TARGET_REJECTED")
        self.assertFalse(failure.retryable)
        self.assertIn("remote parent", failure.diagnostic_message)
        self.assertIn("Grant that user", failure.diagnostic_message)
        self.assertNotIn(secret, str(failure))
        self.assertNotIn(self.password, str(failure))
        self.assertTrue(write_log.called)
        self.assertNotIn(secret, repr(write_log.call_args))

    def test_cleanup_runs_after_probe_failure_and_ignores_fence_for_exact_probe(self):
        local_probe = self._track_probe()
        result = SimpleNamespace(
            returncode=1,
            stdout="mkdir: Access failed: Permission denied",
        )
        cleanup_calls = []

        def cleanup_lftp(*args, **kwargs):
            cleanup_calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout="")

        with mock.patch.object(
            RW, "_write_restore_probe_file", return_value=local_probe
        ), mock.patch.object(
            RW.subprocess, "run", return_value=result
        ), mock.patch.object(
            RW, "_run_lftp", side_effect=cleanup_lftp
        ), mock.patch.object(
            RW, "_capture_safe"
        ), mock.patch.object(
            RW, "_write_log"
        ):
            with self.assertRaises(NodeBackupFailedError):
                self._preflight([{"path": "public_html", "type": "file"}])

        self.assertEqual(len(cleanup_calls), 2)
        cleanup_args, cleanup_kwargs = cleanup_calls[-1]
        self.assertFalse(cleanup_kwargs["enforce_fence"])
        cleanup_script = cleanup_args[4]
        self.assertIn("rm -r", cleanup_script)
        self.assertNotIn('"public_html"', cleanup_script)
        self.assertFalse(os.path.exists(local_probe))

    def test_absent_exact_probe_cleanup_is_idempotent_success(self):
        probe = RW._remote_probe_paths(
            self.restore,
            self.backup,
            {"path": "public_html", "type": "directory"},
        )
        result = SimpleNamespace(
            returncode=1,
            stdout=(
                f"rm: Access failed: No such file ({probe['renamed']})\n"
                f"rm: Access failed: No such file ({probe['root']})\n"
            ),
        )

        with mock.patch.object(RW, "_run_lftp", return_value=result) as run_lftp:
            cleaned = RW._cleanup_restore_target_probe(
                self.node,
                self.backup,
                self.restore,
                self.auth,
                self.username,
                self.password,
                self.ssh_key_path,
                "sftp://sftp.example.invalid",
                self.website.parallel,
                probe,
            )

        self.assertTrue(cleaned)
        self.assertFalse(run_lftp.call_args.kwargs["enforce_fence"])
        self.assertFalse(run_lftp.call_args.kwargs["check_result"])

    def test_probe_cleanup_transport_failure_is_not_success(self):
        probe = RW._remote_probe_paths(
            self.restore,
            self.backup,
            {"path": "public_html", "type": "directory"},
        )
        result = SimpleNamespace(returncode=1, stdout="Connection reset by peer")

        with mock.patch.object(RW, "_run_lftp", return_value=result):
            cleaned = RW._cleanup_restore_target_probe(
                self.node,
                self.backup,
                self.restore,
                self.auth,
                self.username,
                self.password,
                self.ssh_key_path,
                "sftp://sftp.example.invalid",
                self.website.parallel,
                probe,
            )

        self.assertFalse(cleaned)

    def test_fence_loss_stops_probe_and_still_attempts_exact_probe_cleanup(self):
        local_probe = self._track_probe()
        cleanup_calls = []

        def cleanup_lftp(*args, **kwargs):
            cleanup_calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout="")

        with mock.patch.object(
            RW, "_write_restore_probe_file", return_value=local_probe
        ), mock.patch.object(
            RW, "_ensure_restore_fence", side_effect=RestoreLeaseLost("fence-canary")
        ), mock.patch.object(
            RW, "_run_lftp", side_effect=cleanup_lftp
        ) as run_lftp, mock.patch.object(RW, "_capture_safe"):
            with self.assertRaises(RestoreLeaseLost):
                self._preflight([{"path": "public_html", "type": "directory"}])

        self.assertEqual(run_lftp.call_count, 1)
        self.assertFalse(cleanup_calls[0][1]["enforce_fence"])
        self.assertFalse(os.path.exists(local_probe))

    def test_transport_uncertainty_is_retryable_and_does_not_claim_publication(self):
        result = SimpleNamespace(returncode=1, stdout="Connection reset by peer")
        with mock.patch.object(
            RW.subprocess, "run", return_value=result
        ), mock.patch.object(
            RW, "_capture_safe"
        ), mock.patch.object(
            RW, "_write_log"
        ):
            with self.assertRaises(RestoreError) as raised:
                RW._run_restore_target_probe(
                    self.node,
                    self.backup,
                    self.restore,
                    self.auth,
                    "probe-script",
                    self.username,
                    self.password,
                    ".",
                )

        self.assertEqual(raised.exception.code, "PROVIDER_TRANSIENT_FAILURE")
        self.assertTrue(raised.exception.retryable)
        self.assertNotIn("Connection reset", str(raised.exception))
        self.assertNotIn(self.password, str(raised.exception))

    def test_probe_timeout_is_retryable_without_exposing_process_details(self):
        with mock.patch.object(
            RW.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(["lftp"], 12),
        ), mock.patch.object(RW, "_capture_safe"), mock.patch.object(
            RW, "_write_log"
        ):
            with self.assertRaises(RestoreError) as raised:
                RW._run_restore_target_probe(
                    self.node,
                    self.backup,
                    self.restore,
                    self.auth,
                    "probe-script",
                    self.username,
                    self.password,
                    ".",
                )

        self.assertEqual(raised.exception.code, "PROVIDER_TIMEOUT")
        self.assertTrue(raised.exception.retryable)
        self.assertNotIn("lftp", str(raised.exception))
        self.assertNotIn(self.password, str(raised.exception))

    def test_success_proves_target_and_marker_then_removes_only_exact_old_path(self):
        record = self._record()
        state = self._cleanup_state()
        stage = RW._expected_restore_stage(self.restore, record)
        scripts = []
        checkpoints = []

        def run_lftp(*args, **kwargs):
            scripts.append(args[4])
            return SimpleNamespace(returncode=0, stdout="")

        self._cleanup(record, state, run_lftp, checkpoints)

        self.assertEqual(len(scripts), 3)
        self.assertIn(stage["target_path"], scripts[0])
        self.assertIn(stage["marker"], scripts[0])
        self.assertIn(f'rm -r "{stage["old"]}"', scripts[1])
        self.assertNotIn(f'rm -r "{stage["target_path"]}"', scripts[1])
        self.assertNotIn(stage["marker"], scripts[1])
        self.assertIn(f'rm -r "{stage["stage_root"]}"', scripts[2])
        self.assertEqual(checkpoints[-1]["phase"], "website_complete")
        self.assertEqual(checkpoints[-1]["state"]["status"], "complete")
        self.assertEqual(
            checkpoints[-1]["state"]["cleanup"],
            {"previous_target": "complete", "staging": "complete"},
        )

    def test_target_absent_retains_old_path_and_never_starts_cleanup(self):
        record = self._record()
        state = self._cleanup_state()
        scripts = []
        checkpoints = []

        def run_lftp(*args, **kwargs):
            scripts.append(args[4])
            return SimpleNamespace(
                returncode=1,
                stdout="cls: No such file or directory",
            )

        with self.assertRaises(RestoreError) as raised:
            self._cleanup(record, state, run_lftp, checkpoints)

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(len(scripts), 1)
        self.assertNotIn("rm -r", scripts[0])
        self.assertEqual(checkpoints[0]["phase"], "website_cleanup_pending")
        self.assertEqual(checkpoints[0]["state"]["status"], "cleanup_pending")

    def test_lost_old_cleanup_response_is_adopted_idempotently_on_redelivery(self):
        record = self._record()
        state = self._cleanup_state()
        checkpoints = []
        lost = NodeBackupFailedError(None, message="lost cleanup response")

        with self.assertRaises(RestoreError) as raised:
            self._cleanup(
                record,
                state,
                mock.Mock(side_effect=[SimpleNamespace(returncode=0, stdout=""), lost]),
                checkpoints,
            )
        self.assertEqual(raised.exception.code, "PROVIDER_TRANSIENT_FAILURE")
        self.assertTrue(raised.exception.retryable)
        self.assertEqual(checkpoints[-1]["state"]["cleanup"]["previous_target"], "pending")

        scripts = []

        def retry_lftp(*args, **kwargs):
            scripts.append(args[4])
            if len(scripts) == 1:
                return SimpleNamespace(returncode=0, stdout="")
            if len(scripts) == 2:
                return SimpleNamespace(
                    returncode=1,
                    stdout="rm: No such file or directory",
                )
            return SimpleNamespace(returncode=0, stdout="")

        self._cleanup(record, state, retry_lftp)
        self.assertEqual(len(scripts), 3)
        self.assertIn("rm -r", scripts[1])
        self.assertIn("rm -r", scripts[2])

    def test_worker_crash_after_publish_has_cleanup_pending_checkpoint(self):
        record = self._record()
        stage = RW._expected_restore_stage(self.restore, record)
        self.restore.execution_metadata["source_states"] = {
            record["fingerprint"]: {
                **RW._state_for(record, "staged", files_status="staged", stage=stage),
            }
        }
        checkpoints = []

        def checkpoint(restore, **kwargs):
            checkpoints.append(
                {
                    "phase": kwargs["phase"],
                    "state": kwargs["records"][0]["state"],
                }
            )

        with mock.patch.object(RW, "_checkpoint", side_effect=checkpoint), mock.patch.object(
            RW, "_run_lftp", return_value=SimpleNamespace(returncode=0, stdout="")
        ), mock.patch.object(
            RW,
            "_restore_published_source_cleanup",
            side_effect=RuntimeError("worker crashed after publish"),
        ) as cleanup:
            with self.assertRaisesRegex(RuntimeError, "worker crashed after publish"):
                RW._staged_restore_source(
                    self.node,
                    self.backup,
                    self.restore,
                    self.auth,
                    record,
                    self.website,
                    "sftp://sftp.example.invalid",
                    self.username,
                    self.password,
                    self.ssh_key_path,
                )

        cleanup.assert_called_once()
        self.assertEqual(checkpoints[-1]["phase"], "website_cleanup_pending")
        self.assertEqual(checkpoints[-1]["state"]["status"], "cleanup_pending")
        self.assertEqual(
            checkpoints[-1]["state"]["cleanup"],
            {"previous_target": "pending", "staging": "pending"},
        )

    def test_complete_source_with_pending_cleanup_resumes_without_republish(self):
        record = self._record()
        stage = RW._expected_restore_stage(self.restore, record)
        self.restore.execution_metadata["source_states"] = {
            record["fingerprint"]: {
                **RW._state_for(record, "complete", files_status="complete", stage=stage),
                "cleanup": {
                    "previous_target": "pending",
                    "staging": "pending",
                },
            }
        }
        scripts = []
        checkpoints = []

        def run_lftp(*args, **kwargs):
            scripts.append(args[4])
            if len(scripts) == 2:
                return SimpleNamespace(returncode=1, stdout="rm: not found")
            return SimpleNamespace(returncode=0, stdout="")

        def checkpoint(restore, **kwargs):
            checkpoints.append(kwargs["records"][0]["state"])

        with mock.patch.object(RW, "_run_lftp", side_effect=run_lftp), mock.patch.object(
            RW, "_checkpoint", side_effect=checkpoint
        ):
            RW._staged_restore_source(
                self.node,
                self.backup,
                self.restore,
                self.auth,
                record,
                self.website,
                "sftp://sftp.example.invalid",
                self.username,
                self.password,
                self.ssh_key_path,
            )

        self.assertEqual(len(scripts), 3)
        self.assertNotIn("mv", "\n".join(scripts))
        self.assertEqual(checkpoints[-1]["status"], "complete")
        self.assertEqual(
            checkpoints[-1]["cleanup"],
            {"previous_target": "complete", "staging": "complete"},
        )

    def test_staging_cleanup_transient_is_persisted_and_retried(self):
        record = self._record()
        state = self._cleanup_state()
        checkpoints = []
        scripts = []

        def first_attempt(*args, **kwargs):
            scripts.append(args[4])
            if len(scripts) < 3:
                return SimpleNamespace(returncode=0, stdout="")
            return SimpleNamespace(returncode=1, stdout="Connection reset by peer")

        with self.assertRaises(RestoreError) as raised:
            self._cleanup(record, state, first_attempt, checkpoints)
        self.assertEqual(raised.exception.code, "PROVIDER_TRANSIENT_FAILURE")
        retry_state = checkpoints[-1]["state"]
        self.assertEqual(retry_state["status"], "cleanup_pending")
        self.assertEqual(
            retry_state["cleanup"],
            {"previous_target": "complete", "staging": "pending"},
        )

        retry_scripts = []

        def retry_stage(*args, **kwargs):
            retry_scripts.append(args[4])
            return SimpleNamespace(returncode=0, stdout="")

        self._cleanup(record, retry_state, retry_stage)
        self.assertEqual(len(retry_scripts), 1)
        self.assertIn(f'rm -r "{RW._expected_restore_stage(self.restore, record)["stage_root"]}"', retry_scripts[0])

    def test_cleanup_rejects_non_deterministic_old_path_before_remote_call(self):
        record = self._record()
        state = self._cleanup_state()
        stage = RW._expected_restore_stage(self.restore, record)
        stage["old"] = "/var/www/another-restore-previous"
        with mock.patch.object(RW, "_run_lftp") as run_lftp:
            with self.assertRaises(RestoreError) as raised:
                self._cleanup(record, state, mock.Mock(), stage=stage)

        self.assertEqual(raised.exception.code, "PROVIDER_OWNERSHIP_MISMATCH")
        self.assertFalse(raised.exception.retryable)
        run_lftp.assert_not_called()

    def test_stale_fence_stops_cleanup_before_old_path_delete(self):
        record = self._record()
        state = self._cleanup_state()
        run_lftp = mock.Mock(side_effect=RestoreLeaseLost("stale worker"))
        with mock.patch.object(RW, "_checkpoint"):
            with self.assertRaises(RestoreLeaseLost):
                self._cleanup(record, state, run_lftp)

        run_lftp.assert_called_once()
        self.assertNotIn("rm -r", run_lftp.call_args.args[4])
