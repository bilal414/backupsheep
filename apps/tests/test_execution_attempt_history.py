"""Bounded, public-safe execution-attempt history contracts."""

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from apps.console.utils.execution_history import (
    begin_public_attempt,
    update_public_attempt,
)


class ExecutionAttemptHistoryTests(SimpleTestCase):
    correlation_id = "8f841859-63e0-4b78-bb0b-d35043ce4418"

    def test_attempt_tracks_stage_code_retry_decision_and_timestamps(self):
        started_at = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
        metadata = begin_public_attempt(
            {},
            attempt_no=1,
            correlation_id=self.correlation_id,
            stage="website_mirroring",
            now=started_at,
        )
        metadata = update_public_attempt(
            metadata,
            attempt_no=1,
            correlation_id=self.correlation_id,
            stage="website_manifest",
            code="WEBSITE_MANIFEST_FAILED",
            retry_decision="scheduled_retry",
            now=started_at + timedelta(minutes=2),
            finished=True,
        )

        self.assertEqual(metadata["public_attempt_history"], [{
            "attempt": 1,
            "started_at": "2026-08-23T12:00:00+00:00",
            "finished_at": "2026-08-23T12:02:00+00:00",
            "stage": "website_manifest",
            "code": "WEBSITE_MANIFEST_FAILED",
            "retry_decision": "scheduled_retry",
            "correlation_id": self.correlation_id,
        }])

    def test_attempt_history_is_bounded_to_twenty_newest_attempts(self):
        metadata = {}
        started_at = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
        for attempt_no in range(1, 26):
            metadata = begin_public_attempt(
                metadata,
                attempt_no=attempt_no,
                correlation_id=self.correlation_id,
                stage="preparing",
                now=started_at + timedelta(minutes=attempt_no),
            )

        history = metadata["public_attempt_history"]
        self.assertEqual(len(history), 20)
        self.assertEqual(history[0]["attempt"], 6)
        self.assertEqual(history[-1]["attempt"], 25)

    def test_duplicate_delivery_updates_same_running_attempt(self):
        started_at = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
        first = begin_public_attempt(
            {},
            attempt_no=2,
            correlation_id=self.correlation_id,
            stage="preparing",
            now=started_at,
        )
        second = begin_public_attempt(
            first,
            attempt_no=2,
            correlation_id=self.correlation_id,
            stage="website_mirroring",
            now=started_at + timedelta(seconds=30),
        )

        self.assertEqual(len(second["public_attempt_history"]), 1)
        self.assertEqual(
            second["public_attempt_history"][0]["started_at"],
            "2026-08-23T12:00:00+00:00",
        )
        self.assertEqual(
            second["public_attempt_history"][0]["stage"],
            "website_mirroring",
        )
