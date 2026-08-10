"""Focused UI contract tests for logical website and database restores."""

from pathlib import Path

from django.template.loader import get_template
from django.test import SimpleTestCase


class LogicalRestoreModalUiTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        template_path = (
            Path(__file__).resolve().parents[1]
            / "console"
            / "_templates"
            / "console"
            / "node"
            / "detail.html"
        )
        source = template_path.read_text(encoding="utf-8")
        cls.modal = source.split("<!-- Restore backup modal -->", 1)[1].split(
            "<!-- Native cloud restore modal -->", 1
        )[0]

    def test_restore_modal_template_compiles(self):
        get_template("console/node/detail.html")

    def test_website_restore_retains_overwrite_and_delete_warning(self):
        notice = self.modal.rsplit("{% if object.type == 3 %}", 1)[1].split(
            "{% endif %}", 1
        )[0]
        website_notice = notice.split("{% else %}", 1)[0]

        self.assertIn("Warning:", website_notice)
        self.assertIn("This overwrites website files on your server.", website_notice)
        self.assertIn(
            "Files not included in this backup are deleted only when you enable the delete option above.",
            website_notice,
        )
        self.assertIn("Delete files on the server that are not present in this backup", self.modal)

    def test_database_restore_explains_safe_fork_without_source_overwrite_claim(self):
        notice = self.modal.rsplit("{% if object.type == 3 %}", 1)[1].split(
            "{% endif %}", 1
        )[0]
        database_notice = notice.split("{% else %}", 1)[1]

        self.assertIn("Safe fork:", database_notice)
        self.assertIn("This creates a new database from the backup.", database_notice)
        self.assertIn(
            "Your source database and its existing data remain unchanged.",
            database_notice,
        )
        self.assertNotIn("overwrites", database_notice.lower())
        self.assertNotIn("deleted", database_notice.lower())
