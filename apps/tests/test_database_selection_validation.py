from types import SimpleNamespace

from apps.api.v1.database.serializers import CoreDatabaseWriteSerializer
from apps.console.connection.models import CoreAuthDatabase
from apps.tests.base import BaseTestCase
from apps.tests.test_backup_engine import make_database_node


class DatabaseSelectionValidationTests(BaseTestCase):
    def _request(self):
        return SimpleNamespace(user=self.user)

    def _node(self, *, spans_databases=False, **database_values):
        node = make_database_node(
            self.account,
            self.member,
            db_type=CoreAuthDatabase.DatabaseType.MYSQL,
            version="mysql_8_0",
            database_name=None if spans_databases else "appdb",
            all_tables=database_values.pop("all_tables", False),
            tables=database_values.pop("tables", None),
            all_databases=database_values.pop("all_databases", False),
            databases=database_values.pop("databases", None),
        )
        auth = node.connection.auth_database
        auth.all_databases = spans_databases
        auth.save(update_fields=["all_databases", "modified"])
        return node

    def _create_serializer(self, node, **selection):
        return CoreDatabaseWriteSerializer(
            data={
                "node": {
                    "connection": node.connection_id,
                    "name": "selection-node",
                },
                "name": "selection-node",
                **selection,
            },
            context={"request": self._request()},
        )

    def test_single_database_create_rejects_empty_selection(self):
        serializer = self._create_serializer(
            self._node(),
            all_tables=False,
            tables=[],
            all_databases=False,
            databases=[],
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("all_tables", serializer.errors)

    def test_single_database_accepts_all_tables_or_an_explicit_table(self):
        node = self._node()
        for selection in (
            {"all_tables": True, "tables": None},
            {"all_tables": False, "tables": ["orders"]},
        ):
            with self.subTest(selection=selection):
                serializer = self._create_serializer(node, **selection)
                self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_single_database_rejects_conflicting_or_database_selection(self):
        node = self._node()
        for selection in (
            {"all_tables": True, "tables": ["orders"]},
            {"all_databases": True},
            {"databases": ["appdb"]},
            {"tables": ["orders"], "databases": ["appdb"]},
        ):
            with self.subTest(selection=selection):
                serializer = self._create_serializer(node, **selection)
                self.assertFalse(serializer.is_valid())

    def test_multi_database_create_rejects_empty_selection(self):
        serializer = self._create_serializer(
            self._node(spans_databases=True),
            all_tables=False,
            tables=[],
            all_databases=False,
            databases=[],
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("all_databases", serializer.errors)

    def test_multi_database_accepts_all_or_an_explicit_database(self):
        node = self._node(spans_databases=True)
        for selection in (
            {"all_databases": True, "databases": None},
            {"all_databases": False, "databases": ["analytics"]},
        ):
            with self.subTest(selection=selection):
                serializer = self._create_serializer(node, **selection)
                self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_multi_database_rejects_table_mode(self):
        serializer = self._create_serializer(
            self._node(spans_databases=True),
            all_tables=True,
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("all_tables", serializer.errors)

    def test_partial_update_merges_existing_selection_before_validation(self):
        node = self._node(all_tables=True)
        invalid = CoreDatabaseWriteSerializer(
            node.database,
            data={"all_tables": False},
            partial=True,
            context={"request": self._request()},
        )
        self.assertFalse(invalid.is_valid())
        self.assertIn("all_tables", invalid.errors)

        valid = CoreDatabaseWriteSerializer(
            node.database,
            data={"all_tables": False, "tables": ["orders"]},
            partial=True,
            context={"request": self._request()},
        )
        self.assertTrue(valid.is_valid(), valid.errors)

    def test_selection_lists_reject_non_lists_and_blank_names(self):
        node = self._node()
        for tables in ({"orders": True}, ["orders", ""]):
            with self.subTest(tables=tables):
                serializer = self._create_serializer(
                    node,
                    all_tables=False,
                    tables=tables,
                )
                self.assertFalse(serializer.is_valid())
                self.assertIn("tables", serializer.errors)
