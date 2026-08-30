import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"
CONTRACT = ROOT / "deploy" / "postgres" / "source-identity-contract.sh"
MIGRATOR = ROOT / "deploy" / "postgres" / "migrate-runtime.sh"
INSTALLATION_ID = "a" * 64
OTHER_INSTALLATION_ID = "b" * 64
SOURCE_IMAGE_ID = "sha256:" + ("c" * 64)
TARGET_IMAGE_ID = "sha256:" + ("d" * 64)
STORAGE_GENERATION = "18-alpine-icu-v1"
SINGLE_ROLE_INTENT = "migrated-debian-single-role-v1"
GENERATION2_INTENT = "migrated-debian-generation2-v1"
STRICT_INTENT = "migrated-debian-v1"
BOOTSTRAP_ROLE = "backupsheep"
GENERATION2_ROLES = (
    "backupsheep_bootstrap",
    "backupsheep_migrator",
    "backupsheep_runtime",
)
GENERATION2_RECORDS = "\n".join(
    (
        f"{GENERATION2_ROLES[0]}|true|true|true|true|true|true|true|-1|true|true|true|"
        f"backupsheep:database-identity-v2:{INSTALLATION_ID}:bootstrap",
        f"{GENERATION2_ROLES[1]}|false|true|false|false|true|false|false|-1|true|false|true|"
        f"backupsheep:database-identity-v2:{INSTALLATION_ID}:migrator",
        f"{GENERATION2_ROLES[2]}|false|true|false|false|true|false|false|-1|true|false|true|"
        f"backupsheep:database-identity-v2:{INSTALLATION_ID}:runtime",
    )
)
GENERATION2_SETTINGS = "\n".join(
    f"{role}|<all-databases>|search_path=public, pg_catalog"
    for role in GENERATION2_ROLES[1:]
)
GENERATION2_DEFAULT_ACL = "\n".join(
    sorted(
        (
            f"{GENERATION2_ROLES[1]}|public|S|{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|SELECT|false",
            f"{GENERATION2_ROLES[1]}|public|S|{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|USAGE|false",
            f"{GENERATION2_ROLES[1]}|public|f|{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|EXECUTE|false",
            f"{GENERATION2_ROLES[1]}|public|r|{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|DELETE|false",
            f"{GENERATION2_ROLES[1]}|public|r|{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|INSERT|false",
            f"{GENERATION2_ROLES[1]}|public|r|{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|SELECT|false",
            f"{GENERATION2_ROLES[1]}|public|r|{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|UPDATE|false",
        )
    )
)
GENERATION2_DEFAULT_ACL_RECORDS = "\n".join(
    sorted(
        f"{GENERATION2_ROLES[1]}|public|{object_type}"
        for object_type in ("S", "f", "r")
    )
)
GENERATION3_ROLE_KINDS = (
    "bootstrap",
    "migrator",
    "app",
    "preflight",
    "beat",
    "cloud",
    "database",
    "files",
    "storage",
    "logs",
)
GENERATION3_ROLES = tuple(f"backupsheep_{kind}" for kind in GENERATION3_ROLE_KINDS)
GENERATION3_ROSTER = ",".join(GENERATION3_ROLES)


def generation3_records(*, retired=False):
    records = []
    for kind, role in zip(GENERATION3_ROLE_KINDS, GENERATION3_ROLES):
        if kind == "bootstrap":
            fields = "true|true|true|true|true|true|true|-1|true|true|true"
        else:
            limit = 8 if kind in {"migrator", "preflight", "beat"} else 128
            fields = f"false|true|false|false|true|false|false|{limit}|true|false|true"
        records.append(
            f"{role}|{fields}|backupsheep:database-identity-v3:{INSTALLATION_ID}:{kind}"
        )
    if retired:
        records.append(
            "backupsheep_runtime|false|true|false|false|false|false|false|-1|true|true|false|"
            f"backupsheep:database-identity-v3:{INSTALLATION_ID}:retired-v2-runtime"
        )
    return "\n".join(sorted(records))


GENERATION3_SETTINGS = "\n".join(
    sorted(
        f"{role}|<all-databases>|{setting}"
        for role in GENERATION3_ROLES[1:]
        for setting in (
            "idle_in_transaction_session_timeout=5min",
            "lock_timeout=30s",
            "search_path=public, pg_catalog",
            "statement_timeout=1h",
        )
    )
)
GENERATION3_DATABASE_ACL = "\n".join(
    sorted(f"{role}|{GENERATION3_ROLES[1]}|CONNECT|false" for role in GENERATION3_ROLES[2:])
)
GENERATION3_SCHEMA_ACL = "\n".join(
    sorted(f"{role}|{GENERATION3_ROLES[1]}|USAGE|false" for role in GENERATION3_ROLES[2:])
)
GENERATION3_DEFAULT_ACL_RECORDS = "\n".join(
    sorted(
        f"{GENERATION3_ROLES[1]}|<global>|{object_type}"
        for object_type in ("T", "f")
    )
)
GENERATION3_DEFAULT_ACL = "\n".join(
    sorted(
        (
            f"{GENERATION3_ROLES[1]}|<global>|T|{GENERATION3_ROLES[1]}|{GENERATION3_ROLES[1]}|USAGE|false",
            f"{GENERATION3_ROLES[1]}|<global>|f|{GENERATION3_ROLES[1]}|{GENERATION3_ROLES[1]}|EXECUTE|false",
        )
    )
)


def target_placeholder_records():
    records = []
    for kind, role in zip(GENERATION3_ROLE_KINDS, GENERATION3_ROLES):
        if kind == "bootstrap":
            fields = "true|true|true|true|true|true|true|-1|true|true|true"
        else:
            fields = "false|true|false|false|true|false|false|-1|true|true|true"
        records.append(
            f"{role}|{fields}|backupsheep:database-identity-v3:{INSTALLATION_ID}:{kind}"
        )
    return "\n".join(sorted(records))


class PostgresSourceIdentityContractTests(TestCase):
    def run_contract(self, body, **environment):
        env = os.environ.copy()
        env.update(environment)
        return subprocess.run(
            ["/bin/sh", "-c", f'. "$1"\n{body}', "contract-test", str(CONTRACT)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_identity_mode_separates_generations_and_sealed_reconciliation(self):
        accepted = {
            (GENERATION2_INTENT, "3-pending-upgrade"): "generation2-three-role-v1",
            (GENERATION2_INTENT, "3"): "generation2-reconcile-v1",
            (STRICT_INTENT, "3"): "strict-ten-role-v1",
        }
        for (intent, generation), expected in accepted.items():
            with self.subTest(intent=intent, generation=generation):
                result = self.run_contract(
                    'backupsheep_postgres_source_identity_mode "$INTENT" "$GENERATION"',
                    INTENT=intent,
                    GENERATION=generation,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

        for intent, generation in (
            (SINGLE_ROLE_INTENT, ""),
            (SINGLE_ROLE_INTENT, "2"),
            (SINGLE_ROLE_INTENT, "3-pending-upgrade"),
            (SINGLE_ROLE_INTENT, "3"),
            (SINGLE_ROLE_INTENT, "3-pending-fresh"),
            (GENERATION2_INTENT, "2"),
            (STRICT_INTENT, ""),
            (STRICT_INTENT, "2"),
            (STRICT_INTENT, "3-pending-upgrade"),
            ("new-empty-v1", "3-pending-upgrade"),
        ):
            with self.subTest(refused_intent=intent, refused_generation=generation):
                result = self.run_contract(
                    'backupsheep_postgres_source_identity_mode "$INTENT" "$GENERATION"',
                    INTENT=intent,
                    GENERATION=generation,
                )
                self.assertNotEqual(result.returncode, 0)

    def run_generation2(self, **overrides):
        values = {
            "INSTALLATION": INSTALLATION_ID,
            "BOOTSTRAP": GENERATION2_ROLES[0],
            "ROLES": "\n".join(GENERATION2_ROLES),
            "RECORDS": GENERATION2_RECORDS,
            "MEMBERSHIPS": "0",
            "SETTINGS": GENERATION2_SETTINGS,
            "DATABASE_ACL": f"{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|CONNECT|false",
            "SCHEMA_ACL": f"{GENERATION2_ROLES[2]}|{GENERATION2_ROLES[1]}|USAGE|false",
            "DEFAULT_ACL": GENERATION2_DEFAULT_ACL,
            "DEFAULT_RECORDS": GENERATION2_DEFAULT_ACL_RECORDS,
            "DATABASE_OWNER": GENERATION2_ROLES[1],
            "SCHEMA_OWNER": GENERATION2_ROLES[1],
            "PUBLIC_OWNERS": GENERATION2_ROLES[1],
        }
        values.update(overrides)
        return self.run_contract(
            "backupsheep_validate_generation2_source "
            '"$INSTALLATION" "$BOOTSTRAP" "$ROLES" "$RECORDS" '
            '"$MEMBERSHIPS" "$SETTINGS" "$DATABASE_ACL" "$SCHEMA_ACL" '
            '"$DEFAULT_ACL" "$DEFAULT_RECORDS" "$DATABASE_OWNER" '
            '"$SCHEMA_OWNER" "$PUBLIC_OWNERS"',
            **values,
        )

    def run_generation3(self, *, retired=False, **overrides):
        records = generation3_records(retired=retired)
        roles = "\n".join(sorted(GENERATION3_ROLES + (("backupsheep_runtime",) if retired else ())))
        values = {
            "INSTALLATION": INSTALLATION_ID,
            "BOOTSTRAP": GENERATION3_ROLES[0],
            "ROSTER": GENERATION3_ROSTER,
            "ROLES": roles,
            "RECORDS": records,
            "MEMBERSHIPS": "0",
            "SETTINGS": GENERATION3_SETTINGS,
            "DATABASE_ACL": GENERATION3_DATABASE_ACL,
            "SCHEMA_ACL": GENERATION3_SCHEMA_ACL,
            "DEFAULT_ACL": GENERATION3_DEFAULT_ACL,
            "DEFAULT_RECORDS": GENERATION3_DEFAULT_ACL_RECORDS,
            "DATABASE_OWNER": GENERATION3_ROLES[1],
            "SCHEMA_OWNER": GENERATION3_ROLES[1],
            "PUBLIC_OWNERS": GENERATION3_ROLES[1],
        }
        values.update(overrides)
        return self.run_contract(
            "backupsheep_validate_generation3_source "
            '"$INSTALLATION" "$BOOTSTRAP" "$ROSTER" "$ROLES" "$RECORDS" '
            '"$MEMBERSHIPS" "$SETTINGS" "$DATABASE_ACL" "$SCHEMA_ACL" '
            '"$DEFAULT_ACL" "$DEFAULT_RECORDS" "$DATABASE_OWNER" '
            '"$SCHEMA_OWNER" "$PUBLIC_OWNERS"',
            **values,
        )

    def test_exact_generation2_topology_is_accepted_and_drift_is_refused(self):
        self.assertEqual(self.run_generation2().returncode, 0)
        mutations = (
            {"INSTALLATION": OTHER_INSTALLATION_ID},
            {"ROLES": "\n".join(GENERATION2_ROLES) + "\nevil"},
            {"RECORDS": GENERATION2_RECORDS.replace("|-1|true|false|true|", "|4|true|false|true|", 1)},
            {"MEMBERSHIPS": "1"},
            {"SETTINGS": GENERATION2_SETTINGS + "\nevil|<all-databases>|search_path=public"},
            {"DATABASE_ACL": f"{GENERATION2_ROLES[2]}|evil|CONNECT|false"},
            {"SCHEMA_ACL": f"{GENERATION2_ROLES[2]}|evil|USAGE|false"},
            {"DEFAULT_ACL": GENERATION2_DEFAULT_ACL + "\nPUBLIC|public|r|PUBLIC|evil|SELECT|false"},
            {"DEFAULT_ACL": "\n".join(GENERATION2_DEFAULT_ACL.splitlines()[1:])},
            {"DEFAULT_ACL": GENERATION2_DEFAULT_ACL.replace(
                f"|{GENERATION2_ROLES[1]}|SELECT|false",
                "|evil|SELECT|false",
                1,
            )},
            {"DEFAULT_RECORDS": "\n".join(GENERATION2_DEFAULT_ACL_RECORDS.splitlines()[:-1])},
            {"DEFAULT_RECORDS": GENERATION2_DEFAULT_ACL_RECORDS + f"\n{GENERATION2_ROLES[1]}|public|T"},
            {"DATABASE_OWNER": GENERATION2_ROLES[0]},
            {"SCHEMA_OWNER": GENERATION2_ROLES[0]},
            {"PUBLIC_OWNERS": f"{GENERATION2_ROLES[0]}\n{GENERATION2_ROLES[1]}"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(self.run_generation2(**mutation).returncode, 0)

    def test_exact_generation3_ten_and_retired_role_topologies_are_accepted(self):
        self.assertEqual(self.run_generation3().returncode, 0)
        self.assertEqual(self.run_generation3(retired=True).returncode, 0)
        self.assertEqual(
            self.run_generation3(DEFAULT_ACL="", DEFAULT_RECORDS="").returncode,
            0,
        )
        self.assertEqual(
            self.run_generation3(
                retired=True, DEFAULT_ACL="", DEFAULT_RECORDS=""
            ).returncode,
            0,
        )

    def test_generation3_topology_drift_is_refused(self):
        retired = generation3_records(retired=True)
        mutations = (
            {"INSTALLATION": OTHER_INSTALLATION_ID},
            {"RECORDS": generation3_records().replace("|128|true|false|true|", "|129|true|false|true|", 1)},
            {"MEMBERSHIPS": "1"},
            {"SETTINGS": GENERATION3_SETTINGS.replace("statement_timeout=1h", "statement_timeout=0", 1)},
            {"DATABASE_ACL": GENERATION3_DATABASE_ACL + f"\nPUBLIC|{GENERATION3_ROLES[1]}|CONNECT|false"},
            {"SCHEMA_ACL": GENERATION3_SCHEMA_ACL + f"\nPUBLIC|{GENERATION3_ROLES[1]}|USAGE|false"},
            {"DEFAULT_ACL": "\n".join(GENERATION3_DEFAULT_ACL.splitlines()[1:])},
            {"DEFAULT_ACL": GENERATION3_DEFAULT_ACL.replace(
                f"|{GENERATION3_ROLES[1]}|EXECUTE|false",
                "|evil|EXECUTE|false",
                1,
            )},
            {"DEFAULT_ACL": GENERATION3_DEFAULT_ACL, "DEFAULT_RECORDS": ""},
            {"DEFAULT_ACL": "", "DEFAULT_RECORDS": GENERATION3_DEFAULT_ACL_RECORDS},
            {"DEFAULT_RECORDS": GENERATION3_DEFAULT_ACL_RECORDS.splitlines()[0]},
            {"DEFAULT_RECORDS": GENERATION3_DEFAULT_ACL_RECORDS + f"\n{GENERATION3_ROLES[1]}|<global>|r"},
            {"DATABASE_OWNER": GENERATION3_ROLES[0]},
            {"SCHEMA_OWNER": GENERATION3_ROLES[0]},
            {"PUBLIC_OWNERS": f"{GENERATION3_ROLES[0]}\n{GENERATION3_ROLES[1]}"},
            {"RECORDS": retired.replace("|false|backupsheep:database-identity-v3", "|true|backupsheep:database-identity-v3", 1)},
            {"ROLES": "\n".join(sorted(GENERATION3_ROLES + ("evil",))), "RECORDS": generation3_records() + "\nevil|false|true|false|false|true|false|false|128|true|false|true|unexpected"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(self.run_generation3(**mutation).returncode, 0)

    def test_fixed_target_placeholders_are_exact_and_fail_closed(self):
        def validate(**overrides):
            values = {
                "INSTALLATION": INSTALLATION_ID,
                "BOOTSTRAP": GENERATION3_ROLES[0],
                "ROSTER": GENERATION3_ROSTER,
                "RECORDS": target_placeholder_records(),
                "MEMBERSHIPS": "0",
                "SETTINGS": "",
            }
            values.update(overrides)
            return self.run_contract(
                "backupsheep_validate_target_placeholders "
                '"$INSTALLATION" "$BOOTSTRAP" "$ROSTER" "$RECORDS" '
                '"$MEMBERSHIPS" "$SETTINGS"',
                **values,
            )

        self.assertEqual(validate().returncode, 0)
        for mutation in (
            {"INSTALLATION": OTHER_INSTALLATION_ID},
            {"MEMBERSHIPS": "1"},
            {
                "SETTINGS": (
                    f"{GENERATION3_ROLES[1]}|<all-databases>|search_path=public"
                )
            },
            {
                "RECORDS": target_placeholder_records().replace(
                    "|-1|true|true|true|", "|8|true|true|true|", 1
                )
            },
            {
                "RECORDS": target_placeholder_records().replace(
                    "|true|true|true|backupsheep:database",
                    "|false|true|true|backupsheep:database",
                    1,
                )
            },
            {
                "RECORDS": target_placeholder_records()
                + "\nevil|false|true|false|false|true|false|false|-1|true|true|true|evil"
            },
        ):
            with self.subTest(mutation=mutation):
                self.assertNotEqual(validate(**mutation).returncode, 0)

    def completed_evidence(self):
        return "\n".join(
            (
                "status=complete",
                f"generation={STORAGE_GENERATION}",
                f"installation={INSTALLATION_ID}",
                f"intent={GENERATION2_INTENT}",
                "witness=" + ("e" * 64),
                "--receipt--",
                "status=complete",
                "receipt_version=2",
                "restore_strategy=fixed-target-v3-roles-unprivileged-custom-v1",
                "source_contract=generation2-three-role-v1",
                f"source_image={SOURCE_IMAGE_ID}",
                f"target_image={TARGET_IMAGE_ID}",
                "roles_sha256=" + ("1" * 64),
                "schema_sha256=" + ("2" * 64),
                "data_sha256=" + ("3" * 64),
            )
        )

    def validate_evidence(self, evidence, **overrides):
        values = {
            "EVIDENCE": evidence,
            "GENERATION": STORAGE_GENERATION,
            "INSTALLATION": INSTALLATION_ID,
            "INTENT": GENERATION2_INTENT,
            "WITNESS": "e" * 64,
            "SOURCE_IMAGE": SOURCE_IMAGE_ID,
            "TARGET_IMAGE": TARGET_IMAGE_ID,
        }
        values.update(overrides)
        return self.run_contract(
            "backupsheep_validate_completed_postgres_migration_evidence "
            '"$EVIDENCE" "$GENERATION" "$INSTALLATION" "$INTENT" '
            '"$WITNESS" "$SOURCE_IMAGE" "$TARGET_IMAGE"',
            **values,
        )

    def test_completed_receipt_is_exact_installation_and_current_image_bound(self):
        evidence = self.completed_evidence()
        result = self.validate_evidence(evidence)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, TARGET_IMAGE_ID)

        for override in (
            {"INSTALLATION": OTHER_INSTALLATION_ID},
            {"WITNESS": "f" * 64},
            {"SOURCE_IMAGE": "sha256:" + ("9" * 64)},
            {"TARGET_IMAGE": "sha256:" + ("8" * 64)},
            {"INTENT": STRICT_INTENT},
        ):
            with self.subTest(override=override):
                self.assertNotEqual(
                    self.validate_evidence(evidence, **override).returncode, 0
                )

    def test_receipt_replay_with_extra_or_malformed_content_is_refused(self):
        valid = self.completed_evidence()
        mutations = (
            valid + "\nunexpected=tail",
            "\n".join(
                line
                for line in valid.splitlines()
                if not line.startswith("receipt_version=")
            ),
            valid.replace("receipt_version=2", "receipt_version=1"),
            valid.replace(
                "restore_strategy=fixed-target-v3-roles-unprivileged-custom-v1",
                "restore_strategy=legacy-superuser-plain-v1",
            ),
            valid.replace(
                "source_contract=generation2-three-role-v1",
                "source_contract=strict-ten-role-v1",
            ),
            valid.replace("roles_sha256=" + ("1" * 64), "roles_sha256=short"),
            valid.replace("status=complete", "status=pending", 1),
            valid.replace(f"target_image={TARGET_IMAGE_ID}", "target_image=sha256:bad"),
        )
        for evidence in mutations:
            with self.subTest(evidence=evidence[-32:]):
                self.assertNotEqual(self.validate_evidence(evidence).returncode, 0)

    def test_sealed_reconcile_mode_can_neither_reset_nor_create_a_target(self):
        source = MIGRATOR.read_text(encoding="utf-8")
        reset_guard = (
            '[[ "$reconcile_only" == false ]] \\\n'
            '        || die "sealed database identity state requires an already-complete '
            'migration receipt; target reset is refused"'
        )
        create_guard = (
            '[[ "$reconcile_only" == false ]] \\\n'
            '    || die "sealed database identity state cannot authorize a new PostgreSQL migration"'
        )
        self.assertIn(reset_guard, source)
        self.assertIn(create_guard, source)
        self.assertLess(source.index(reset_guard), source.index('volume rm "$target_volume"'))
        self.assertLess(source.index(create_guard), source.index("volume create \\\n"))

    def test_restore_is_unprivileged_and_code_bearing_objects_are_preflighted(self):
        source = MIGRATOR.read_text(encoding="utf-8")
        self.assertIn(
            "CREATE ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1",
            source,
        )
        self.assertIn(
            "--format=custom --no-owner --no-acl --no-security-labels", source
        )
        self.assertIn("pg_restore --no-password --exit-on-error", source)
        self.assertIn("--single-transaction", source)
        self.assertIn("ALTER SCHEMA public OWNER TO %I", source)
        self.assertIn("ALTER ROLE %I NOLOGIN", source)
        self.assertIn("pg_terminate_backend", source)
        self.assertIn("REASSIGN OWNED BY %I TO %I", source)
        self.assertIn("DROP OWNED BY %I", source)
        self.assertIn("DROP ROLE %I", source)
        self.assertIn("pg_largeobject_metadata", source)
        self.assertIn("language.lanname NOT IN ('sql','plpgsql')", source)
        self.assertIn("COALESCE(auth.rolpassword LIKE 'SCRAM-SHA-256\\$%', false)", source)
        self.assertLess(source.index("pg_largeobject_metadata"), source.index("prepare-restore"))
        self.assertLess(source.index("prepare-restore"), source.index("dump-source"))
        self.assertLess(source.index("dump-source"), source.index("restore-target"))
        self.assertLess(source.index("restore-target"), source.index("finalize-restore"))
        self.assertNotIn("helper_runtime", source)
        self.assertIn(
            'source_dump_helper=("${helper_base[@]}" -v "${source_socket}:/source:ro" '
            '-v "${secret_file}:/run/secrets/source_password:ro")',
            source,
        )
        self.assertIn(
            'target_restore_helper=("${helper_base[@]}" -v "${target_socket}:/target:ro" '
            '-v "${restore_secret_file}:/run/secrets/restore_password:ro")',
            source,
        )
        self.assertNotIn("VALID UNTIL", source)
        self.assertIn('chmod 0444 "$ephemeral_secret"', source)
        self.assertIn("credential-read-attestation", source)
        self.assertIn("migration-bootstrap.XXXXXXXX", source)
        self.assertIn("migration-restore.XXXXXXXX", source)
        self.assertLess(
            source.index('target_bootstrap_secret_file=""', source.index("prove-credential-rotation")),
            source.index("dump-source"),
        )
        self.assertIn("default_transaction_read_only=on", source)
        self.assertIn("shared_preload_libraries=", source)
        self.assertIn("max_parallel_apply_workers_per_subscription=0", source)
        self.assertIn("output_plugin_libraries=", source)
        self.assertIn("pg_prepared_xacts", source)
        self.assertIn("pg_catalog.pg_attribute", source)
        self.assertIn("REVOKE USAGE ON TYPE %I.%I FROM PUBLIC", source)
        self.assertGreaterEqual(source.count("pg_catalog.acldefault("), 5)
        self.assertEqual(source.count("type.typtype NOT IN ('m','p')"), 2)
        self.assertEqual(source.count("pg_catalog.array_subscript_handler"), 2)
        self.assertIn('"$target_migrator_user" "$target_migrator_user"', source)

    def test_multiline_sql_and_restore_streams_are_attached_as_literal_stdin(self):
        source = MIGRATOR.read_text(encoding="utf-8")
        for delimiter in (
            "TARGET_PLACEHOLDER_SCRIPT",
            "PREPARE_RESTORE_SCRIPT",
            "FINALIZE_RESTORE_SCRIPT",
            "TARGET_OWNERSHIP_SCRIPT",
        ):
            with self.subTest(delimiter=delimiter):
                self.assertIn(f"<<'{delimiter}'", source)
        self.assertNotIn("<<'\"'\"'SQL'\"'\"'", source)
        self.assertEqual(source.count("run --interactive"), 5)
        self.assertIn(
            'run --interactive "${target_restore_helper[@]}"', source
        )
        self.assertEqual(source.count("$target_image_id\" -seu --"), 4)
        self.assertIn(
            "if ! \"$docker_bin\" run --interactive \"${target_admin_helper[@]}\"",
            source,
        )
        self.assertIn(">/dev/null <<'FINALIZE_RESTORE_SCRIPT'", source)
        self.assertIn(
            "FINALIZE_RESTORE_SCRIPT\nthen\n"
            '    die "could not retire the ephemeral restore identity and normalize ownership"\n'
            "fi",
            source,
        )

    def test_literal_stdin_scripts_preserve_sql_and_positional_arguments(self):
        source = MIGRATOR.read_text(encoding="utf-8")
        cases = (
            (
                "TARGET_PLACEHOLDER_SCRIPT",
                "target-placeholder-attestation",
                ("backupsheep_bootstrap", "backupsheep"),
                "COALESCE(database.datname, '<all-databases>')",
                "'SCRAM-SHA-256$%'",
            ),
            (
                "PREPARE_RESTORE_SCRIPT",
                "prepare-restore",
                ("backupsheep_bootstrap", "backupsheep", "restore_role", INSTALLATION_ID),
                "'CREATE ROLE %I WITH LOGIN NOINHERIT",
                ":'restore_role'",
            ),
            (
                "FINALIZE_RESTORE_SCRIPT",
                "finalize-restore",
                (
                    "backupsheep_bootstrap",
                    "backupsheep",
                    "restore_role",
                    "backupsheep_migrator",
                    "backupsheep_migrator",
                ),
                "'REASSIGN OWNED BY %I TO %I'",
                ":'restore_role'",
            ),
            (
                "TARGET_OWNERSHIP_SCRIPT",
                "target-ownership",
                ("backupsheep_bootstrap", "backupsheep", "restore_role"),
                "pg_catalog.acldefault('T', type.typowner)",
                ":'restore_role'",
            ),
        )
        with tempfile.TemporaryDirectory(prefix="postgres-literal-stdin-") as temp_dir:
            fake_bin = Path(temp_dir) / "bin"
            fake_bin.mkdir()
            fake_cat = fake_bin / "cat"
            fake_cat.write_text(
                "#!/bin/sh\n"
                "case \"${1:-}\" in\n"
                "  *restore_password*) printf '%s\\n' restore-secret ;;\n"
                "  *) printf '%s\\n' source-secret ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_cat.chmod(0o755)
            fake_psql = fake_bin / "psql"
            fake_psql.write_text(
                "#!/bin/sh\n"
                ": \"${CAPTURE_ARGS:?}\" \"${CAPTURE_STDIN:?}\"\n"
                "printf '%s\\0' \"$@\" > \"$CAPTURE_ARGS\"\n"
                "/bin/cat > \"$CAPTURE_STDIN\"\n"
                "quiet=false\n"
                "for argument do\n"
                "  [ \"$argument\" = --quiet ] && quiet=true\n"
                "done\n"
                "[ \"$quiet\" = true ] || printf 'COMMAND STATUS\\n'\n"
                "printf '%s' \"${PSQL_EXPECTED_STDOUT:-}\"\n",
                encoding="utf-8",
            )
            fake_psql.chmod(0o755)

            for delimiter, sentinel, arguments, sql_fragment, parameter_fragment in cases:
                with self.subTest(delimiter=delimiter):
                    body = source.split(f"<<'{delimiter}'\n", 1)[1].split(
                        f"\n{delimiter}\n", 1
                    )[0]
                    capture_args = Path(temp_dir) / f"{delimiter}.args"
                    capture_stdin = Path(temp_dir) / f"{delimiter}.sql"
                    environment = os.environ.copy()
                    expected_stdout = ""
                    if delimiter == "PREPARE_RESTORE_SCRIPT":
                        expected_stdout = (
                            "restore_role|false|false|false|false|true|false|false|1|"
                            "true|true|true|"
                            f"backupsheep:postgres-restore-v1:{INSTALLATION_ID}\n0\n"
                        )
                    environment.update(
                        PATH=f"{fake_bin}:{environment['PATH']}",
                        CAPTURE_ARGS=str(capture_args),
                        CAPTURE_STDIN=str(capture_stdin),
                        PSQL_EXPECTED_STDOUT=expected_stdout,
                    )
                    result = subprocess.run(
                        ["/bin/sh", "-seu", "--", sentinel, *arguments],
                        input=body + "\n",
                        check=False,
                        capture_output=True,
                        text=True,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    psql_arguments = capture_args.read_bytes().split(b"\0")[:-1]
                    self.assertEqual(
                        psql_arguments[psql_arguments.index(b"-U") + 1],
                        b"backupsheep_bootstrap",
                    )
                    self.assertEqual(
                        psql_arguments[psql_arguments.index(b"-d") + 1],
                        b"backupsheep",
                    )
                    if delimiter == "PREPARE_RESTORE_SCRIPT":
                        self.assertIn(b"--quiet", psql_arguments)
                        self.assertEqual(result.stdout, expected_stdout)
                    captured_sql = capture_stdin.read_text(encoding="utf-8")
                    self.assertIn(sql_fragment, captured_sql)
                    self.assertIn(parameter_fragment, captured_sql)

    def test_default_acl_object_types_are_explicitly_serialized_as_text(self):
        source = MIGRATOR.read_text(encoding="utf-8")
        self.assertEqual(source.count("defaults.defaclobjtype::text"), 2)
        self.assertNotIn("defaults.defaclobjtype ||", source)


class PostgresInterruptedMigrationRecoveryTests(TestCase):
    @staticmethod
    def migration_function_chunk(start, end):
        source = MIGRATOR.read_text(encoding="utf-8")
        return start + source.split(start, 1)[1].split(end, 1)[0]

    def run_source_attachment_contract(self, **overrides):
        values = {
            "PROJECT_LABEL": "backupsheep",
            "INSTALLATION_LABEL": INSTALLATION_ID,
            "PURPOSE_LABEL": "postgres-runtime-" + ("e" * 64),
            "COMPOSE_PROJECT_LABEL": "",
            "COMPOSE_SERVICE_LABEL": "",
            "RUNTIME_RECORD": (
                f"/backupsheep-postgres-migration-source|{SOURCE_IMAGE_ID}|999:999|"
                "none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|"
                "/usr/local/bin/docker-entrypoint.sh"
            ),
            "MOUNT_RECORDS": (
                "volume|backupsheep_pgdata|/var/lib/postgresql|true\n"
                "volume|backupsheep_postgres_migration_source_socket|"
                "/var/run/postgresql|true"
            ),
        }
        values.update(overrides)
        command = r'''
source "$1"
PROJECT_NAME=backupsheep
DOCKER_BIN=mock_docker
mock_docker() {
    [[ "$1" == inspect && "$2" == --format ]] || return 91
    template="$3"
    case "$template" in
        *com.backupsheep.project*) value="$PROJECT_LABEL" ;;
        *com.backupsheep.installation-id*) value="$INSTALLATION_LABEL" ;;
        *com.backupsheep.postgres-migration*) value="$PURPOSE_LABEL" ;;
        *com.docker.compose.project*) value="$COMPOSE_PROJECT_LABEL" ;;
        *com.docker.compose.service*) value="$COMPOSE_SERVICE_LABEL" ;;
        '{{.Name}}|'*) printf '%s\n' "$RUNTIME_RECORD"; return 0 ;;
        '{{range .Mounts}}'*) printf '%s\n' "$MOUNT_RECORDS"; return 0 ;;
        *) return 92 ;;
    esac
    printf '%s:%s%s\n' "${#value}" "$value" '__BACKUPSHEEP_DOCKER_LABEL_FRAME_V1__'
}
is_exact_interrupted_postgres_source container-id \
    "$INSTALLATION" "$WITNESS" "$SOURCE_IMAGE"
'''
        env = os.environ.copy()
        env.update(
            values,
            INSTALLATION=INSTALLATION_ID,
            WITNESS="e" * 64,
            SOURCE_IMAGE=SOURCE_IMAGE_ID,
        )
        return subprocess.run(
            ["/bin/bash", "-c", command, "interrupted-source-test", str(INSTALLER)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_abrupt_crash_source_is_recognized_only_by_exact_runtime_witness(self):
        accepted = self.run_source_attachment_contract()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        mutations = {
            "wrong-project": {"PROJECT_LABEL": "other"},
            "wrong-installation": {"INSTALLATION_LABEL": OTHER_INSTALLATION_ID},
            "wrong-purpose": {"PURPOSE_LABEL": "postgres-runtime-" + ("f" * 64)},
            "compose-container": {"COMPOSE_PROJECT_LABEL": "backupsheep"},
            "wrong-user": {
                "RUNTIME_RECORD": (
                    f"/backupsheep-postgres-migration-source|{SOURCE_IMAGE_ID}|0:0|"
                    "none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|"
                    "/usr/local/bin/docker-entrypoint.sh"
                )
            },
            "extra-mount": {
                "MOUNT_RECORDS": (
                    "volume|backupsheep_pgdata|/var/lib/postgresql|true\n"
                    "volume|backupsheep_postgres_migration_source_socket|"
                    "/var/run/postgresql|true\n"
                    "bind||/host|/unexpected|false"
                )
            },
        }
        for scenario, mutation in mutations.items():
            with self.subTest(scenario=scenario):
                refused = self.run_source_attachment_contract(**mutation)
                self.assertNotEqual(refused.returncode, 0)

        installer = INSTALLER.read_text(encoding="utf-8")
        ownership = installer.split("validate_compose_project_ownership() {", 1)[
            1
        ].split("\n}\n", 1)[0]
        self.assertIn("is_exact_interrupted_postgres_source", ownership)
        runner = installer.split("run_postgres_runtime_migration() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertNotIn("prove legacy PostgreSQL detachment", runner)
        migrator = MIGRATOR.read_text(encoding="utf-8")
        self.assertLess(
            migrator.index('remove_owned_container "$source_container"'),
            migrator.index("legacy source volume is absent"),
        )

    def run_secret_residue_cleanup(
        self,
        secret_file,
        *,
        attached=False,
        attached_path=None,
        host_kernel="Linux",
        docker_daemon_identity="Docker Engine|linux",
    ):
        functions = self.migration_function_chunk(
            "normalize_docker_bind_source() {", "cleanup() {"
        )
        residue_paths = list(
            secret_file.parent.glob(secret_file.name + ".migration-*")
        )
        command = r'''
set -Eeuo pipefail
die() { printf '%s\n' "$*" >&2; exit 64; }
docker_bin=mock_docker
secret_file="$1"
host_kernel="$HOST_KERNEL"
docker_daemon_identity="$DOCKER_DAEMON_IDENTITY"
mock_docker() {
    if [[ "$1" == ps ]]; then
        [[ "$ATTACHED" == true ]] && printf '%s\n' attached-container
        return 0
    fi
    if [[ "$1" == inspect && "$2" == --format ]]; then
        [[ "$ATTACHED" == true ]] && printf '%s\n' "$ATTACHED_PATH"
        return 0
    fi
    if [[ "$1" == inspect ]]; then return 0; fi
    return 91
}
remove_unattached_ephemeral_secret_residue
'''
        env = os.environ.copy()
        env.update(
            ATTACHED=str(attached).lower(),
            ATTACHED_PATH=(
                str(attached_path)
                if attached_path is not None
                else str(residue_paths[0]) if attached and residue_paths else ""
            ),
            HOST_KERNEL=host_kernel,
            DOCKER_DAEMON_IDENTITY=docker_daemon_identity,
        )
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                functions + "\n" + command,
                "secret-residue-test",
                str(secret_file),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_sigkill_secret_residue_is_removed_only_after_exact_safety_checks(self):
        with tempfile.TemporaryDirectory(prefix="postgres-secret-residue-") as temp_dir:
            secret = Path(temp_dir) / "db_bootstrap_password"
            secret.write_text("installed-secret\n", encoding="ascii")
            for kind, suffix in (("bootstrap", "A1b2C3d4"), ("restore", "Z9y8X7w6")):
                residue = Path(f"{secret}.migration-{kind}.{suffix}")
                residue.write_text(("a" * 64) + "\n", encoding="ascii")
                residue.chmod(0o444)
            result = self.run_secret_residue_cleanup(secret)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(list(Path(temp_dir).glob("*.migration-*")))

        for byte_count in (0, 17, 65):
            with self.subTest(construction_residue_size=byte_count), tempfile.TemporaryDirectory(
                prefix="postgres-secret-residue-construction-"
            ) as temp_dir:
                secret = Path(temp_dir) / "db_bootstrap_password"
                secret.write_text("installed-secret\n", encoding="ascii")
                residue = Path(f"{secret}.migration-bootstrap.A1b2C3d4")
                residue.write_bytes(b"partial-not-yet-canonical"[:byte_count].ljust(byte_count, b"!"))
                residue.chmod(0o600)
                result = self.run_secret_residue_cleanup(secret)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(residue.exists())

        for scenario in (
            "mode",
            "content",
            "oversized-construction",
            "suffix",
            "symlink",
            "hardlink",
            "attached",
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                prefix="postgres-secret-residue-hostile-"
            ) as temp_dir:
                secret = Path(temp_dir) / "db_bootstrap_password"
                secret.write_text("installed-secret\n", encoding="ascii")
                suffix = "SHORT" if scenario == "suffix" else "A1b2C3d4"
                residue = Path(f"{secret}.migration-restore.{suffix}")
                if scenario == "symlink":
                    target = Path(temp_dir) / "symlink-target"
                    target.write_text(("a" * 64) + "\n", encoding="ascii")
                    residue.symlink_to(target)
                else:
                    if scenario == "oversized-construction":
                        residue.write_bytes(b"a" * 66)
                        residue.chmod(0o600)
                    else:
                        residue.write_text(
                            ("g" * 64 if scenario == "content" else "a" * 64) + "\n",
                            encoding="ascii",
                        )
                        residue.chmod(0o640 if scenario == "mode" else 0o444)
                    if scenario == "hardlink":
                        os.link(residue, Path(temp_dir) / "second-link")
                result = self.run_secret_residue_cleanup(
                    secret, attached=scenario == "attached"
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(residue.exists() or residue.is_symlink())

        with tempfile.TemporaryDirectory(
            prefix="postgres-secret-residue-desktop-"
        ) as temp_dir:
            secret = Path(temp_dir) / "db_bootstrap_password"
            secret.write_text("installed-secret\n", encoding="ascii")
            residue = Path(f"{secret}.migration-restore.A1b2C3d4")
            residue.write_text(("a" * 64) + "\n", encoding="ascii")
            residue.chmod(0o444)
            result = self.run_secret_residue_cleanup(
                secret,
                attached=True,
                attached_path="/host_mnt" + str(residue),
                host_kernel="Darwin",
                docker_daemon_identity="Docker Desktop|linux",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(residue.exists())

            ambiguous_paths = (
                "/host_mnt" + str(residue.parent) + "/../" + residue.parent.name + "/" + residue.name,
                "/host_mnt/host_mnt" + str(residue),
                "/host_mnt" + str(residue) + "|foreign",
            )
            for attached_path in ambiguous_paths:
                with self.subTest(attached_path=attached_path):
                    result = self.run_secret_residue_cleanup(
                        secret,
                        attached=True,
                        attached_path=attached_path,
                        host_kernel="Darwin",
                        docker_daemon_identity="Docker Desktop|linux",
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(residue.exists())

            unsupported = self.run_secret_residue_cleanup(
                secret,
                attached=True,
                attached_path="/host_mnt" + str(residue),
                host_kernel="Darwin",
                docker_daemon_identity="Other Desktop|linux",
            )
            self.assertNotEqual(unsupported.returncode, 0)
            self.assertTrue(residue.exists())

    def test_docker_desktop_bind_source_normalization_is_narrow(self):
        functions = self.migration_function_chunk(
            "normalize_docker_bind_source() {", "remove_owned_container() {"
        )
        command = r'''
set -Eeuo pipefail
host_kernel="$HOST_KERNEL"
docker_daemon_identity="$DOCKER_DAEMON_IDENTITY"
secret_file=/private/tmp/safe/db_bootstrap_password
case "$MODE" in
    exact) docker_bind_source_matches "$REPORTED" "$EXPECTED" ;;
    ephemeral) is_exact_ephemeral_secret_bind_source "$REPORTED" "$KIND" ;;
    *) exit 98 ;;
esac
'''

        def run(
            reported,
            *,
            expected="/private/tmp/safe/db_bootstrap_password",
            host_kernel="Darwin",
            daemon="Docker Desktop|linux",
            mode="exact",
            kind="bootstrap",
        ):
            return subprocess.run(
                ["/bin/bash", "-c", functions + "\n" + command],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "HOST_KERNEL": host_kernel,
                    "DOCKER_DAEMON_IDENTITY": daemon,
                    "MODE": mode,
                    "REPORTED": reported,
                    "EXPECTED": expected,
                    "KIND": kind,
                },
            )

        accepted = (
            run("/host_mnt/private/tmp/safe/db_bootstrap_password"),
            run(
                "/private/tmp/safe/db_bootstrap_password",
                host_kernel="Linux",
                daemon="",
            ),
            run(
                "/host_mnt/private/tmp/safe/db_bootstrap_password."
                "migration-bootstrap.A1b2C3d4",
                mode="ephemeral",
            ),
        )
        for result in accepted:
            self.assertEqual(result.returncode, 0, result.stderr)

        refused = (
            run(
                "/host_mnt/private/tmp/safe/db_bootstrap_password",
                host_kernel="Linux",
                daemon="Docker Desktop|linux",
            ),
            run(
                "/host_mnt/private/tmp/safe/db_bootstrap_password",
                daemon="Other Desktop|linux",
            ),
            run("/host_mnt/private/tmp/../safe/db_bootstrap_password"),
            run("/host_mnt/host_mnt/private/tmp/safe/db_bootstrap_password"),
            run(
                "/host_mnt/private/tmp/safe/db_bootstrap_password."
                "migration-bootstrap.SHORT",
                mode="ephemeral",
            ),
            run(
                "/host_mnt/private/tmp/safe/db_bootstrap_password."
                "migration-bootstrap.A1b2C3d4extra",
                mode="ephemeral",
            ),
            run(
                "/host_mnt/private/tmp/safe/db_bootstrap_password."
                "migration-restore.A1b2C3d4",
                mode="ephemeral",
                kind="bootstrap",
            ),
        )
        for result in refused:
            self.assertNotEqual(result.returncode, 0)

    def test_docker_mount_record_sort_removes_only_format_blank_lines(self):
        function = self.migration_function_chunk(
            "sort_nonempty_docker_mount_records() {",
            "normalize_docker_bind_source() {",
        )
        records = (
            "\n"
            "volume|z|/z|true|/engine/z\n"
            " \n"
            "volume|a|/a|false|/engine/a\n"
            "\n"
        )
        result = subprocess.run(
            [
                "/bin/bash",
                "-c",
                function + "\nsort_nonempty_docker_mount_records",
            ],
            input=records,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            " \n"
            "volume|a|/a|false|/engine/a\n"
            "volume|z|/z|true|/engine/z\n",
        )
        source = MIGRATOR.read_text(encoding="utf-8")
        self.assertEqual(source.count("| sort_nonempty_docker_mount_records"), 2)

    def test_target_cleanup_parses_the_entire_bind_source_before_removal(self):
        functions = self.migration_function_chunk(
            "sort_nonempty_docker_mount_records() {",
            "validate_interrupted_helper_mounts() {",
        )
        image_id = "sha256:" + ("4" * 64)
        command = r'''
set -Eeuo pipefail
die() { printf '%s\n' "$*" >&2; exit 64; }
docker_bin=mock_docker
project=backupsheep
installation_id="$(printf '%064d' 0)"
purpose="postgres-runtime-$(printf '%064d' 1)"
source_container=backupsheep-postgres-migration-source
target_container=backupsheep-postgres-migration-target
target_socket=backupsheep_postgres_migration_target_socket
target_volume=backupsheep_postgres_data_v1
secret_file=/private/tmp/safe/db_bootstrap_password
host_kernel=Darwin
docker_daemon_identity='Docker Desktop|linux'
docker_resource_label() {
    case "$1|$3" in
        container\|com.backupsheep.installation-id) printf '%s' "$installation_id" ;;
        container\|com.backupsheep.postgres-migration) printf '%s' "$purpose" ;;
        container\|com.backupsheep.project) printf '%s' "$project" ;;
        image\|com.backupsheep.postgres.runtime-generation)
            printf '%s' 18.6-alpine3.24-icu-v1 ;;
        *) return 93 ;;
    esac
}
mock_docker() {
    if [[ "$1" == ps ]]; then printf '%s\n' container-id; return 0; fi
    if [[ "$1" == inspect && "$2" == --format ]]; then
        case "$3" in
            '{{.Image}}|'*)
                printf '%s\n' "$IMAGE_ID|70:70|none|true|[\"ALL\"]|[\"no-new-privileges:true\"]|/usr/local/bin/docker-entrypoint.sh"
                ;;
            '{{range .Mounts}}'*) printf '%s\n\n' "$MOUNT_RECORDS" ;;
            *) return 94 ;;
        esac
        return 0
    fi
    if [[ "$1" == stop || "$1" == rm ]]; then
        printf '%s\n' "$1" >> "$MUTATION_LOG"
        return 0
    fi
    return 95
}
remove_owned_container "$target_container"
'''

        def run(source):
            records = (
                "volume|backupsheep_postgres_migration_target_socket|"
                "/var/run/postgresql|true|/engine/socket\n"
                "volume|backupsheep_postgres_data_v1|/var/lib/postgresql|"
                "true|/engine/data\n"
                "bind||/run/secrets/db_bootstrap_password|false|" + source
            )
            with tempfile.TemporaryDirectory(
                prefix="postgres-target-cleanup-"
            ) as temp_dir:
                mutation_log = Path(temp_dir) / "mutations"
                result = subprocess.run(
                    ["/bin/bash", "-c", functions + "\n" + command],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "IMAGE_ID": image_id,
                        "MOUNT_RECORDS": records,
                        "MUTATION_LOG": str(mutation_log),
                    },
                )
                mutations = (
                    mutation_log.read_text(encoding="utf-8")
                    if mutation_log.exists()
                    else ""
                )
                return result, mutations

        valid, mutations = run(
            "/host_mnt/private/tmp/safe/db_bootstrap_password."
            "migration-bootstrap.A1b2C3d4"
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(mutations, "stop\nrm\n")

        hostile_sources = (
            "/foreign|/host_mnt/private/tmp/safe/db_bootstrap_password."
            "migration-bootstrap.A1b2C3d4",
            "/host_mnt/private/tmp/../tmp/safe/db_bootstrap_password."
            "migration-bootstrap.A1b2C3d4",
            "/host_mnt/host_mnt/private/tmp/safe/db_bootstrap_password."
            "migration-bootstrap.A1b2C3d4",
            "/host_mnt/private/tmp/safe/db_bootstrap_password."
            "migration-bootstrap.A1b2C3d4extra",
        )
        for source in hostile_sources:
            with self.subTest(source=source):
                refused, mutations = run(source)
                self.assertNotEqual(refused.returncode, 0)
                self.assertEqual(mutations, "")

    def test_existing_target_evidence_distinguishes_absence_from_corruption(self):
        function = self.migration_function_chunk(
            "classify_existing_target_evidence() {", "remove_owned_container() {"
        )
        pending_marker = (
            "status=pending\n"
            "generation=18-alpine-icu-v1\n"
            f"installation={INSTALLATION_ID}\n"
            f"intent={GENERATION2_INTENT}\n"
            + "witness=" + ("e" * 64)
        )
        complete_marker = pending_marker.replace("status=pending", "status=complete")
        receipt = "\n".join(
            (
                "status=complete",
                "receipt_version=2",
                "restore_strategy=fixed-target-v3-roles-unprivileged-custom-v1",
                "source_contract=generation2-three-role-v1",
                f"source_image={SOURCE_IMAGE_ID}",
                f"target_image={TARGET_IMAGE_ID}",
                "roles_sha256=" + ("1" * 64),
                "schema_sha256=" + ("2" * 64),
                "data_sha256=" + ("3" * 64),
            )
        )

        def run(evidence):
            return subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    function
                    + '\nclassify_existing_target_evidence "$EVIDENCE" '
                    '"$PENDING_MARKER" "$COMPLETE_MARKER"',
                ],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "EVIDENCE": evidence,
                    "PENDING_MARKER": pending_marker,
                    "COMPLETE_MARKER": complete_marker,
                },
            )

        absent = run(
            "--storage-marker-absent-v2--\n"
            "--receipt-absent-v2--\n"
            "--evidence-end-v2--"
        )
        self.assertEqual(absent.returncode, 0, absent.stderr)
        self.assertEqual(absent.stdout, "absent")

        pending = run(
            "--storage-marker-present-v2--\n"
            + pending_marker
            + "\n--receipt-absent-v2--\n--evidence-end-v2--"
        )
        self.assertEqual(pending.returncode, 0, pending.stderr)
        self.assertEqual(pending.stdout, "pending-empty")

        pending_receipt = run(
            "--storage-marker-present-v2--\n"
            + pending_marker
            + "\n--receipt-present-v2--\n"
            + receipt
            + "\n--evidence-end-v2--"
        )
        self.assertEqual(pending_receipt.returncode, 0, pending_receipt.stderr)
        self.assertEqual(
            pending_receipt.stdout,
            "pending-receipt\n" + pending_marker + "\n--receipt--\n" + receipt,
        )

        complete = run(
            "--storage-marker-present-v2--\n"
            + complete_marker
            + "\n--receipt-present-v2--\n"
            + receipt
            + "\n--evidence-end-v2--"
        )
        self.assertEqual(complete.returncode, 0, complete.stderr)
        self.assertEqual(
            complete.stdout,
            "complete\n" + complete_marker + "\n--receipt--\n" + receipt,
        )

        malformed = (
            "--receipt--",
            "--storage-marker-absent-v2--\n--receipt-absent-v2--",
            "--storage-marker-absent-v2--\n--receipt-present-v2--\n"
            + receipt
            + "\n--evidence-end-v2--",
            "--storage-marker-present-v2--\n\n"
            + complete_marker
            + "\n--receipt-present-v2--\n"
            + receipt
            + "\n--evidence-end-v2--",
            "--storage-marker-present-v2--\n"
            + pending_marker.replace(f"installation={INSTALLATION_ID}", "installation=wrong")
            + "\n--receipt-absent-v2--\n--evidence-end-v2--",
            "--storage-marker-present-v2--\n"
            + pending_marker
            + "\n--receipt-present-v2--\n"
            + "\n".join(receipt.splitlines()[:-1])
            + "--evidence-end-v2--",
            "--storage-marker-present-v2--\n"
            + pending_marker
            + "\n--receipt-present-v2--\n"
            + receipt
            + "\n\n--evidence-end-v2--",
            "--storage-marker-unknown-v2--\n--receipt-absent-v2--\n"
            "--evidence-end-v2--",
        )
        for evidence in malformed:
            with self.subTest(evidence=evidence):
                self.assertNotEqual(run(evidence).returncode, 0)

        source = MIGRATOR.read_text(encoding="utf-8")
        self.assertNotIn(
            "cat /evidence/.backupsheep-storage-witness-v1 2>/dev/null || true",
            source,
        )
        self.assertNotIn(
            "cat /evidence/.backupsheep-logical-migration-receipt-v2 "
            "2>/dev/null || true",
            source,
        )
        self.assertIn('bounded_evidence_file "$marker" 5 512', source)
        self.assertIn('bounded_evidence_file "$receipt" 9 1024', source)
        self.assertIn('stat -c "%s" "$evidence_path"', source)
        self.assertNotIn('evidence_bytes="$(wc -c < "$evidence_path"', source)
        self.assertIn('tr -d "\\012\\040-\\176"', source)

    def test_existing_target_evidence_files_are_bounded_before_capture(self):
        function = self.migration_function_chunk(
            "bounded_evidence_file() {",
            "marker=/evidence/.backupsheep-storage-witness-v1",
        )

        def validate(path, lines, maximum):
            return subprocess.run(
                [
                    "/bin/sh",
                    "-ceu",
                    function
                    + '\nbounded_evidence_file "$1" "$2" "$3"',
                    "bounded-evidence-test",
                    str(path),
                    str(lines),
                    str(maximum),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        with tempfile.TemporaryDirectory(
            prefix="postgres-bounded-evidence-"
        ) as temp_dir:
            root = Path(temp_dir)
            valid = root / "valid"
            valid.write_bytes(b"one\ntwo\nthree\nfour\nfive\n")
            self.assertEqual(validate(valid, 5, 512).returncode, 0)

            oversized_marker = root / "oversized-marker"
            oversized_marker.write_bytes((b"a" * 508) + (b"\n" * 5))
            self.assertNotEqual(validate(oversized_marker, 5, 512).returncode, 0)

            oversized_receipt = root / "oversized-receipt"
            oversized_receipt.write_bytes((b"a" * 1016) + (b"\n" * 9))
            self.assertNotEqual(
                validate(oversized_receipt, 9, 1024).returncode,
                0,
            )

            sparse = root / "sparse-marker"
            with sparse.open("wb") as sparse_file:
                sparse_file.seek((1024 * 1024 * 1024) - 1)
                sparse_file.write(b"\n")
            self.assertNotEqual(validate(sparse, 5, 512).returncode, 0)

            missing_final_newline = root / "missing-final-newline"
            missing_final_newline.write_bytes(b"one\ntwo\nthree\nfour\nfive")
            self.assertNotEqual(
                validate(missing_final_newline, 5, 512).returncode,
                0,
            )

            extra_final_newline = root / "extra-final-newline"
            extra_final_newline.write_bytes(b"one\ntwo\nthree\nfour\nfive\n\n")
            self.assertNotEqual(
                validate(extra_final_newline, 5, 512).returncode,
                0,
            )

            binary = root / "binary"
            binary.write_bytes(b"one\ntwo\x00\nthree\nfour\nfive\n")
            self.assertNotEqual(validate(binary, 5, 512).returncode, 0)

    def test_anonymous_helper_mount_contract_prevents_source_target_secret_crossover(self):
        functions = self.migration_function_chunk(
            "normalize_docker_bind_source() {", "remove_owned_socket_volume() {"
        )
        command = r'''
set -Eeuo pipefail
host_kernel="$HOST_KERNEL"
docker_daemon_identity="$DOCKER_DAEMON_IDENTITY"
source_socket=backupsheep_postgres_migration_source_socket
target_socket=backupsheep_postgres_migration_target_socket
target_volume=backupsheep_postgres_data_v1
secret_file=/safe/db_bootstrap_password
validate_interrupted_helper_mounts "$MOUNTS"
'''
        accepted_records = (
            "volume|backupsheep_postgres_migration_source_socket|/source|false|/engine/source\n"
            "bind||/run/secrets/source_password|false|/safe/db_bootstrap_password",
            "volume|backupsheep_postgres_migration_target_socket|/target|false|/engine/target\n"
            "bind||/run/secrets/restore_password|false|"
            "/safe/db_bootstrap_password.migration-restore.A1b2C3d4",
            "volume|backupsheep_postgres_data_v1|/var/lib/postgresql|true|/engine/data",
            "volume|backupsheep_postgres_data_v1|/evidence|false|/engine/data",
        )
        refused_records = (
            accepted_records[0] + "\n" + accepted_records[1].split("\n", 1)[0],
            "volume|backupsheep_postgres_migration_source_socket|/source|false|/engine/source\n"
            "bind||/run/secrets/restore_password|false|"
            "/safe/db_bootstrap_password.migration-restore.A1b2C3d4",
            "bind||/run/secrets/source_password|false|/host/foreign",
            accepted_records[0] + "\nbind||/unexpected|false|/host/foreign",
        )
        for records in accepted_records:
            result = subprocess.run(
                ["/bin/bash", "-c", functions + "\n" + command],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "MOUNTS": records,
                    "HOST_KERNEL": "Linux",
                    "DOCKER_DAEMON_IDENTITY": "",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        for records in refused_records:
            result = subprocess.run(
                ["/bin/bash", "-c", functions + "\n" + command],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "MOUNTS": records,
                    "HOST_KERNEL": "Linux",
                    "DOCKER_DAEMON_IDENTITY": "",
                },
            )
            self.assertNotEqual(result.returncode, 0)

        desktop_records = (
            "volume|backupsheep_postgres_migration_target_socket|/target|false|"
            "/var/lib/docker/volumes/socket\n"
            "bind||/run/secrets/restore_password|false|/host_mnt/safe/"
            "db_bootstrap_password.migration-restore.A1b2C3d4"
        )
        desktop = subprocess.run(
            ["/bin/bash", "-c", functions + "\n" + command],
            check=False,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "MOUNTS": desktop_records,
                "HOST_KERNEL": "Darwin",
                "DOCKER_DAEMON_IDENTITY": "Docker Desktop|linux",
            },
        )
        self.assertEqual(desktop.returncode, 0, desktop.stderr)
        linux = subprocess.run(
            ["/bin/bash", "-c", functions + "\n" + command],
            check=False,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "MOUNTS": desktop_records,
                "HOST_KERNEL": "Linux",
                "DOCKER_DAEMON_IDENTITY": "Docker Desktop|linux",
            },
        )
        self.assertNotEqual(linux.returncode, 0)


class PostgresInstallerStateMachineTests(TestCase):
    def witness(self, intent=GENERATION2_INTENT):
        material = (
            "BackupSheep/postgres-storage/v1|"
            f"{INSTALLATION_ID}|backupsheep|postgres_data_v1|"
            f"{STORAGE_GENERATION}|icu=und|{intent}"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def run_configure(
        self,
        *,
        state="",
        intent="",
        witness="",
        database_generation="",
        migrate_postgres=True,
        migrate_database=True,
        active_volume=False,
    ):
        command = r'''
source "$1"
PROJECT_NAME=backupsheep
POSTGRES_MIGRATION_REQUIRED=false
MIGRATE_POSTGRES_RUNTIME="$MIGRATE_POSTGRES_VALUE"
MIGRATE_DATABASE_IDENTITIES="$MIGRATE_DATABASE_VALUE"
DOCKER_BIN=mock_docker

read_env_value() {
    case "$1" in
        BACKUPSHEEP_INSTALLATION_ID) printf '%s' "$INSTALLATION_VALUE" ;;
        BACKUPSHEEP_POSTGRES_STORAGE_GENERATION) printf '%s' "$STORAGE_STATE" ;;
        BACKUPSHEEP_POSTGRES_STORAGE_INTENT) printf '%s' "$STORAGE_INTENT" ;;
        BACKUPSHEEP_POSTGRES_STORAGE_WITNESS) printf '%s' "$STORAGE_WITNESS" ;;
        BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID) printf '%s' "$SOURCE_IMAGE" ;;
        BACKUPSHEEP_POSTGRES_IMAGE) printf '%s' legacy-postgres-image ;;
        BACKUPSHEEP_DATABASE_IDENTITY_GENERATION) printf '%s' "$DATABASE_GENERATION" ;;
        *) return 0 ;;
    esac
}
set_env_value() { printf 'SET:%s=%s\n' "$1" "$2" >> "$EVENT_LOG"; }
mock_docker() {
    if [[ "$1:$2" == volume:ls ]]; then
        printf '%s\n' backupsheep_pgdata
        [[ "$ACTIVE_VOLUME" == true ]] && printf '%s\n' backupsheep_postgres_data_v1
        return 0
    fi
    if [[ "$1:$2" == image:inspect ]]; then
        if [[ "${3:-}" == --format && "${4:-}" == '{{.Id}}' ]]; then
            printf '%s\n' "$SOURCE_IMAGE"
        elif [[ "${3:-}" == --format && "${4:-}" == '{{.Config.User}}' ]]; then
            printf '%s\n' '999:999'
        fi
        return 0
    fi
    return 91
}

configure_postgres_storage_generation
printf 'MIGRATION_REQUIRED=%s\n' "$POSTGRES_MIGRATION_REQUIRED"
'''
        env = os.environ.copy()
        with tempfile.TemporaryDirectory(prefix="postgres-storage-state-") as temp_dir:
            event_log = Path(temp_dir) / "events"
            env.update(
                STORAGE_STATE=state,
                STORAGE_INTENT=intent,
                STORAGE_WITNESS=witness,
                DATABASE_GENERATION=database_generation,
                MIGRATE_POSTGRES_VALUE=str(migrate_postgres).lower(),
                MIGRATE_DATABASE_VALUE=str(migrate_database).lower(),
                ACTIVE_VOLUME=str(active_volume).lower(),
                INSTALLATION_VALUE=INSTALLATION_ID,
                SOURCE_IMAGE=SOURCE_IMAGE_ID,
                EVENT_LOG=str(event_log),
            )
            result = subprocess.run(
                ["/bin/bash", "-c", command, "configure-test", str(INSTALLER)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            events = event_log.read_text(encoding="utf-8") if event_log.exists() else ""
            return result, events

    def test_blank_single_superuser_path_is_refused_even_with_both_flags(self):
        result, events = self.run_configure()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not supported for a legacy single-superuser", result.stderr)
        self.assertNotIn("BACKUPSHEEP_POSTGRES_STORAGE_INTENT", events)
        self.assertNotIn("BACKUPSHEEP_POSTGRES_STORAGE_GENERATION", events)

    def test_early_crash_before_database_generation_write_is_resumable_only_explicitly(self):
        state = f"{STORAGE_GENERATION}-pending-upgrade"
        result, _ = self.run_configure(
            state=state,
            intent=GENERATION2_INTENT,
            witness=self.witness(),
            database_generation="2",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MIGRATION_REQUIRED=true", result.stdout)

        for postgres_flag, database_flag in ((False, True), (True, False), (False, False)):
            with self.subTest(
                migrate_postgres=postgres_flag, migrate_database=database_flag
            ):
                refused, _ = self.run_configure(
                    state=state,
                    intent=GENERATION2_INTENT,
                    witness=self.witness(),
                    database_generation="2",
                    migrate_postgres=postgres_flag,
                    migrate_database=database_flag,
                )
                self.assertNotEqual(refused.returncode, 0)

    def test_pending_before_seal_requires_pending_database_identity_and_both_flags(self):
        state = f"{STORAGE_GENERATION}-pending-upgrade"
        result, _ = self.run_configure(
            state=state,
            intent=GENERATION2_INTENT,
            witness=self.witness(),
            database_generation="3-pending-upgrade",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        for generation in ("", "3-pending-fresh", "unexpected"):
            with self.subTest(generation=generation):
                refused, _ = self.run_configure(
                    state=state,
                    intent=GENERATION2_INTENT,
                    witness=self.witness(),
                    database_generation=generation,
                )
                self.assertNotEqual(refused.returncode, 0)

    def test_generation2_and_generation3_select_distinct_witnessed_paths(self):
        for generation, database_flag, expected_intent in (
            ("2", True, GENERATION2_INTENT),
            ("3", False, STRICT_INTENT),
        ):
            with self.subTest(generation=generation):
                result, events = self.run_configure(
                    database_generation=generation,
                    migrate_database=database_flag,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    f"SET:BACKUPSHEEP_POSTGRES_STORAGE_INTENT={expected_intent}",
                    events,
                )

                refused, _ = self.run_configure(
                    database_generation=generation,
                    migrate_database=not database_flag,
                )
                self.assertNotEqual(refused.returncode, 0)

        ambiguous, _ = self.run_configure(database_generation="3-pending-upgrade")
        self.assertNotEqual(ambiguous.returncode, 0)
        self.assertIn("source generation is ambiguous", ambiguous.stderr)

    def test_strict_pending_path_accepts_only_completed_generation3(self):
        state = f"{STORAGE_GENERATION}-pending-upgrade"
        accepted, _ = self.run_configure(
            state=state,
            intent=STRICT_INTENT,
            witness=self.witness(STRICT_INTENT),
            database_generation="3",
            migrate_database=False,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

        for generation in ("2", "3-pending-upgrade", ""):
            with self.subTest(generation=generation):
                refused, _ = self.run_configure(
                    state=state,
                    intent=STRICT_INTENT,
                    witness=self.witness(STRICT_INTENT),
                    database_generation=generation,
                    migrate_database=True,
                )
                self.assertNotEqual(refused.returncode, 0)

    def test_late_crash_reconciles_only_existing_target_without_database_flag(self):
        state = f"{STORAGE_GENERATION}-pending-upgrade"
        result, _ = self.run_configure(
            state=state,
            intent=GENERATION2_INTENT,
            witness=self.witness(),
            database_generation="3",
            migrate_database=False,
            active_volume=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MIGRATION_REQUIRED=true", result.stdout)

        for active_volume, database_flag in ((False, False), (True, True)):
            with self.subTest(active=active_volume, database_flag=database_flag):
                refused, _ = self.run_configure(
                    state=state,
                    intent=GENERATION2_INTENT,
                    witness=self.witness(),
                    database_generation="3",
                    migrate_database=database_flag,
                    active_volume=active_volume,
                )
                self.assertNotEqual(refused.returncode, 0)

    def test_stale_or_replayed_storage_witness_is_refused(self):
        result, _ = self.run_configure(
            state=f"{STORAGE_GENERATION}-pending-upgrade",
            intent=GENERATION2_INTENT,
            witness="0" * 64,
            database_generation="3-pending-upgrade",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match this installation", result.stderr)

    def test_runtime_migration_argument_assembly_is_set_u_safe_and_complete(self):
        with tempfile.TemporaryDirectory(prefix="postgres-argument-assembly-") as temp_dir:
            install_dir = Path(temp_dir)
            migration_dir = install_dir / "deploy" / "postgres"
            migration_dir.mkdir(parents=True)
            argument_log = install_dir / "arguments"
            fake_migrator = migration_dir / "migrate-runtime.sh"
            fake_migrator.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGUMENT_LOG\"\n",
                encoding="utf-8",
            )
            fake_migrator.chmod(0o700)
            secret_dir = install_dir / ".secrets"
            secret_dir.mkdir()

            command = r'''
source "$1"
PROJECT_NAME=backupsheep
POSTGRES_MIGRATION_REQUIRED=true
DOCKER_BIN=mock_docker
INSTALL_DIR="$TEST_INSTALL_DIR"
SECRETS_DIR="$INSTALL_DIR/.secrets"
read_env_value() {
    case "$1" in
        BACKUPSHEEP_INSTALLATION_ID) printf '%s' "$INSTALLATION_VALUE" ;;
        BACKUPSHEEP_POSTGRES_RETIRED_IMAGE_ID) printf '%s' "$SOURCE_IMAGE" ;;
        BACKUPSHEEP_POSTGRES_IMAGE) printf '%s' backupsheep-postgres:test ;;
        DB_NAME) printf '%s' backupsheep ;;
        DB_BOOTSTRAP_USER) printf '%s' backupsheep ;;
        DB_MIGRATOR_USER) printf '%s' backupsheep_migrator ;;
        DB_APP_USER) printf '%s' backupsheep_app ;;
        DB_PREFLIGHT_USER) printf '%s' backupsheep_preflight ;;
        DB_BEAT_USER) printf '%s' backupsheep_beat ;;
        DB_CLOUD_USER) printf '%s' backupsheep_cloud ;;
        DB_DATABASE_USER) printf '%s' backupsheep_database ;;
        DB_FILES_USER) printf '%s' backupsheep_files ;;
        DB_STORAGE_USER) printf '%s' backupsheep_storage ;;
        DB_LOGS_USER) printf '%s' backupsheep_logs ;;
        BACKUPSHEEP_POSTGRES_STORAGE_WITNESS) printf '%s' "$WITNESS_VALUE" ;;
        BACKUPSHEEP_POSTGRES_STORAGE_INTENT) printf '%s' "$INTENT_VALUE" ;;
        BACKUPSHEEP_DATABASE_IDENTITY_GENERATION) printf '%s' "$DATABASE_GENERATION" ;;
        *) return 0 ;;
    esac
}
mock_docker() { [[ "$1" == ps ]] && return 0; return 90; }
validate_compose_project_ownership() { printf 'ownership-validated\n' >> "$ARGUMENT_LOG"; }
log() { :; }
run_postgres_runtime_migration
printf 'MIGRATION_REQUIRED=%s\n' "$POSTGRES_MIGRATION_REQUIRED"
'''
            env = os.environ.copy()
            env.update(
                TEST_INSTALL_DIR=str(install_dir),
                ARGUMENT_LOG=str(argument_log),
                INSTALLATION_VALUE=INSTALLATION_ID,
                SOURCE_IMAGE=SOURCE_IMAGE_ID,
                WITNESS_VALUE=self.witness(),
                INTENT_VALUE=GENERATION2_INTENT,
                DATABASE_GENERATION="3-pending-upgrade",
            )
            result = subprocess.run(
                ["/bin/bash", "-c", command, "argument-test", str(INSTALLER)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "MIGRATION_REQUIRED=false\n")
            arguments = argument_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(arguments), 15)
            self.assertEqual(arguments[0], "mock_docker")
            self.assertEqual(arguments[1], "backupsheep")
            self.assertEqual(arguments[12], GENERATION2_INTENT)
            self.assertEqual(arguments[13], "3-pending-upgrade")
            self.assertEqual(arguments[14], "ownership-validated")

    def test_storage_promotion_requires_sealed_database_and_exact_receipt_verifier(self):
        command = r'''
source "$1"
POSTGRES_MIGRATION_REQUIRED="$MIGRATION_REQUIRED"
DOCKER_BIN=mock_docker
read_env_value() {
    case "$1" in
        BACKUPSHEEP_POSTGRES_STORAGE_GENERATION) printf '%s' '18-alpine-icu-v1-pending-upgrade' ;;
        BACKUPSHEEP_DATABASE_IDENTITY_GENERATION) printf '%s' "$DATABASE_GENERATION" ;;
        BACKUPSHEEP_POSTGRES_IMAGE) printf '%s' backupsheep-postgres:test ;;
        *) return 0 ;;
    esac
}
compose() {
    [[ "$1" == ps && "$2" == --all && "$3" == --quiet && "$4" == db ]] || return 90
    printf '%s\n' database-container
}
mock_docker() {
    if [[ "$1:$2:$3" == image:inspect:--format ]]; then
        printf '%s\n' "$TARGET_IMAGE"
        return 0
    fi
    if [[ "$1:$2" == inspect:--format ]]; then
        printf '%s\n' "$TARGET_IMAGE"
        return 0
    fi
    if [[ "$1" == exec ]]; then
        {
            printf 'EXEC:'
            printf '%s|' "$@"
            printf '\n'
        } >> "$EVENT_LOG"
        return 0
    fi
    return 91
}
set_env_value() { printf 'SET:%s=%s\n' "$1" "$2" >> "$EVENT_LOG"; }
complete_postgres_storage_generation
'''
        for database_generation, migration_required, succeeds in (
            ("3", "false", True),
            ("3-pending-upgrade", "false", False),
            ("3", "true", False),
        ):
            with self.subTest(
                database_generation=database_generation,
                migration_required=migration_required,
            ), tempfile.TemporaryDirectory(prefix="postgres-promotion-") as temp_dir:
                event_log = Path(temp_dir) / "events"
                env = os.environ.copy()
                env.update(
                    DATABASE_GENERATION=database_generation,
                    MIGRATION_REQUIRED=migration_required,
                    TARGET_IMAGE=TARGET_IMAGE_ID,
                    EVENT_LOG=str(event_log),
                )
                result = subprocess.run(
                    ["/bin/bash", "-c", command, "promotion-test", str(INSTALLER)],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                )
                events = (
                    event_log.read_text(encoding="utf-8")
                    if event_log.exists()
                    else ""
                )
                if succeeds:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(
                        "EXEC:exec|database-container|"
                        "/usr/local/bin/backupsheep-postgres-storage-witness|"
                        "verify-migration|",
                        events,
                    )
                    self.assertIn(
                        "SET:BACKUPSHEEP_POSTGRES_STORAGE_GENERATION="
                        f"{STORAGE_GENERATION}",
                        events,
                    )
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("SET:BACKUPSHEEP_POSTGRES_STORAGE_GENERATION", events)
