"""Safety-first Hetzner Cloud fixture for BackupSheep UI testing.

This harness creates exactly one labelled SSH key and one labelled Hetzner
Cloud server. The server's cloud-init payload installs nginx, MariaDB, and
PostgreSQL, then creates deterministic website and database fixtures for
manual BackupSheep UI configuration. The databases listen on loopback so
BackupSheep can reach them through an SSH tunnel made with the non-root
"backupsheep" user.

The command is read-only unless BACKUPSHEEP_E2E_APPLY=YES is present. Cleanup
is independently gated by BACKUPSHEEP_E2E_CLEANUP=YES and also requires
BACKUPSHEEP_E2E_APPLY=YES because cleanup is a provider write. Create runs
deliberately leave their resources in place for UI testing. A later cleanup
invocation rehydrates exact IDs from the durable ledger and deletes only those
IDs after a fresh ownership read-back.

Required environment variables:

    HCLOUD_TOKEN
    BACKUPSHEEP_E2E_RUN_ID
    BACKUPSHEEP_E2E_LEDGER_PATH

Apply-only additions:

    HETZNER_E2E_SSH_PUBLIC_KEY or HETZNER_E2E_SSH_PRIVATE_KEY_PATH
    HETZNER_E2E_MARIADB_DATABASE
    HETZNER_E2E_MARIADB_USERNAME
    HETZNER_E2E_MARIADB_PASSWORD
    HETZNER_E2E_POSTGRES_DATABASE
    HETZNER_E2E_POSTGRES_USERNAME
    HETZNER_E2E_POSTGRES_PASSWORD

The database values are process inputs only. Passwords are carried to the
server only in the provider's cloud-init payload, encoded in a root-readable
temporary secret file. They are never included in the JSON report, durable
ledger, ownership witnesses, request errors, or readiness marker.

Useful configurable defaults:

    HETZNER_E2E_API=https://api.hetzner.cloud
    HETZNER_E2E_SERVER_TYPE=cx23
    HETZNER_E2E_LOCATION=fsn1
    HETZNER_E2E_IMAGE=ubuntu-24.04
    HETZNER_E2E_POLL_SECONDS=5
    HETZNER_E2E_TIMEOUT_SECONDS=900
    HETZNER_E2E_HTTP_TIMEOUT_SECONDS=10

No live provider mutation is performed by this module's tests.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.live_e2e_ledger import (  # noqa: E402
    DurableMutationIntentStore,
    DurableResourceLedger,
    LedgerError,
    bounded_error,
    provider_error_class,
    require_run_id,
)


SSH_USER = "backupsheep"
READINESS_PATH = "/backupsheep-e2e-readiness.json"
SSH_READINESS_PATH = "/var/lib/backupsheep-e2e/readiness.json"
RUN_LABEL = "backupsheep.com/e2e-run"
ROLE_LABEL = "backupsheep.com/e2e-role"
SOURCE_LABEL = "backupsheep.com/e2e-source"
KEY_ROLE = "ssh-key"
SERVER_ROLE = "server"

MARIADB_ENV = (
    "HETZNER_E2E_MARIADB_DATABASE",
    "HETZNER_E2E_MARIADB_USERNAME",
    "HETZNER_E2E_MARIADB_PASSWORD",
)
POSTGRES_ENV = (
    "HETZNER_E2E_POSTGRES_DATABASE",
    "HETZNER_E2E_POSTGRES_USERNAME",
    "HETZNER_E2E_POSTGRES_PASSWORD",
)
PASSWORD_ENV_NAMES = {
    "HETZNER_E2E_MARIADB_PASSWORD",
    "HETZNER_E2E_POSTGRES_PASSWORD",
}
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
PROVIDER_ID_RE = re.compile(r"^[0-9]+$")
PUBLIC_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}
MAX_PROVIDER_PAGES = 1000
MAX_PROVIDER_ITEMS = 10000


class HarnessError(RuntimeError):
    """A live harness invariant failed closed."""


class AmbiguousMutation(HarnessError):
    """A provider mutation may have succeeded but its response was lost."""

    provider_code = "PROVIDER_AMBIGUOUS"


class ProviderHTTPError(HarnessError):
    """A bounded, classified Hetzner HTTP failure."""

    def __init__(self, code, message):
        self.provider_code = str(code)
        super().__init__(message)


def _redact(value, secrets):
    text = bounded_error(value, secrets)
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "<redacted>")
    return text


def _bounded_int(name, default, minimum, maximum):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise HarnessError(f"{name} must be an integer") from error
    return max(minimum, min(value, maximum))


def _api_host():
    configured = os.environ.get("HETZNER_E2E_API", "https://api.hetzner.cloud")
    try:
        parsed = urlsplit(configured)
        port = parsed.port
    except (TypeError, ValueError) as error:
        raise HarnessError(
            "HETZNER_E2E_API must be exactly https://api.hetzner.cloud"
        ) from error
    if (
        configured != "https://api.hetzner.cloud"
        or parsed.scheme != "https"
        or parsed.netloc != "api.hetzner.cloud"
        or parsed.hostname != "api.hetzner.cloud"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise HarnessError(
            "HETZNER_E2E_API must be exactly https://api.hetzner.cloud"
        )
    return configured


def _normalize_public_key(value):
    key = str(value or "").strip()
    if not key or "\n" in key or "\r" in key or "\x00" in key:
        raise HarnessError("The SSH public key must be one non-empty OpenSSH line")
    fields = key.split()
    if len(fields) < 2 or fields[0] not in PUBLIC_KEY_TYPES:
        raise HarnessError("The SSH public key format is not supported")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (ValueError, TypeError) as error:
        raise HarnessError("The SSH public key payload is not valid base64") from error
    if len(decoded) < 16:
        raise HarnessError("The SSH public key payload is unexpectedly short")
    return " ".join(fields)


def _derive_public_key(private_key_path):
    path = Path(str(private_key_path)).expanduser()
    if not path.is_file():
        raise HarnessError("HETZNER_E2E_SSH_PRIVATE_KEY_PATH is not a readable file")
    try:
        completed = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessError("Unable to derive the SSH public key from the private key path") from error
    if completed.returncode != 0:
        raise HarnessError("Unable to derive the SSH public key from the private key path")
    return _normalize_public_key(completed.stdout)


def _load_public_key():
    supplied = os.environ.get("HETZNER_E2E_SSH_PUBLIC_KEY")
    private_path = os.environ.get("HETZNER_E2E_SSH_PRIVATE_KEY_PATH")
    if supplied:
        public_key = _normalize_public_key(supplied)
        if private_path and _derive_public_key(private_path) != public_key:
            raise HarnessError(
                "HETZNER_E2E_SSH_PUBLIC_KEY does not match the configured private key"
            )
        return public_key
    if private_path:
        return _derive_public_key(private_path)
    raise HarnessError(
        "Apply requires HETZNER_E2E_SSH_PUBLIC_KEY or "
        "HETZNER_E2E_SSH_PRIVATE_KEY_PATH"
    )


def _validate_identifier(name, value):
    if not IDENTIFIER_RE.fullmatch(value or ""):
        raise HarnessError(
            f"{name} must match {IDENTIFIER_RE.pattern} for safe deterministic fixtures"
        )
    return value


def _fixture_inputs_from_environment():
    missing = [
        name
        for name in MARIADB_ENV + POSTGRES_ENV
        if not os.environ.get(name)
    ]
    if missing:
        raise HarnessError(
            "Apply requires explicit database environment inputs: "
            + ", ".join(missing)
        )
    values = {name: os.environ[name] for name in MARIADB_ENV + POSTGRES_ENV}
    for name in PASSWORD_ENV_NAMES:
        password = values[name]
        if len(password) > 256 or any(character in password for character in "\x00\r\n"):
            raise HarnessError(f"{name} contains unsupported control characters or is too long")
    return {
        "mariadb": {
            "database": _validate_identifier(MARIADB_ENV[0], values[MARIADB_ENV[0]]),
            "username": _validate_identifier(MARIADB_ENV[1], values[MARIADB_ENV[1]]),
            "password": values[MARIADB_ENV[2]],
        },
        "postgresql": {
            "database": _validate_identifier(POSTGRES_ENV[0], values[POSTGRES_ENV[0]]),
            "username": _validate_identifier(POSTGRES_ENV[1], values[POSTGRES_ENV[1]]),
            "password": values[POSTGRES_ENV[2]],
        },
    }


def _bounded_name(run_id, suffix):
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:10]
    tail = f"-{digest}-{suffix}"
    return f"{run_id[:63 - len(tail)]}{tail}"


def _b64(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _bootstrap_script():
    """Return a password-free Python bootstrap program for cloud-init."""
    return r'''#!/usr/bin/env python3
import json
import os
import pathlib
import pwd
import subprocess


CONFIG_PATH = "/var/lib/backupsheep-e2e/config.json"
SECRETS_PATH = "/run/backupsheep-e2e/secrets.json"
READY_PATH = "/var/lib/backupsheep-e2e/readiness.json"
WEB_ROOT = pathlib.Path("/var/www/html")
SSH_USER = "backupsheep"


def sql_literal(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def sql_identifier(value, quote):
    return quote + str(value).replace(quote, quote + quote) + quote


def run(command, *, input_text=None, user=None):
    if user:
        command = ["runuser", "-u", user, "--"] + list(command)
    subprocess.run(
        command,
        check=True,
        input=input_text,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=300,
    )


def read_json(path):
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def write_json(path, payload, mode=0o644):
    temporary = pathlib.Path(str(path) + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(temporary, mode)
    os.replace(temporary, path)


config = read_json(CONFIG_PATH)
secrets = read_json(SECRETS_PATH)
run_id = config["run_id"]
mariadb = secrets["mariadb"]
postgresql = secrets["postgresql"]

try:
    subprocess.run(
        [
            "useradd",
            "--create-home",
            "--shell",
            "/bin/bash",
            "--user-group",
            "backupsheep",
        ],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
except Exception:
    raise SystemExit("fixture user setup failed")

ssh_dir = pathlib.Path("/home/backupsheep/.ssh")
ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
authorized_keys = ssh_dir / "authorized_keys"
authorized_keys.write_text(config["ssh_public_key"] + "\n", encoding="utf-8")
os.chmod(authorized_keys, 0o600)
run(["chown", "-R", "backupsheep:backupsheep", str(ssh_dir)])

pathlib.Path("/var/lib/backupsheep-e2e").mkdir(mode=0o755, parents=True, exist_ok=True)
pathlib.Path("/run/backupsheep-e2e").mkdir(mode=0o700, parents=True, exist_ok=True)

pathlib.Path("/etc/mysql/mariadb.conf.d/60-backupsheep-e2e.cnf").write_text(
    "[mysqld]\nbind-address=127.0.0.1\n",
    encoding="utf-8",
)
run(["systemctl", "enable", "--now", "mariadb"])
run(["systemctl", "restart", "mariadb"])

maria_db = sql_identifier(mariadb["database"], chr(96))
maria_user = sql_literal(mariadb["username"])
maria_password = sql_literal(mariadb["password"])
maria_rows = []
for index in range(1, 21):
    maria_rows.append(
        "(%d, %s, %s)"
        % (
            index,
            sql_literal("%s-customer-%02d" % (run_id, index)),
            sql_literal("customer-%02d@example.invalid" % index),
        )
    )
maria_orders = []
for index in range(1, 41):
    maria_orders.append(
        "(%d, %d, %s, %d)"
        % (
            index,
            ((index - 1) % 20) + 1,
            sql_literal("%s-order-%02d" % (run_id, index)),
            index * 17,
        )
    )
maria_sql = """
CREATE DATABASE IF NOT EXISTS %s;
CREATE USER IF NOT EXISTS %s@'127.0.0.1' IDENTIFIED BY %s;
ALTER USER %s@'127.0.0.1' IDENTIFIED BY %s;
CREATE USER IF NOT EXISTS %s@'localhost' IDENTIFIED BY %s;
ALTER USER %s@'localhost' IDENTIFIED BY %s;
GRANT ALL PRIVILEGES ON %s.* TO %s@'127.0.0.1';
GRANT ALL PRIVILEGES ON %s.* TO %s@'localhost';
FLUSH PRIVILEGES;
USE %s;
CREATE TABLE IF NOT EXISTS fixture_metadata (fixture_key VARCHAR(128) PRIMARY KEY, fixture_value VARCHAR(255) NOT NULL);
CREATE TABLE IF NOT EXISTS customers (id INT PRIMARY KEY, display_name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS orders (id INT PRIMARY KEY, customer_id INT NOT NULL, order_ref VARCHAR(255) NOT NULL UNIQUE, amount_cents INT NOT NULL);
DELETE FROM fixture_metadata;
INSERT INTO fixture_metadata (fixture_key, fixture_value) VALUES ('run_id', %s), ('dataset', 'mariadb-v1');
INSERT INTO customers (id, display_name, email) VALUES %s ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), email=VALUES(email);
INSERT INTO orders (id, customer_id, order_ref, amount_cents) VALUES %s ON DUPLICATE KEY UPDATE customer_id=VALUES(customer_id), order_ref=VALUES(order_ref), amount_cents=VALUES(amount_cents);
""" % (
    maria_db,
    maria_user,
    maria_password,
    maria_user,
    maria_password,
    maria_user,
    maria_password,
    maria_user,
    maria_password,
    maria_db,
    maria_user,
    maria_db,
    maria_user,
    maria_db,
    sql_literal(run_id),
    ",".join(maria_rows),
    ",".join(maria_orders),
)
run(
    ["mariadb", "--protocol=socket", "--batch", "--skip-column-names"],
    input_text=maria_sql,
)

run(["systemctl", "enable", "--now", "postgresql"])
run(
    [
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "--set",
        "ON_ERROR_STOP=1",
        "-c",
        "ALTER SYSTEM SET listen_addresses = '127.0.0.1';",
    ]
)
run(["systemctl", "restart", "postgresql"])

pg_db = sql_identifier(postgresql["database"], '"')
pg_user = sql_identifier(postgresql["username"], '"')
pg_user_literal = sql_literal(postgresql["username"])
pg_password = sql_literal(postgresql["password"])
pg_rows = []
for index in range(1, 21):
    pg_rows.append(
        "(%d, %s, %s)"
        % (
            index,
            sql_literal("%s-customer-%02d" % (run_id, index)),
            sql_literal("customer-%02d@example.invalid" % index),
        )
    )
pg_orders = []
for index in range(1, 41):
    pg_orders.append(
        "(%d, %d, %s, %d)"
        % (
            index,
            ((index - 1) % 20) + 1,
            sql_literal("%s-order-%02d" % (run_id, index)),
            index * 17,
        )
    )
pg_sql = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN
        EXECUTE 'CREATE ROLE %s LOGIN';
    END IF;
END
$$;
ALTER ROLE %s LOGIN PASSWORD %s;
SELECT 'CREATE DATABASE %s OWNER %s' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = %s)\\gexec
\\connect %s
CREATE TABLE IF NOT EXISTS fixture_metadata (fixture_key VARCHAR(128) PRIMARY KEY, fixture_value VARCHAR(255) NOT NULL);
CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY, display_name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL, order_ref VARCHAR(255) NOT NULL UNIQUE, amount_cents INTEGER NOT NULL);
DELETE FROM fixture_metadata;
INSERT INTO fixture_metadata (fixture_key, fixture_value) VALUES ('run_id', %s), ('dataset', 'postgresql-v1') ON CONFLICT (fixture_key) DO UPDATE SET fixture_value=EXCLUDED.fixture_value;
INSERT INTO customers (id, display_name, email) VALUES %s ON CONFLICT (id) DO UPDATE SET display_name=EXCLUDED.display_name, email=EXCLUDED.email;
INSERT INTO orders (id, customer_id, order_ref, amount_cents) VALUES %s ON CONFLICT (id) DO UPDATE SET customer_id=EXCLUDED.customer_id, order_ref=EXCLUDED.order_ref, amount_cents=EXCLUDED.amount_cents;
ALTER TABLE fixture_metadata OWNER TO %s;
ALTER TABLE customers OWNER TO %s;
ALTER TABLE orders OWNER TO %s;
""" % (
    pg_user_literal,
    pg_user,
    pg_user,
    pg_password,
    pg_db,
    pg_user,
    sql_literal(postgresql["database"]),
    pg_db,
    sql_literal(run_id),
    ",".join(pg_rows),
    ",".join(pg_orders),
    pg_user,
    pg_user,
    pg_user,
)
run(["psql", "--set", "ON_ERROR_STOP=1", "-f", "-"], input_text=pg_sql, user="postgres")

website_root = WEB_ROOT / "backupsheep-e2e"
(website_root / "data").mkdir(mode=0o755, parents=True, exist_ok=True)
website_marker = "%s:website-fixture-v1" % run_id
(website_root / "index.html").write_text(
    "<!doctype html><html><head><title>BackupSheep fixture</title></head>"
    "<body><h1>%s</h1><p>Deterministic website backup fixture.</p></body></html>\n"
    % website_marker,
    encoding="utf-8",
)
(website_root / "data" / "alpha.txt").write_text(
    "%s:website-alpha\n" % run_id,
    encoding="utf-8",
)
(website_root / "data" / "beta.txt").write_text(
    "%s:website-beta\n" % run_id,
    encoding="utf-8",
)
(website_root / "manifest.json").write_text(
    json.dumps(
        {
            "schema": 1,
            "run_id": run_id,
            "files": ["index.html", "data/alpha.txt", "data/beta.txt"],
            "marker": website_marker,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)

user_record = pwd.getpwnam(SSH_USER)
if user_record.pw_uid == 0:
    raise SystemExit("fixture SSH user unexpectedly has root UID")

readiness = {
    "schema": 1,
    "ready": True,
    "run_id": run_id,
    "ssh": {"user": SSH_USER, "port": 22, "non_root": True},
    "website": {
        "marker": website_marker,
        "path": "/var/www/html/backupsheep-e2e/",
        "readiness_path": READY_PATH,
    },
    "databases": {
        "mariadb": {
            "host": "127.0.0.1",
            "port": 3306,
            "ssh_tunnel_required": True,
            "tables": {"fixture_metadata": 2, "customers": 20, "orders": 40},
        },
        "postgresql": {
            "host": "127.0.0.1",
            "port": 5432,
            "ssh_tunnel_required": True,
            "tables": {"fixture_metadata": 2, "customers": 20, "orders": 40},
        },
    },
}
write_json(READY_PATH, readiness)
write_json(WEB_ROOT / "backupsheep-e2e-readiness.json", readiness)
os.chmod(READY_PATH, 0o644)
os.chmod(WEB_ROOT / "backupsheep-e2e-readiness.json", 0o644)
run(["systemctl", "enable", "--now", "nginx"])
try:
    pathlib.Path(SECRETS_PATH).unlink()
except FileNotFoundError:
    pass
'''


def build_cloud_init(run_id, public_key, fixture_inputs):
    """Build cloud-init without placing plaintext passwords in the payload."""
    config = {
        "schema": 1,
        "run_id": run_id,
        "ssh_public_key": public_key,
    }
    secret_payload = {
        "mariadb": fixture_inputs["mariadb"],
        "postgresql": fixture_inputs["postgresql"],
    }
    return "\n".join(
        (
            "#cloud-config",
            "package_update: true",
            "package_upgrade: false",
            "packages:",
            "  - nginx",
            "  - mariadb-server",
            "  - postgresql",
            "  - python3",
            "write_files:",
            "  - path: /var/lib/backupsheep-e2e/config.json",
            "    owner: root:root",
            "    permissions: '0600'",
            "    encoding: b64",
            f"    content: {_b64(json.dumps(config, sort_keys=True))}",
            "  - path: /run/backupsheep-e2e/secrets.json",
            "    owner: root:root",
            "    permissions: '0600'",
            "    encoding: b64",
            f"    content: {_b64(json.dumps(secret_payload, sort_keys=True))}",
            "  - path: /root/backupsheep-e2e-bootstrap.py",
            "    owner: root:root",
            "    permissions: '0700'",
            "    encoding: b64",
            f"    content: {_b64(_bootstrap_script())}",
            "runcmd:",
            "  - [python3, /root/backupsheep-e2e-bootstrap.py]",
            "",
        )
    )


class HetznerFixtureHarness:
    """One-run Hetzner fixture lifecycle with ledger-gated cleanup."""

    def __init__(self, token):
        self.token = str(token or "")
        if not self.token:
            raise HarnessError("HCLOUD_TOKEN is required")
        self.api = f"{_api_host()}/v1"
        self.http_timeout = (
            _bounded_int("HETZNER_E2E_CONNECT_TIMEOUT_SECONDS", 10, 1, 30),
            _bounded_int("HETZNER_E2E_HTTP_TIMEOUT_SECONDS", 10, 1, 120),
        )
        self.poll_seconds = _bounded_int("HETZNER_E2E_POLL_SECONDS", 5, 1, 60)
        self.timeout_seconds = _bounded_int(
            "HETZNER_E2E_TIMEOUT_SECONDS", 900, 30, 3600
        )
        self.apply = os.environ.get("BACKUPSHEEP_E2E_APPLY") == "YES"
        self.cleanup_requested = os.environ.get("BACKUPSHEEP_E2E_CLEANUP") == "YES"
        self.run_id = require_run_id(os.environ.get("BACKUPSHEEP_E2E_RUN_ID"))
        ledger_path = os.environ.get("BACKUPSHEEP_E2E_LEDGER_PATH")
        if not ledger_path:
            raise LedgerError("BACKUPSHEEP_E2E_LEDGER_PATH is required")
        self.server_type = os.environ.get("HETZNER_E2E_SERVER_TYPE", "cx23")
        self.location = os.environ.get("HETZNER_E2E_LOCATION", "fsn1")
        self.image = os.environ.get("HETZNER_E2E_IMAGE", "ubuntu-24.04")
        self.ssh_key_name = _bounded_name(self.run_id, "ssh-key")
        self.server_name = _bounded_name(self.run_id, "server")
        scope = f"{self.api}:{hashlib.sha256(self.token.encode()).hexdigest()[:16]}"
        self.ledger = DurableResourceLedger(
            ledger_path,
            provider="hetzner_cloud_fixture",
            run_id=self.run_id,
            scope=scope,
        )
        self.intents = DurableMutationIntentStore(
            ledger_path,
            provider="hetzner_cloud_fixture",
            run_id=self.run_id,
            scope=scope,
            suffix=".fixture-intents.json",
        )
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        )
        self.active = {"ssh_key": None, "server": None}
        self.public_key = None
        self.fixture_inputs = None
        self._secrets = [self.token]
        self.report = {
            "status": "NOT_RUN",
            "mode": "cleanup_only" if self.cleanup_requested else "read_only",
            "run_id": self.run_id,
            "provider": "hetzner_cloud",
            "server_type": self.server_type,
            "location": self.location,
            "image": self.image,
            "resource_names": {
                "ssh_key": self.ssh_key_name,
                "server": self.server_name,
            },
            "tests": {},
            "cleanup": {"status": "NOT_REQUESTED", "errors": [], "considered": []},
        }
        self._hydrate_active_ledger()

    @property
    def labels_for_key(self):
        return {RUN_LABEL: self.run_id, ROLE_LABEL: KEY_ROLE, SOURCE_LABEL: "fixture"}

    def labels_for_server(self, ssh_key_id):
        return {
            RUN_LABEL: self.run_id,
            ROLE_LABEL: SERVER_ROLE,
            SOURCE_LABEL: str(ssh_key_id),
        }

    def _safe_error(self, error):
        return f"{provider_error_class(error)}: {_redact(error, self._secrets)}"

    def _preflight_cleanup(self):
        if self.cleanup_requested and not self.apply:
            raise HarnessError(
                "Cleanup is a provider write and requires both "
                "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES"
            )

    def request(
        self,
        method,
        path,
        *,
        expected=(200,),
        allow_404=False,
        mutation=False,
        **kwargs,
    ):
        """Make exactly one request; a lost mutation response is never retried."""
        try:
            response = self.session.request(
                method,
                f"{self.api}{path}",
                timeout=self.http_timeout,
                **kwargs,
            )
        except requests.RequestException as error:
            detail = self._safe_error(error)
            if mutation:
                raise AmbiguousMutation(
                    f"Hetzner {method} {path} response was lost; no mutation retry was issued: {detail}"
                ) from error
            raise ProviderHTTPError(
                "PROVIDER_TIMEOUT"
                if isinstance(error, requests.Timeout)
                else "PROVIDER_TRANSIENT_OUTAGE",
                f"Hetzner {method} {path} request failed: {detail}",
            ) from error
        if response.status_code == 404 and allow_404:
            return None
        if response.status_code not in expected:
            try:
                detail = response.json().get("error", {}).get("message", "")
            except (TypeError, ValueError):
                detail = ""
            detail = _redact(detail, self._secrets)
            suffix = f": {detail}" if detail else ""
            if response.status_code in {401, 403}:
                code = "PROVIDER_AUTH_FAILED"
            elif response.status_code == 429:
                code = "PROVIDER_RATE_LIMIT"
            elif response.status_code >= 500:
                code = "PROVIDER_TRANSIENT_OUTAGE"
            else:
                code = "PROVIDER_PERMANENT"
            raise ProviderHTTPError(
                code,
                f"Hetzner {method} {path} returned HTTP {response.status_code}{suffix}",
            )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as error:
            raise HarnessError(
                f"Hetzner {method} {path} returned non-JSON content"
            ) from error

    def collection(self, resource, params=None):
        """Read a bounded page collection with a repeated-page guard."""
        values = []
        page = 1
        seen_pages = set()
        base = dict(params or {})
        for _ in range(MAX_PROVIDER_PAGES):
            if page in seen_pages:
                raise HarnessError(f"Hetzner returned a repeated {resource} pagination page")
            seen_pages.add(page)
            payload = self.request(
                "GET",
                f"/{resource}",
                params={**base, "page": page, "per_page": 50},
            )
            page_values = payload.get(resource)
            if not isinstance(page_values, list):
                raise HarnessError(f"Hetzner returned a malformed {resource} page")
            values.extend(page_values)
            if len(values) > MAX_PROVIDER_ITEMS:
                raise HarnessError(f"Hetzner {resource} pagination exceeded the bounded item limit")
            meta = payload.get("meta")
            pagination = meta.get("pagination") if isinstance(meta, dict) else None
            if not isinstance(pagination, dict):
                if len(page_values) >= 50:
                    raise HarnessError(
                        f"Hetzner returned a full {resource} page without pagination metadata"
                    )
                return values
            next_page = pagination.get("next_page")
            if next_page in (None, "", 0):
                if len(page_values) >= 50:
                    raise HarnessError(
                        f"Hetzner returned a full {resource} page without a terminal pagination witness"
                    )
                return values
            try:
                next_page = int(next_page)
            except (TypeError, ValueError) as error:
                raise HarnessError(f"Hetzner returned an invalid {resource} page") from error
            if next_page <= page:
                raise HarnessError(f"Hetzner returned a non-progressing {resource} page")
            if next_page < 1:
                raise HarnessError(f"Hetzner returned an invalid {resource} page")
            page = next_page
        raise HarnessError(f"Hetzner {resource} pagination exceeded the bounded page limit")

    @staticmethod
    def _resource_key(kind):
        return {"ssh_key": ("ssh_keys", "ssh_key"), "server": ("servers", "server")}[kind]

    def _get_resource_once(self, kind, resource_id):
        resource, result_key = self._resource_key(kind)
        if not PROVIDER_ID_RE.fullmatch(str(resource_id or "")):
            raise HarnessError(f"Invalid provider ID for {kind}")
        payload = self.request(
            "GET",
            f"/{resource}/{resource_id}",
            allow_404=True,
        )
        return None if payload is None else payload.get(result_key)

    def _hydrate_active_ledger(self):
        """Adopt only exact IDs already durably recorded before a crash."""
        expected_names = {"ssh_key": self.ssh_key_name, "server": self.server_name}
        for entry in self.ledger.entries():
            kind = str(entry.get("kind") or "")
            if kind not in expected_names:
                raise HarnessError(
                    "The fixture ledger contains a resource kind outside this harness"
                )
            identifier = str(entry.get("resource_id") or "")
            if not PROVIDER_ID_RE.fullmatch(identifier):
                raise HarnessError("The fixture ledger contains an invalid provider ID")
            if entry.get("name") != expected_names[kind]:
                raise HarnessError("The fixture ledger contains an unexpected resource name")
            ownership = entry.get("ownership") or {}
            labels = ownership.get("labels") or {}
            if labels.get(RUN_LABEL) != self.run_id:
                raise HarnessError("The fixture ledger run label witness does not match")
            expected_role = KEY_ROLE if kind == "ssh_key" else SERVER_ROLE
            if labels.get(ROLE_LABEL) != expected_role:
                raise HarnessError("The fixture ledger role label witness does not match")
            if self.ledger.cleanup_eligible(kind, identifier):
                if self.active[kind] and self.active[kind] != identifier:
                    raise HarnessError(f"The fixture ledger contains duplicate active {kind} IDs")
                self.active[kind] = identifier

        server_id = self.active.get("server")
        key_id = self.active.get("ssh_key")
        if server_id and not key_id:
            raise HarnessError(
                "The fixture server ledger entry has no active SSH key source witness"
            )
        if server_id and key_id:
            server_entry = self.ledger.get("server", server_id) or {}
            if (server_entry.get("source_witness") or "") != f"ssh-key:{key_id}":
                raise HarnessError("The fixture server source witness does not match its SSH key")
            labels = (server_entry.get("ownership") or {}).get("labels") or {}
            if labels.get(SOURCE_LABEL) != str(key_id):
                raise HarnessError("The fixture server source label does not match its SSH key")

    def baseline(self):
        """Detect only this run's labelled collisions; never mutate inventory."""
        selector = f"{RUN_LABEL}=={self.run_id}"
        ssh_keys = self.collection("ssh_keys", {"label_selector": selector})
        servers = self.collection("servers", {"label_selector": selector})
        collisions = {
            "ssh_keys": [
                self._identity(item)
                for item in ssh_keys
                if item.get("name") == self.ssh_key_name
                or (item.get("labels") or {}).get(ROLE_LABEL) == KEY_ROLE
            ],
            "servers": [
                self._identity(item)
                for item in servers
                if item.get("name") == self.server_name
                or (item.get("labels") or {}).get(ROLE_LABEL) == SERVER_ROLE
            ],
        }
        self.report["baseline"] = {
            "label_selector": selector,
            "counts": {"ssh_keys": len(ssh_keys), "servers": len(servers)},
            "collisions": collisions,
        }
        if any(collisions.values()):
            raise HarnessError(
                "A run-owned label collision exists; use its durable ledger or a new run ID"
            )
        active_entries = [
            entry
            for entry in self.ledger.entries()
            if self.ledger.cleanup_eligible(entry.get("kind"), entry.get("resource_id"))
        ]
        if active_entries:
            raise HarnessError("This run already has active ledger resources; clean them up first")

    @staticmethod
    def _identity(item):
        return {
            "id": item.get("id"),
            "name": item.get("name"),
            "labels": item.get("labels") or {},
        }

    def preflight_capabilities(self):
        self._preflight_cleanup()
        server_types = self.collection("server_types")
        locations = self.collection("locations")
        images = self.collection("images", {"type": "system"})
        selected_type = next(
            (item for item in server_types if item.get("name") == self.server_type), None
        )
        selected_location = next(
            (item for item in locations if item.get("name") == self.location), None
        )
        selected_image = next(
            (
                item
                for item in images
                if (str(item.get("id")) == self.image or item.get("name") == self.image)
            ),
            None,
        )
        if not selected_type:
            raise HarnessError(f"Hetzner server type {self.server_type!r} is unavailable")
        if not selected_location:
            raise HarnessError(f"Hetzner location {self.location!r} is unavailable")
        if not selected_image or selected_image.get("status") not in {None, "available"}:
            raise HarnessError(f"Hetzner system image {self.image!r} is unavailable")
        priced_locations = {
            str(price.get("location") or "")
            for price in (selected_type.get("prices") or [])
        }
        if priced_locations and self.location not in priced_locations:
            raise HarnessError(
                f"Hetzner server type {self.server_type!r} is not offered in {self.location!r}"
            )
        architecture = str(selected_type.get("architecture") or "")
        image_architecture = str(selected_image.get("architecture") or "")
        if architecture and image_architecture and architecture != image_architecture:
            raise HarnessError("Configured server type and Ubuntu image architectures differ")
        self.report["preflight"] = {
            "server_type_id": selected_type.get("id"),
            "location_id": selected_location.get("id"),
            "image_id": selected_image.get("id"),
            "architecture": architecture or image_architecture,
            "database_credentials": "provided only at apply time and intentionally omitted",
        }

    def _wait_readback(self, kind, resource_id):
        deadline = time.monotonic() + min(self.timeout_seconds, 180)
        last_error = None
        while time.monotonic() < deadline:
            try:
                resource = self._get_resource_once(kind, resource_id)
            except HarnessError as error:
                last_error = self._safe_error(error)
                resource = None
            if resource is not None:
                return resource
            time.sleep(self.poll_seconds)
        suffix = f"; last error={last_error}" if last_error else ""
        raise AmbiguousMutation(
            f"Hetzner {kind} {resource_id} was not available for ownership read-back{suffix}"
        )

    def _key_ownership(self, public_key):
        return {
            "labels": self.labels_for_key,
            "public_key_sha256": hashlib.sha256(public_key.encode()).hexdigest(),
        }

    def _server_ownership(self, ssh_key_id):
        return {"labels": self.labels_for_server(ssh_key_id)}

    def _verify_key(self, resource, identifier, ownership, source_witness):
        expected_source = f"public-key-sha256:{ownership.get('public_key_sha256')}"
        return bool(
            resource
            and str(resource.get("id")) == str(identifier)
            and resource.get("name") == self.ssh_key_name
            and all(
                str((resource.get("labels") or {}).get(key) or "") == str(value)
                for key, value in (ownership.get("labels") or {}).items()
            )
            and hashlib.sha256(str(resource.get("public_key") or "").encode()).hexdigest()
            == ownership.get("public_key_sha256")
            and source_witness == expected_source
        )

    def _verify_server(self, resource, identifier, ownership, source_witness):
        labels = ownership.get("labels") or {}
        expected_key_id = self.active.get("ssh_key")
        return bool(
            resource
            and str(resource.get("id")) == str(identifier)
            and resource.get("name") == self.server_name
            and all(
                str((resource.get("labels") or {}).get(key) or "") == str(value)
                for key, value in labels.items()
            )
            and expected_key_id
            and source_witness == f"ssh-key:{expected_key_id}"
            and labels.get(SOURCE_LABEL) == str(expected_key_id)
        )

    def _reconcile_pending_intents(self):
        """Adopt exact accepted creates or prove a prepared intent has no resource."""
        errors = []
        selectors = {
            "ssh_key": f"{RUN_LABEL}=={self.run_id}",
            "server": f"{RUN_LABEL}=={self.run_id}",
        }
        for key, intent in self.intents.pending().items():
            kind = str(intent.get("kind") or "")
            name = str(intent.get("name") or "")
            if kind not in selectors or not name:
                errors.append(f"{key}: malformed pending fixture intent")
                continue
            provider_id = str(intent.get("provider_id") or "")
            if provider_id:
                matches = [self._get_resource_once(kind, provider_id)]
                matches = [item for item in matches if item is not None]
            else:
                resource_name, _ = self._resource_key(kind)
                matches = [
                    item
                    for item in self.collection(
                        resource_name, {"label_selector": selectors[kind]}
                    )
                    if item.get("name") == name
                    and (item.get("labels") or {}).get(RUN_LABEL) == self.run_id
                    and (item.get("labels") or {}).get(ROLE_LABEL)
                    == (KEY_ROLE if kind == "ssh_key" else SERVER_ROLE)
                ]
            if len(matches) > 1:
                errors.append(f"{key}: multiple exact pending {kind} matches")
                continue
            if len(matches) == 1:
                observed = matches[0]
                identifier = str(observed.get("id") or "")
                ownership = intent.get("ownership") or {}
                source_witness = str(intent.get("source_witness") or "")
                if kind == "ssh_key":
                    owned = self._verify_key(
                        observed, identifier, ownership, source_witness
                    )
                else:
                    key_id = str(intent.get("ssh_key_id") or "")
                    key_resource = self._get_resource_once("ssh_key", key_id)
                    key_labels = (key_resource or {}).get("labels") or {}
                    if (
                        not key_resource
                        or str(key_resource.get("id")) != key_id
                        or key_labels.get(RUN_LABEL) != self.run_id
                        or key_labels.get(ROLE_LABEL) != KEY_ROLE
                    ):
                        owned = False
                    else:
                        self.active["ssh_key"] = key_id
                        owned = self._verify_server(
                            observed, identifier, ownership, source_witness
                        )
                if not owned or not identifier:
                    errors.append(f"{key}: pending {kind} ownership mismatch")
                    continue
                self.ledger.record(
                    kind=kind,
                    resource_id=identifier,
                    name=name,
                    ownership=ownership,
                    source_witness=source_witness,
                )
                self.intents.update(key, provider_id=identifier, mutation_state="ledgered")
                self.intents.clear(key)
                self.active[kind] = identifier
                continue
            if str(intent.get("mutation_state") or "prepared") == "prepared":
                self.intents.clear(key)
                continue
            errors.append(
                f"{key}: accepted or ambiguous {kind} create has no exact provider match"
            )
        return errors

    def create_ssh_key(self):
        payload = {
            "name": self.ssh_key_name,
            "public_key": self.public_key,
            "labels": self.labels_for_key,
        }
        pending_key = "create:ssh_key"
        self.intents.put(
            pending_key,
            {
                "marker": self.ssh_key_name,
                "kind": "ssh_key",
                "name": self.ssh_key_name,
                "operation": "create_ssh_key",
                "ownership": self._key_ownership(self.public_key),
                "source_witness": f"public-key-sha256:{hashlib.sha256(self.public_key.encode()).hexdigest()}",
                "mutation_state": "request_started",
                "payload_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True).encode()
                ).hexdigest(),
            },
        )
        try:
            response = self.request(
                "POST",
                "/ssh_keys",
                expected=(201,),
                mutation=True,
                json=payload,
            )
        except Exception as error:
            self.intents.update(
                pending_key,
                mutation_state="outcome_unknown",
                last_error_code=provider_error_class(error),
            )
            raise
        returned = response.get("ssh_key") or {}
        identifier = str(returned.get("id") or "")
        if not PROVIDER_ID_RE.fullmatch(identifier):
            self.intents.update(
                pending_key,
                mutation_state="outcome_unknown",
                last_error_code="PROVIDER_MALFORMED_RESPONSE",
            )
            raise AmbiguousMutation("Hetzner SSH key create returned no usable ID; no retry issued")
        self.intents.update(pending_key, provider_id=identifier, mutation_state="accepted")
        observed = self._wait_readback("ssh_key", identifier)
        ownership = self._key_ownership(self.public_key)
        if not self._verify_key(
            observed,
            identifier,
            ownership,
            f"public-key-sha256:{ownership['public_key_sha256']}",
        ):
            raise HarnessError("Hetzner SSH key ownership read-back failed")
        self.ledger.record(
            kind="ssh_key",
            resource_id=identifier,
            name=self.ssh_key_name,
            ownership=ownership,
            source_witness=f"public-key-sha256:{ownership['public_key_sha256']}",
        )
        self.intents.update(pending_key, mutation_state="ledgered")
        self.intents.clear(pending_key)
        self.active["ssh_key"] = identifier
        self.report["resources"] = {"ssh_key_id": identifier}
        return observed

    def create_server(self, ssh_key_id):
        self.user_data = build_cloud_init(self.run_id, self.public_key, self.fixture_inputs)
        image = int(self.image) if str(self.image).isdigit() else self.image
        payload = {
            "name": self.server_name,
            "server_type": self.server_type,
            "image": image,
            "location": self.location,
            "ssh_keys": [int(ssh_key_id)],
            "start_after_create": True,
            "labels": self.labels_for_server(ssh_key_id),
            "user_data": self.user_data,
        }
        pending_key = "create:server"
        ownership = self._server_ownership(ssh_key_id)
        self.intents.put(
            pending_key,
            {
                "marker": self.server_name,
                "kind": "server",
                "name": self.server_name,
                "operation": "create_server",
                "ssh_key_id": str(ssh_key_id),
                "ownership": ownership,
                "source_witness": f"ssh-key:{ssh_key_id}",
                "mutation_state": "request_started",
                "payload_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True).encode()
                ).hexdigest(),
            },
        )
        try:
            response = self.request(
                "POST",
                "/servers",
                expected=(201,),
                mutation=True,
                json=payload,
            )
        except Exception as error:
            self.intents.update(
                pending_key,
                mutation_state="outcome_unknown",
                last_error_code=provider_error_class(error),
            )
            raise
        returned = response.get("server") or {}
        identifier = str(returned.get("id") or "")
        if not PROVIDER_ID_RE.fullmatch(identifier):
            self.intents.update(
                pending_key,
                mutation_state="outcome_unknown",
                last_error_code="PROVIDER_MALFORMED_RESPONSE",
            )
            raise AmbiguousMutation("Hetzner server create returned no usable ID; no retry issued")
        self.intents.update(pending_key, provider_id=identifier, mutation_state="accepted")
        observed = self._wait_readback("server", identifier)
        ownership = self._server_ownership(ssh_key_id)
        if not self._verify_server(observed, identifier, ownership, f"ssh-key:{ssh_key_id}"):
            raise HarnessError("Hetzner server ownership read-back failed")
        self.ledger.record(
            kind="server",
            resource_id=identifier,
            name=self.server_name,
            ownership=ownership,
            source_witness=f"ssh-key:{ssh_key_id}",
        )
        self.intents.update(pending_key, mutation_state="ledgered")
        self.intents.clear(pending_key)
        self.active["server"] = identifier
        self.report.setdefault("resources", {})["server_id"] = identifier
        return observed

    def _wait_server_running(self, server_id):
        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            server = self._get_resource_once("server", server_id)
            if server is None:
                raise HarnessError("The fixture server disappeared before becoming running")
            status = str(server.get("status") or "")
            if status == "running":
                return server
            if status in {"deleting", "unknown"}:
                raise HarnessError(f"The fixture server entered terminal state {status!r}")
            time.sleep(self.poll_seconds)
        raise HarnessError("Timed out waiting for the fixture server to become running")

    @staticmethod
    def _public_ipv4(server):
        return str(((server.get("public_net") or {}).get("ipv4") or {}).get("ip") or "")

    def _validate_readiness(self, marker):
        website_marker = f"{self.run_id}:website-fixture-v1"
        if not isinstance(marker, dict):
            raise HarnessError("Fixture readiness marker is not a JSON object")
        if marker.get("schema") != 1 or marker.get("ready") is not True:
            raise HarnessError("Fixture readiness marker is not ready")
        if marker.get("run_id") != self.run_id:
            raise HarnessError("Fixture readiness marker belongs to another run")
        if (marker.get("website") or {}).get("marker") != website_marker:
            raise HarnessError("Fixture website marker does not match this run")
        databases = marker.get("databases") or {}
        for engine, port, counts in (
            ("mariadb", 3306, {"customers": 20, "orders": 40}),
            ("postgresql", 5432, {"customers": 20, "orders": 40}),
        ):
            detail = databases.get(engine) or {}
            if detail.get("host") != "127.0.0.1" or detail.get("port") != port:
                raise HarnessError(f"Fixture {engine} tunnel endpoint is incorrect")
            if detail.get("ssh_tunnel_required") is not True:
                raise HarnessError(f"Fixture {engine} is not marked for SSH tunnelling")
            table_counts = detail.get("tables") or {}
            if any(table_counts.get(name) != count for name, count in counts.items()):
                raise HarnessError(f"Fixture {engine} dataset counts are incomplete")
        return {
            "schema": marker.get("schema"),
            "run_id": marker.get("run_id"),
            "website_marker": website_marker,
            "database_engines": ["mariadb", "postgresql"],
        }

    def _wait_http_readiness(self, public_ip):
        url = f"http://{public_ip}{READINESS_PATH}"
        client = requests.Session()
        deadline = time.monotonic() + self.timeout_seconds
        last_status = None
        while time.monotonic() < deadline:
            try:
                response = client.get(url, timeout=self.http_timeout)
                last_status = response.status_code
                if response.status_code == 200:
                    try:
                        marker = response.json()
                    except ValueError as error:
                        raise HarnessError("Fixture readiness HTTP response was not JSON") from error
                    return self._validate_readiness(marker)
            except requests.RequestException:
                last_status = "unreachable"
            time.sleep(self.poll_seconds)
        raise HarnessError(
            f"Timed out waiting for HTTP fixture readiness; last_status={last_status!r}"
        )

    def _ssh_readiness(self, public_ip):
        private_key_path = os.environ.get("HETZNER_E2E_SSH_PRIVATE_KEY_PATH")
        if not private_key_path:
            return {
                "status": "SKIPPED",
                "reason": "HETZNER_E2E_SSH_PRIVATE_KEY_PATH was not supplied",
            }
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", prefix="backupsheep-e2e-known-hosts-", delete=True
            ) as known_hosts:
                os.chmod(known_hosts.name, 0o600)
                scanned = subprocess.run(
                    ["ssh-keyscan", "-T", "10", "-p", "22", public_ip],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if scanned.returncode != 0 or not scanned.stdout.strip():
                    raise HarnessError("ssh-keyscan could not obtain the fixture host key")
                known_hosts.write(scanned.stdout)
                known_hosts.flush()
                completed = subprocess.run(
                    [
                        "ssh",
                        "-i",
                        str(Path(private_key_path).expanduser()),
                        "-p",
                        "22",
                        "-o",
                        "BatchMode=yes",
                        "-o",
                        "IdentitiesOnly=yes",
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "StrictHostKeyChecking=yes",
                        "-o",
                        f"UserKnownHostsFile={known_hosts.name}",
                        f"{SSH_USER}@{public_ip}",
                        "cat",
                        SSH_READINESS_PATH,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if completed.returncode != 0:
                    raise HarnessError("SSH readiness marker could not be read")
                try:
                    marker = json.loads(completed.stdout)
                except ValueError as error:
                    raise HarnessError("SSH readiness response was not JSON") from error
                self._validate_readiness(marker)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HarnessError("SSH readiness check failed") from error
        return {"status": "PASS", "user": SSH_USER, "non_root": True}

    def run_fixture(self):
        self.public_key = _load_public_key()
        self.fixture_inputs = _fixture_inputs_from_environment()
        self._secrets.extend(
            [
                self.fixture_inputs["mariadb"]["password"],
                self.fixture_inputs["postgresql"]["password"],
            ]
        )
        key = self.create_ssh_key()
        server = self.create_server(str(key["id"]))
        server_id = str(server["id"])
        running = self._wait_server_running(server_id)
        public_ip = self._public_ipv4(running)
        if not public_ip:
            raise HarnessError("The fixture server has no public IPv4 for HTTP/SSH readiness")
        http_result = self._wait_http_readiness(public_ip)
        ssh_result = self._ssh_readiness(public_ip)
        self.report["tests"]["cloud-init website and database fixture"] = {
            "status": "PASS",
            "http_readiness": http_result,
            "ssh_readiness": ssh_result,
        }
        self.report["connection"] = {
            "website_url": f"http://{public_ip}/backupsheep-e2e/",
            "readiness_url": f"http://{public_ip}{READINESS_PATH}",
            "ssh": {"host": public_ip, "port": 22, "user": SSH_USER},
            "database_tunnels": [
                {
                    "engine": "mariadb",
                    "remote_host": "127.0.0.1",
                    "remote_port": 3306,
                    "suggested_local_port": 13306,
                },
                {
                    "engine": "postgresql",
                    "remote_host": "127.0.0.1",
                    "remote_port": 5432,
                    "suggested_local_port": 15432,
                },
            ],
            "credentials": "supplied out-of-band; intentionally omitted",
        }

    def _wait_absent(self, kind, resource_id):
        deadline = time.monotonic() + min(self.timeout_seconds, 300)
        while time.monotonic() < deadline:
            if self._get_resource_once(kind, resource_id) is None:
                return True
            time.sleep(self.poll_seconds)
        return False

    def _delete_entry(self, entry):
        kind = str(entry.get("kind") or "")
        identifier = str(entry.get("resource_id") or "")
        if kind not in {"ssh_key", "server"} or not PROVIDER_ID_RE.fullmatch(identifier):
            raise HarnessError("Refused cleanup for malformed ledger entry")
        if not self.ledger.cleanup_eligible(kind, identifier):
            return "skipped"
        resource = self._get_resource_once(kind, identifier)
        if resource is None:
            self.ledger.mark_cleanup(kind, identifier, state="absent")
            return "absent"
        ownership = entry.get("ownership") or {}
        source_witness = str(entry.get("source_witness") or "")
        if kind == "ssh_key":
            owned = self._verify_key(resource, identifier, ownership, source_witness)
            path = f"/ssh_keys/{identifier}"
            provider_resource = "SSH key"
        else:
            owned = self._verify_server(resource, identifier, ownership, source_witness)
            path = f"/servers/{identifier}"
            provider_resource = "server"
        if not owned:
            self.ledger.mark_cleanup(
                kind, identifier, state="manual_review", error="ownership mismatch"
            )
            raise HarnessError(f"Refused {provider_resource} deletion: ownership mismatch")
        try:
            response = self.request(
                "DELETE",
                path,
                expected=(200, 204),
                allow_404=True,
                mutation=True,
            )
            if response is None:
                self.ledger.mark_cleanup(kind, identifier, state="absent")
                return "absent"
        except AmbiguousMutation as error:
            remaining = self._get_resource_once(kind, identifier)
            if remaining is None:
                self.ledger.mark_cleanup(kind, identifier, state="deleted")
                return "deleted-after-ambiguous-response"
            self.ledger.mark_cleanup(
                kind, identifier, state="manual_review", error=self._safe_error(error)
            )
            raise
        if not self._wait_absent(kind, identifier):
            self.ledger.mark_cleanup(
                kind,
                identifier,
                state="manual_review",
                error="resource remained after confirmed delete response",
            )
            raise HarnessError(f"{provider_resource} {identifier} remained after deletion")
        self.ledger.mark_cleanup(kind, identifier, state="deleted")
        return "deleted"

    def cleanup(self):
        if not self.cleanup_requested:
            self.report["cleanup"] = {
                "status": "NOT_REQUESTED",
                "errors": [],
                "considered": [],
            }
            return
        if not self.apply:
            self.report["cleanup"] = {
                "status": "REFUSED",
                "errors": [
                    "Cleanup is a provider write and requires both "
                    "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES"
                ],
                "considered": [],
            }
            return
        pending_errors = self._reconcile_pending_intents()
        if pending_errors:
            self.report["cleanup"] = {
                "status": "MANUAL_REVIEW",
                "errors": [bounded_error(error, self._secrets) for error in pending_errors],
                "considered": [],
            }
            return
        errors = []
        entries = self.ledger.entries()
        server_entries = [
            entry
            for entry in entries
            if entry.get("kind") == "server"
            and self.ledger.cleanup_eligible("server", entry.get("resource_id"))
        ]
        key_entries = [
            entry
            for entry in entries
            if entry.get("kind") == "ssh_key"
            and self.ledger.cleanup_eligible("ssh_key", entry.get("resource_id"))
        ]
        considered = [
            {"kind": entry.get("kind"), "resource_id": entry.get("resource_id")}
            for entry in server_entries + key_entries
        ]
        server_clear = bool(server_entries)
        for entry in server_entries:
            try:
                result = self._delete_entry(entry)
                server_clear = server_clear and result in {
                    "deleted",
                    "absent",
                    "deleted-after-ambiguous-response",
                }
            except Exception as error:
                server_clear = False
                errors.append(self._safe_error(error))
        if key_entries and not server_entries:
            errors.append("refused SSH key deletion because no ledgered server witness exists")
            for entry in key_entries:
                identifier = str(entry.get("resource_id") or "")
                self.ledger.mark_cleanup(
                    "ssh_key",
                    identifier,
                    state="manual_review",
                    error="no ledgered server witness",
                )
        elif key_entries and not server_clear:
            errors.append("refused SSH key deletion because the ledgered server is not confirmed absent")
            for entry in key_entries:
                identifier = str(entry.get("resource_id") or "")
                if self.ledger.cleanup_eligible("ssh_key", identifier):
                    self.ledger.mark_cleanup(
                        "ssh_key",
                        identifier,
                        state="manual_review",
                        error="ledgered server was not confirmed absent",
                    )
        else:
            for entry in key_entries:
                try:
                    self._delete_entry(entry)
                except Exception as error:
                    errors.append(self._safe_error(error))
        self.report["cleanup"] = {
            "status": "PASS" if not errors else "MANUAL_REVIEW",
            "errors": errors,
            "considered": considered,
        }

    def run(self):
        if self.cleanup_requested and not self.apply:
            self.cleanup()
            self.report["status"] = "FAIL"
            self.report["error"] = (
                "Cleanup is a provider write and requires both "
                "BACKUPSHEEP_E2E_APPLY=YES and BACKUPSHEEP_E2E_CLEANUP=YES"
            )
            print(json.dumps(self.report, indent=2, sort_keys=True))
            return 1
        try:
            if self.cleanup_requested:
                self.report["mode"] = "cleanup_only"
                self.cleanup()
                self.report["status"] = (
                    "CLEANUP_PASS"
                    if self.report["cleanup"]["status"] == "PASS"
                    else "CLEANUP_MANUAL_REVIEW"
                )
                return 0 if self.report["status"] == "CLEANUP_PASS" else 2
            pending_errors = self._reconcile_pending_intents()
            if pending_errors:
                raise HarnessError("; ".join(pending_errors))
            self.baseline()
            self.preflight_capabilities()
            if not self.apply:
                self.report["status"] = "PREFLIGHT_PASS"
                self.report["mode"] = "read_only"
                return 0
            self.report["mode"] = "create_for_ui"
            self.run_fixture()
            self.report["status"] = "PASS"
            return 0
        except Exception as error:
            self.report["status"] = "MANUAL_REVIEW" if isinstance(error, AmbiguousMutation) else "FAIL"
            self.report["error"] = self._safe_error(error)
            return 2 if isinstance(error, AmbiguousMutation) else 1
        finally:
            if not self.cleanup_requested:
                self.report["cleanup"] = {
                    "status": "NOT_REQUESTED",
                    "errors": [],
                    "considered": [],
                }
            print(json.dumps(self.report, indent=2, sort_keys=True, default=str))


def main():
    required = ("HCLOUD_TOKEN", "BACKUPSHEEP_E2E_RUN_ID", "BACKUPSHEEP_E2E_LEDGER_PATH")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": "Missing required environment variables: " + ", ".join(missing),
                },
                indent=2,
            )
        )
        return 1
    try:
        harness = HetznerFixtureHarness(os.environ["HCLOUD_TOKEN"])
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": _redact(error, [os.environ.get("HCLOUD_TOKEN")]),
                },
                indent=2,
            )
        )
        return 1
    return harness.run()


if __name__ == "__main__":
    sys.exit(main())
