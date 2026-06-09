"""Input guards for the database backup tasks.

The dump commands in mysql.py / mariadb.py / postgresql.py are built by interpolating
user-controlled connection/node fields (host, username, database/table names, dump
options, ...) into shell command strings that are executed with ``shell=True`` or sent
to a remote ``ssh.exec_command``. Those fields originate from authenticated users and
are otherwise unvalidated, which makes them a command-injection / path-traversal vector.

Rather than restructure every command builder, these helpers reject values that could
break out of their interpolation context *before* the command is assembled. Legitimate
hostnames, usernames, database/table names and dump flags pass untouched; anything that
could inject a second command (or escape the ``_storage`` directory when used as a dump
filename) raises ``UnsafeBackupInput``, which the task's existing ``except`` turns into a
normal backup failure.
"""

import re

# Single-token values that are interpolated *unquoted* into the command and are also used
# as on-disk dump filenames (host, port, username, database name, table name). Reject
# shell metacharacters, whitespace (argument splitting) and path separators (traversal).
_UNQUOTED_TOKEN_BAD = re.compile(r"""[\s;&|`$<>(){}\[\]\\'"!*?~#/]""")

# Free-form dump option strings (e.g. pg_dump "-w --clean") legitimately contain spaces
# and dashes, so only reject characters that allow chaining a second command.
_OPTION_BAD = re.compile(r"""[;&|`$<>(){}\[\]\\'"\n\r]""")


class UnsafeBackupInput(ValueError):
    """Raised when a backup input contains characters that are unsafe to shell out with."""


def safe_token(value, field):
    """Validate a value interpolated unquoted into a command / used as a dump filename."""
    text = "" if value is None else str(value)
    if _UNQUOTED_TOKEN_BAD.search(text):
        raise UnsafeBackupInput(
            f"Rejected unsafe characters in {field!r}. Remove shell metacharacters, "
            f"spaces and slashes."
        )
    return text


def safe_password(value, field="password"):
    """Validate a value interpolated inside a single-quoted shell context (e.g. PGPASSWORD).

    Inside single quotes the shell treats everything literally, so the only character that
    can break out is the single quote itself; carriage-return / newline are also rejected
    so a value can never start a new command line.
    """
    text = "" if value is None else str(value)
    if "'" in text or "\n" in text or "\r" in text:
        raise UnsafeBackupInput(
            f"Rejected unsafe characters in {field!r}. Single quotes and newlines are not "
            f"allowed."
        )
    return text


def safe_options(value, field):
    """Validate a free-form dump option string that may contain spaces/dashes."""
    text = "" if value is None else str(value)
    if _OPTION_BAD.search(text):
        raise UnsafeBackupInput(f"Rejected unsafe characters in {field!r}.")
    return text
