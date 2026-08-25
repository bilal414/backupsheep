=== BackupSheep Secure Connector ===
Contributors: backupsheep
Requires at least: 6.0
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Authenticated, replay-resistant BackupSheep integration for UpdraftPlus.

== Security ==

Version 2 removes the legacy query-string bearer key and state-changing GET API.
Every request uses a short-lived timestamp, one-time nonce, exact body digest, and
HMAC-SHA256 signature. Backup files are streamed only through the authenticated REST
request and are never moved into a public web directory.

There is intentionally no protocol-v1 compatibility mode. Rotate the integration key
after replacing an older plugin release.
