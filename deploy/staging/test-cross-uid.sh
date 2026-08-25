#!/bin/sh
# Linux-kernel adversarial proof for the staging UID/GID layout.
# Run only against disposable mounts after provision-volumes.sh succeeds.
set -eu
umask 077

fail() {
  printf '%s\n' "cross-UID staging test failed: $*" >&2
  exit 1
}

[ "$(id -u)" = 0 ] || fail "test harness requires disposable container root."
command -v setpriv >/dev/null 2>&1 || fail "setpriv is required."

run_database() {
  setpriv --reuid=10002 --regid=10002 --groups=10994,10997,10998,10999 -- "$@"
}

run_files() {
  setpriv --reuid=10003 --regid=10003 --groups=10993,10997,10998,10999 -- "$@"
}

run_storage() {
  setpriv --reuid=10004 --regid=10004 --groups=10993,10994,10995,10999 -- "$@"
}

run_web() {
  setpriv --reuid=10001 --regid=10001 --clear-groups -- "$@"
}

run_logs() {
  setpriv --reuid=10005 --regid=10005 --clear-groups -- "$@"
}

expect_denied() {
  label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$label unexpectedly succeeded."
  fi
}

run_database sh -ceu '
  umask 077
  printf plaintext-database > /volumes/database/plaintext.zip
  mkdir /volumes/transfer/11111111-2222-4333-8444-555555555555
  chgrp 10999 /volumes/transfer/11111111-2222-4333-8444-555555555555
  chmod 2750 /volumes/transfer/11111111-2222-4333-8444-555555555555
  printf BSE1ciphertext > /volumes/transfer/11111111-2222-4333-8444-555555555555/archive.bse1
  chmod 0640 /volumes/transfer/11111111-2222-4333-8444-555555555555/archive.bse1
'
run_files sh -ceu '
  umask 077
  printf plaintext-files > /volumes/files/plaintext.zip
'
run_storage sh -ceu '
  umask 077
  printf local-ciphertext > /volumes/backup-storage/local-object.bse1
  mkdir /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
  chgrp 10994 /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
  chmod 2750 /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
  printf BSE1restore > /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1
  chmod 0640 /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1
'
run_web sh -ceu '
  umask 077
  printf approved-key > /volumes/ssh-trust/.known_hosts.new
  chgrp 10997 /volumes/ssh-trust/.known_hosts.new
  chmod 0640 /volumes/ssh-trust/.known_hosts.new
  mv /volumes/ssh-trust/.known_hosts.new /volumes/ssh-trust/known_hosts
'

expect_denied "files reading database plaintext" \
  run_files sh -c 'exec 3</volumes/database/plaintext.zip'
expect_denied "storage reading database plaintext" \
  run_storage sh -c 'exec 3</volumes/database/plaintext.zip'
expect_denied "database reading files plaintext" \
  run_database sh -c 'exec 3</volumes/files/plaintext.zip'
expect_denied "files writing database plaintext" \
  run_files sh -c 'printf attack >> /volumes/database/plaintext.zip'
expect_denied "storage deleting database plaintext" \
  run_storage sh -c 'rm /volumes/database/plaintext.zip'
expect_denied "database reading local storage" \
  run_database sh -c 'exec 3</volumes/backup-storage/local-object.bse1'
expect_denied "files deleting local storage" \
  run_files sh -c 'rm /volumes/backup-storage/local-object.bse1'
expect_denied "storage pre-creating a transfer fence" \
  run_storage sh -c 'mkdir /volumes/transfer/22222222-3333-4444-8555-666666666666'
expect_denied "storage enumerating transfer fences" \
  run_storage sh -c 'ls /volumes/transfer'
run_database sh -ceu '
  test "$(cat /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1)" = BSE1restore
'
expect_denied "database enumerating restore handoffs" \
  run_database sh -c 'ls /volumes/restore-transfer'
expect_denied "files reading database restore ciphertext" \
  run_files sh -c 'exec 3</volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1'
expect_denied "database modifying restore ciphertext" \
  run_database sh -c 'printf attack >> /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1'
expect_denied "database deleting restore ciphertext" \
  run_database sh -c 'rm /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1'
run_database sh -ceu 'test "$(cat /volumes/ssh-trust/known_hosts)" = approved-key'
run_files sh -ceu 'test "$(cat /volumes/ssh-trust/known_hosts)" = approved-key'
expect_denied "database modifying SSH trust" \
  run_database sh -c 'printf attack >> /volumes/ssh-trust/known_hosts'
expect_denied "files deleting SSH trust" \
  run_files sh -c 'rm /volumes/ssh-trust/known_hosts'
expect_denied "storage reading SSH trust" \
  run_storage sh -c 'exec 3</volumes/ssh-trust/known_hosts'
expect_denied "logs reading SSH trust" \
  run_logs sh -c 'exec 3</volumes/ssh-trust/known_hosts'
run_web sh -ceu '
  printf rotated-key > /volumes/ssh-trust/.known_hosts.rotated
  chgrp 10997 /volumes/ssh-trust/.known_hosts.rotated
  chmod 0640 /volumes/ssh-trust/.known_hosts.rotated
  mv /volumes/ssh-trust/.known_hosts.rotated /volumes/ssh-trust/known_hosts
'
run_files sh -ceu 'test "$(cat /volumes/ssh-trust/known_hosts)" = rotated-key'

run_storage sh -ceu '
  test "$(cat /volumes/transfer/11111111-2222-4333-8444-555555555555/archive.bse1)" = BSE1ciphertext
'
expect_denied "storage modifying published ciphertext" \
  run_storage sh -c 'printf attack >> /volumes/transfer/11111111-2222-4333-8444-555555555555/archive.bse1'
expect_denied "storage deleting published ciphertext" \
  run_storage sh -c 'rm /volumes/transfer/11111111-2222-4333-8444-555555555555/archive.bse1'
expect_denied "files deleting another lane fence" \
  run_files sh -c 'rmdir /volumes/transfer/11111111-2222-4333-8444-555555555555'

# Only the owning source identity can clean its exact fence.  The test names every
# target explicitly and operates solely on disposable tmpfs mounts.
run_database sh -ceu '
  rm /volumes/transfer/11111111-2222-4333-8444-555555555555/archive.bse1
  rmdir /volumes/transfer/11111111-2222-4333-8444-555555555555
'
test ! -e /volumes/transfer/11111111-2222-4333-8444-555555555555 \
  || fail "the owning source lane could not clean its exact fence."
run_storage sh -ceu '
  rm /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1
  rmdir /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
'
test ! -e /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee \
  || fail "storage could not clean its exact restore fence."

printf '%s\n' "cross-UID staging isolation passed"
