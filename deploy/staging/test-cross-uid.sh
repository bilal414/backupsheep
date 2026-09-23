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
  setpriv --reuid=10002 --regid=10002 --groups=10989,10990,10994 -- "$@"
}

run_files() {
  setpriv --reuid=10003 --regid=10003 --groups=10991,10992,10993 -- "$@"
}

run_storage() {
  setpriv --reuid=10004 --regid=10004 --groups=10990,10992,10993,10994,10995 -- "$@"
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
  mkdir /volumes/database-transfer/11111111-2222-4333-8444-555555555555
  chgrp 10990 /volumes/database-transfer/11111111-2222-4333-8444-555555555555
  chmod 2750 /volumes/database-transfer/11111111-2222-4333-8444-555555555555
  printf BSE1database > /volumes/database-transfer/11111111-2222-4333-8444-555555555555/archive.bse1
  chmod 0640 /volumes/database-transfer/11111111-2222-4333-8444-555555555555/archive.bse1
'
run_files sh -ceu '
  umask 077
  printf plaintext-files > /volumes/files/plaintext.zip
  mkdir /volumes/files-transfer/11111111-2222-4333-8444-555555555555
  chgrp 10992 /volumes/files-transfer/11111111-2222-4333-8444-555555555555
  chmod 2750 /volumes/files-transfer/11111111-2222-4333-8444-555555555555
  printf BSE1files > /volumes/files-transfer/11111111-2222-4333-8444-555555555555/archive.bse1
  chmod 0640 /volumes/files-transfer/11111111-2222-4333-8444-555555555555/archive.bse1
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
  run_storage sh -c 'mkdir /volumes/database-transfer/22222222-3333-4444-8555-666666666666'
expect_denied "storage pre-creating a files transfer fence" \
  run_storage sh -c 'mkdir /volumes/files-transfer/22222222-3333-4444-8555-666666666666'
expect_denied "storage enumerating database transfer fences" \
  run_storage sh -c 'ls /volumes/database-transfer'
expect_denied "storage enumerating files transfer fences" \
  run_storage sh -c 'ls /volumes/files-transfer'
expect_denied "files enumerating database transfer fences" \
  run_files sh -c 'ls /volumes/database-transfer'
expect_denied "database enumerating files transfer fences" \
  run_database sh -c 'ls /volumes/files-transfer'
expect_denied "files reading known database ciphertext" \
  run_files sh -c 'exec 3</volumes/database-transfer/11111111-2222-4333-8444-555555555555/archive.bse1'
expect_denied "database reading known files ciphertext" \
  run_database sh -c 'exec 3</volumes/files-transfer/11111111-2222-4333-8444-555555555555/archive.bse1'
expect_denied "files pre-creating a database transfer fence" \
  run_files sh -c 'mkdir /volumes/database-transfer/22222222-3333-4444-8555-666666666666'
expect_denied "database pre-creating a files transfer fence" \
  run_database sh -c 'mkdir /volumes/files-transfer/22222222-3333-4444-8555-666666666666'
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
run_storage sh -ceu '
  test "$(cat /volumes/database-transfer/11111111-2222-4333-8444-555555555555/archive.bse1)" = BSE1database
  test "$(cat /volumes/files-transfer/11111111-2222-4333-8444-555555555555/archive.bse1)" = BSE1files
'
expect_denied "storage modifying published ciphertext" \
  run_storage sh -c 'printf attack >> /volumes/database-transfer/11111111-2222-4333-8444-555555555555/archive.bse1'
expect_denied "storage deleting published ciphertext" \
  run_storage sh -c 'rm /volumes/database-transfer/11111111-2222-4333-8444-555555555555/archive.bse1'
expect_denied "files deleting another lane fence" \
  run_files sh -c 'rmdir /volumes/database-transfer/11111111-2222-4333-8444-555555555555'

# Only the owning source identity can clean its exact fence.  The test names every
# target explicitly and operates solely on disposable tmpfs mounts.
run_database sh -ceu '
  rm /volumes/database-transfer/11111111-2222-4333-8444-555555555555/archive.bse1
  rmdir /volumes/database-transfer/11111111-2222-4333-8444-555555555555
'
test ! -e /volumes/database-transfer/11111111-2222-4333-8444-555555555555 \
  || fail "the owning source lane could not clean its exact fence."
run_files sh -ceu '
  rm /volumes/files-transfer/11111111-2222-4333-8444-555555555555/archive.bse1
  rmdir /volumes/files-transfer/11111111-2222-4333-8444-555555555555
'
run_storage sh -ceu '
  rm /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/archive.bse1
  rmdir /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
'
test ! -e /volumes/restore-transfer/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee \
  || fail "storage could not clean its exact restore fence."

printf '%s\n' "cross-UID staging isolation passed"
