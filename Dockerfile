# syntax=docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

# Self-hosted BackupSheep image, shared by the web, Celery worker, and beat
# services. Native compilation, repository tooling, and archive verification stay
# in disposable builder stages. The final stage starts from a digest-pinned Ubuntu
# LTS image, receives Python from the separately pinned official Python image, and
# installs only authenticated offline runtime packages and verified client artifacts.

FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS python-runtime

FROM python-runtime AS python-wheels

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_NO_INPUT=1 \
    PIP_CONFIG_FILE=/dev/null

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        libcurl4-openssl-dev \
        libffi-dev \
        libfreetype-dev \
        libgnutls28-dev \
        libjpeg62-turbo-dev \
        libncurses-dev \
        libpq-dev \
        libreadline-dev \
        libsqlite3-dev \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        libzmq3-dev \
        pkg-config \
        unixodbc-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY --link --chmod=0444 requirements.txt requirements.lock /build/
RUN set -eu; \
    requirements_sha256="$(sha256sum /build/requirements.txt | awk '{print $1}')"; \
    grep -Fqx "# requirements-sha256: ${requirements_sha256}" \
        /build/requirements.lock

# A small bootstrap lock is derived from the already authenticated full lock.
# The source-only provider SDKs use setuptools' legacy backend; installing these
# two exact wheel artifacts lets the main build disable pip's otherwise unpinned
# build-isolation downloads.
RUN python - <<'PY'
from pathlib import Path

lines = Path("/build/requirements.lock").read_text(encoding="utf-8").splitlines()
selected = []
for package in ("setuptools", "wheel"):
    start = next(
        (index for index, line in enumerate(lines) if line.startswith(f"{package}==")),
        None,
    )
    if start is None:
        raise SystemExit(f"{package} is missing from requirements.lock")
    index = start
    while True:
        selected.append(lines[index])
        if not lines[index].rstrip().endswith("\\"):
            break
        index += 1
Path("/build/build-tools.lock").write_text(
    "\n".join(selected) + "\n", encoding="utf-8"
)
PY
RUN python -m pip --isolated install \
        --index-url=https://pypi.org/simple \
        --no-cache-dir \
        --no-deps \
        --only-binary=:all: \
        --require-hashes \
        --requirement=/build/build-tools.lock
RUN python -m pip --isolated wheel \
        --index-url=https://pypi.org/simple \
        --no-cache-dir \
        --prefer-binary \
        --only-binary=:all: \
        --no-binary=crcmod,ibm-cos-sdk,ibm-cos-sdk-core,ibm-cos-sdk-s3transfer,oss2 \
        --no-build-isolation \
        --require-hashes \
        --wheel-dir=/wheels \
        --requirement=/build/requirements.lock

# Locally built wheels do not have the same digest as their authenticated source
# archives. Bind the exact, platform-specific wheelhouse to a second hash lock so
# the final offline install also operates in pip's hash-checking mode.
RUN python - <<'PY'
from hashlib import file_digest
from pathlib import Path

wheels = sorted(Path("/wheels").glob("*.whl"))
if not wheels:
    raise SystemExit("The authenticated wheelhouse is empty.")
with Path("/wheels/requirements.runtime.lock").open("w", encoding="utf-8") as output:
    for wheel in wheels:
        with wheel.open("rb") as source:
            digest = file_digest(source, "sha256").hexdigest()
        output.write(f"{wheel} --hash=sha256:{digest}\n")
PY


# Produce the PGDG keyring in an isolated stage. Both the downloaded key bytes
# and its OpenPGP primary fingerprint are pinned before it is trusted by APT.
FROM python-runtime AS repository-metadata

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    install -d -m 0755 /repository; \
    curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 \
        -o /tmp/pgdg.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc; \
    echo "0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76  /tmp/pgdg.asc" \
        | sha256sum -c -; \
    actual_fingerprint="$(gpg --batch --with-colons --import-options show-only \
        --import /tmp/pgdg.asc | awk -F: '$1 == "fpr" { print $10; exit }')"; \
    test "$actual_fingerprint" = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"; \
    gpg --batch --yes --dearmor --output /repository/pgdg.gpg /tmp/pgdg.asc


# Download the exact PostgreSQL client artifacts while APT still has the signed
# Debian/PGDG indexes. Repackage only the versioned client trees, with their
# authenticated source-archive and payload hashes, so dpkg and SBOM scanners can
# attribute every installed executable without importing PGDG's Perl wrappers.
FROM python-runtime AS postgres-clients

ARG TARGETARCH
COPY --from=repository-metadata /repository/pgdg.gpg /usr/share/keyrings/pgdg.gpg
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64|arm64) ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt trixie-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && install -d -m 0755 /postgres-client-debs /extract-debs \
    && apt-get update \
    && cd /extract-debs \
    && for package in \
        "postgresql-client-14=14.24-1.pgdg13+2" \
        "postgresql-client-15=15.19-1.pgdg13+2" \
        "postgresql-client-16=16.15-1.pgdg13+2" \
        "postgresql-client-17=17.11-1.pgdg13+2" \
        "postgresql-client-18=18.6-1.pgdg13+2"; do \
        apt-get download "$package"; \
    done \
    && for metadata in \
        "14 14.24-1.pgdg13+2 2a17bc01dd3c4345d4ac85b084a11d7fb74265aead805e75cf0a296552f0f42e 4ac24008059ecc1993d9a944648ed36d0730b95d01f6a3522407795b2d00a47f 61983f6ae42ee31c3e3477cfed77d7a42c58956e7abbfeed06e4c6e176042454 65a052e5e9563563d2a502f58066c9bb074e4ef63ef2c321bcfba97ab4a15c0b" \
        "15 15.19-1.pgdg13+2 718b5a25eb99db5ee37b165ebeeefea50ecf993c9cde1db26eb401e6bbe0be08 29b55286e8de51c79ad317968e03d7a311c66c101e8536e2b635d860da3648af ec63ed182c6f3719e6b820bdf44a854597574af0a683d1a49e3cc81f68e3d855 0f4126aaa556bf544961f8e20fd2a9926a872f9afdf09924b32bc548231ca760" \
        "16 16.15-1.pgdg13+2 82e1dfb1c8f6aed02811c43bff4ead374343ebafe61bca9af3662fc75a83a4b7 98f1b6ea41235282173901ef49dfb7b4c254810e9e23a2f2b3aeb758aedd2604 3c2bff97c4547d2106e2fd0f9ba2738d1d0a217baf84ea228f1d411d1f0fa620 5964afee95ca55cd1816cb725d0289fba0c6f42159edc5f139676500f1a2157f" \
        "17 17.11-1.pgdg13+2 c36408bb62178bc9193c113da65e30fc6a5237648de5e9db1ea594214df9ae4b 706c9fde003d98ff423a3d73bd5ac1115379481cb86daabf251e02f240d660d3 e2ca95d99073796d6dc4578282cd1f1789f81507b17c97158f024ef05d43eff0 e9fe0d1133b2cd6db2447a8ccc7e92794ca98572909de790a7ec8509cc929877" \
        "18 18.6-1.pgdg13+2 9af40c99f7074f8ff3798155af2f07f1a4e1e3bd4edce44ef928c1e03aea620e 098492efc9f576ffee23e1871d31682b332a3c6582072d3ef8f99b6b72573bc7 17e395f57433689ac3f8ed6cbeb631cf91dbb4e21d10573d4cc7b7f1f36a8f4b 1ac98a12bb3d68cf67413cfa68bc4f96e658eb8bdc88fa43b0a1dd6207c78473"; do \
        set -- $metadata; \
        pg_major="$1"; \
        pg_version="$2"; \
        case "$TARGETARCH" in \
            amd64) expected_archive_sha256="$3"; expected_payload_sha256="$5" ;; \
            arm64) expected_archive_sha256="$4"; expected_payload_sha256="$6" ;; \
        esac; \
        archive="$(find /extract-debs -maxdepth 1 -type f \
            -name "postgresql-client-${pg_major}_${pg_version}_${TARGETARCH}.deb" \
            -print -quit)"; \
        test -n "$archive"; \
        test "$(dpkg-deb --field "$archive" Package)" = "postgresql-client-${pg_major}"; \
        test "$(dpkg-deb --field "$archive" Version)" = "$pg_version"; \
        test "$(dpkg-deb --field "$archive" Source)" = "postgresql-${pg_major}"; \
        test "$(dpkg-deb --field "$archive" Architecture)" = "$TARGETARCH"; \
        echo "${expected_archive_sha256}  ${archive}" | sha256sum -c -; \
        source_root="/extract-debs/postgresql-${pg_major}"; \
        package_root="/extract-debs/backupsheep-postgresql-${pg_major}"; \
        dpkg-deb --extract "$archive" "$source_root"; \
        install -d -m 0755 \
            "$package_root/DEBIAN" \
            "$package_root/usr/lib/postgresql" \
            "$package_root/usr/share/backupsheep/provenance"; \
        cp -a "$source_root/usr/lib/postgresql/${pg_major}" \
            "$package_root/usr/lib/postgresql/"; \
        payload_sha256="$(cd "$package_root/usr/lib/postgresql/${pg_major}" \
            && find . -type f -print0 \
                | LC_ALL=C sort -z \
                | xargs -0 sha256sum \
                | sha256sum \
                | awk '{print $1}')"; \
        test "$payload_sha256" = "$expected_payload_sha256"; \
        pg_dump_sha256="$(sha256sum \
            "$package_root/usr/lib/postgresql/${pg_major}/bin/pg_dump" \
            | awk '{print $1}')"; \
        psql_sha256="$(sha256sum \
            "$package_root/usr/lib/postgresql/${pg_major}/bin/psql" \
            | awk '{print $1}')"; \
        printf '%s\n' \
            "Package: backupsheep-postgresql-client-${pg_major}" \
            "Version: ${pg_version}+backupsheep1" \
            "Source: postgresql-${pg_major} (${pg_version})" \
            "Architecture: ${TARGETARCH}" \
            'Maintainer: BackupSheep Security <security@backupsheep.com>' \
            'Depends: libc6 (= 2.43-2ubuntu2.3), libpq5 (= 18.6-0ubuntu0.26.04.1), libreadline8t64 (= 8.3-4), libssl3t64 (= 3.5.5-1ubuntu3.4), zlib1g (= 1:1.3.dfsg+really1.3.1-1ubuntu3)' \
            "Built-Using: postgresql-${pg_major} (= ${pg_version})" \
            'Section: database' \
            'Priority: optional' \
            "Description: Authenticated PostgreSQL ${pg_major} client tree for BackupSheep" \
            > "$package_root/DEBIAN/control"; \
        printf '{"artifact_architecture":"%s","payload_root":"/usr/lib/postgresql/%s","payload_sha256":"%s","pg_dump_sha256":"%s","psql_sha256":"%s","source_archive_sha256":"%s","source_binary_package":"postgresql-client-%s","source_package":"postgresql-%s","source_version":"%s"}\n' \
            "$TARGETARCH" "$pg_major" "$payload_sha256" "$pg_dump_sha256" \
            "$psql_sha256" "$expected_archive_sha256" "$pg_major" \
            "$pg_major" "$pg_version" \
            > "$package_root/usr/share/backupsheep/provenance/postgresql-client-${pg_major}.json"; \
        chmod 0444 \
            "$package_root/DEBIAN/control" \
            "$package_root/usr/share/backupsheep/provenance/postgresql-client-${pg_major}.json"; \
        package_archive="/postgres-client-debs/backupsheep-postgresql-client-${pg_major}_${pg_version}+backupsheep1_${TARGETARCH}.deb"; \
        dpkg-deb --build --root-owner-group "$package_root" "$package_archive"; \
        test "$(dpkg-deb --field "$package_archive" Package)" = \
            "backupsheep-postgresql-client-${pg_major}"; \
        test "$(dpkg-deb --field "$package_archive" Version)" = \
            "${pg_version}+backupsheep1"; \
    done \
    && find /postgres-client-debs -maxdepth 1 -type f -name '*.deb' -print0 \
        | sort -z \
        | xargs -0 sha256sum > /postgres-client-debs/SHA256SUMS \
    && sha256sum -c /postgres-client-debs/SHA256SUMS \
    && rm -rf /extract-debs /var/lib/apt/lists/* \
    && for version in 14 15 16 17 18; do \
        test -f "/postgres-client-debs/backupsheep-postgresql-client-${version}_"*.deb; \
    done


# Oracle MySQL's APT repository does not publish arm64 clients. Extract the two
# required tools from the versioned upstream generic bundle after validating the
# signing key checksum, key fingerprint, detached artifact signature and pinned
# architecture-specific artifact hash. A minimal package preserves dpkg/SBOM
# attribution and immutable installed provenance for exactly those two tools.
FROM python-runtime AS mysql-client

ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg libaio1t64 libncurses6 libnuma1 xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) \
            mysql_arch="x86_64"; \
            expected_archive_sha256="94e204cc94dede3746d2773fa5818f28f555cd8368c75ca0612eac124e6f3e58"; \
            expected_signature_sha256="23bcbef86b5125deceef25726a39f165094448c48e5263ba8e8fd89a90f9c17a"; \
            expected_payload_sha256="91f3d13d4d651794a4f746d9503605641d129cf700a7abaa6793768851383346" \
            ;; \
        arm64) \
            mysql_arch="aarch64"; \
            expected_archive_sha256="04b2f9791d314167a9eb83abcb476f45a7cd9e4aa88fa7a638cba40d1bc2a109"; \
            expected_signature_sha256="81fe648f43050d3af5e5f3d5a2b915a5c60c8f04141eafeb34047e75295ee9a1"; \
            expected_payload_sha256="b019990ef3b06aff37c9e7e6c7739cc73fed13de591cacc22f40b010be075a09" \
            ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    mysql_version="8.4.11"; \
    pkg="mysql-${mysql_version}-linux-glibc2.28-${mysql_arch}"; \
    export GNUPGHOME=/tmp/mysql-gnupg; \
    install -d -m 0700 "$GNUPGHOME"; \
    curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 \
        -o /tmp/mysql-build-key.asc \
        https://repo.mysql.com/RPM-GPG-KEY-mysql-2025; \
    echo "a4bcd9f16a53cc763f87b9955dbcdced33c7aa90296b157eb6ceef0f156f4327  /tmp/mysql-build-key.asc" \
        | sha256sum -c -; \
    actual_fingerprint="$(gpg --batch --with-colons --import-options show-only \
        --import /tmp/mysql-build-key.asc | awk -F: '$1 == "fpr" { print $10; exit }')"; \
    test "$actual_fingerprint" = "BCA43417C3B485DD128EC6D4B7B3B788A8D3785C"; \
    gpg --batch --import /tmp/mysql-build-key.asc; \
    curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 \
        -o /tmp/mysql-client.tar.xz \
        "https://cdn.mysql.com/Downloads/MySQL-8.4/${pkg}.tar.xz"; \
    curl --fail --silent --show-error --location \
        --proto '=https' --tlsv1.2 \
        -o /tmp/mysql-client.tar.xz.asc \
        "https://cdn.mysql.com/Downloads/MySQL-8.4/${pkg}.tar.xz.asc"; \
    echo "${expected_archive_sha256}  /tmp/mysql-client.tar.xz" | sha256sum -c -; \
    echo "${expected_signature_sha256}  /tmp/mysql-client.tar.xz.asc" | sha256sum -c -; \
    gpg --batch --verify /tmp/mysql-client.tar.xz.asc /tmp/mysql-client.tar.xz; \
    package_root=/tmp/backupsheep-oracle-mysql-client; \
    install -d -m 0755 \
        /mysql-client-debs \
        /tmp/mysql-client \
        "$package_root/DEBIAN" \
        "$package_root/opt/mysql/bin" \
        "$package_root/usr/share/backupsheep/provenance"; \
    tar -xJf /tmp/mysql-client.tar.xz -C /tmp/mysql-client \
        "${pkg}/bin/mysql" "${pkg}/bin/mysqldump"; \
    install -o root -g root -m 0555 \
        "/tmp/mysql-client/${pkg}/bin/mysql" \
        "$package_root/opt/mysql/bin/mysql"; \
    install -o root -g root -m 0555 \
        "/tmp/mysql-client/${pkg}/bin/mysqldump" \
        "$package_root/opt/mysql/bin/mysqldump"; \
    payload_sha256="$(cd "$package_root/opt/mysql" \
        && find . -type f -print0 \
            | LC_ALL=C sort -z \
            | xargs -0 sha256sum \
            | sha256sum \
            | awk '{print $1}')"; \
    test "$payload_sha256" = "$expected_payload_sha256"; \
    mysql_sha256="$(sha256sum "$package_root/opt/mysql/bin/mysql" | awk '{print $1}')"; \
    mysqldump_sha256="$(sha256sum "$package_root/opt/mysql/bin/mysqldump" | awk '{print $1}')"; \
    printf '%s\n' \
        'Package: backupsheep-oracle-mysql-client' \
        'Version: 8.4.11+backupsheep1' \
        'Source: mysql-community (8.4.11)' \
        "Architecture: ${TARGETARCH}" \
        'Maintainer: BackupSheep Security <security@backupsheep.com>' \
        'Depends: libc6 (= 2.43-2ubuntu2.3), libgcc-s1 (= 16-20260322-1ubuntu1), libncurses6 (= 6.6+20251231-1), libssl3t64 (= 3.5.5-1ubuntu3.4), libstdc++6 (= 16-20260322-1ubuntu1), libzstd1 (= 1.5.7+dfsg-3), zlib1g (= 1:1.3.dfsg+really1.3.1-1ubuntu3)' \
        'Built-Using: mysql-community (= 8.4.11)' \
        'Section: database' \
        'Priority: optional' \
        'Description: Authenticated minimal Oracle MySQL client for BackupSheep' \
        > "$package_root/DEBIAN/control"; \
    printf '{"artifact":"%s.tar.xz","artifact_architecture":"%s","payload_root":"/opt/mysql","payload_sha256":"%s","mysql_sha256":"%s","mysqldump_sha256":"%s","signing_key_fingerprint":"BCA43417C3B485DD128EC6D4B7B3B788A8D3785C","source_archive_sha256":"%s","source_package":"mysql-community","source_signature_sha256":"%s","source_version":"8.4.11","vendor":"Oracle"}\n' \
        "$pkg" "$TARGETARCH" "$payload_sha256" "$mysql_sha256" \
        "$mysqldump_sha256" "$expected_archive_sha256" \
        "$expected_signature_sha256" \
        > "$package_root/usr/share/backupsheep/provenance/oracle-mysql-client.json"; \
    chmod 0444 \
        "$package_root/DEBIAN/control" \
        "$package_root/usr/share/backupsheep/provenance/oracle-mysql-client.json"; \
    package_archive="/mysql-client-debs/backupsheep-oracle-mysql-client_8.4.11+backupsheep1_${TARGETARCH}.deb"; \
    dpkg-deb --build --root-owner-group "$package_root" "$package_archive"; \
    test "$(dpkg-deb --field "$package_archive" Package)" = \
        "backupsheep-oracle-mysql-client"; \
    test "$(dpkg-deb --field "$package_archive" Version)" = \
        "8.4.11+backupsheep1"; \
    sha256sum "$package_archive" > /mysql-client-debs/SHA256SUMS; \
    sha256sum -c /mysql-client-debs/SHA256SUMS


# Ubuntu 26.04 supplies patched MariaDB and OpenSSH clients while retaining the
# glibc ABI required by the verified Oracle and PGDG artifacts. The base carries
# an unused Pebble binary; remove it in a networkless parent stage so neither the
# package-preparation stage nor the final runtime can accidentally inherit it.
FROM ubuntu:26.04@sha256:2260313b31c8c011cd2eebe728008efac1b3982be73eb71348ea2648d2c0e09b AS ubuntu-runtime-base

RUN --network=none set -eux; \
    rm -f /usr/bin/pebble; \
    test ! -e /usr/bin/pebble


# Resolve and download the exact Ubuntu runtime package closure against signed
# repository metadata. The final stage installs these .deb files with networking
# disabled, so a missing dependency or moved version fails closed.
FROM ubuntu-runtime-base AS ubuntu-runtime-packages

ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64|arm64) ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    install -d -m 0755 /runtime-debs/partial /extract-debs \
        /mariadb-dump-package/DEBIAN \
        /mariadb-dump-package/usr/bin \
        /mariadb-dump-package/usr/share/backupsheep/provenance; \
    apt-get update; \
    cd /extract-debs; \
    apt-get download "mariadb-client=1:11.8.6-5ubuntu0.1"; \
    mariadb_archive="$(find /extract-debs -maxdepth 1 -type f -name 'mariadb-client_*.deb' -print -quit)"; \
    test -n "$mariadb_archive"; \
    test "$(dpkg-deb --field "$mariadb_archive" Package)" = "mariadb-client"; \
    test "$(dpkg-deb --field "$mariadb_archive" Version)" = "1:11.8.6-5ubuntu0.1"; \
    mariadb_architecture="$(dpkg-deb --field "$mariadb_archive" Architecture)"; \
    case "$TARGETARCH:$mariadb_architecture" in \
        amd64:amd64|arm64:arm64) ;; \
        *) echo "MariaDB archive architecture mismatch." >&2; exit 1 ;; \
    esac; \
    dpkg-deb --fsys-tarfile "$mariadb_archive" \
        | tar -xOf - ./usr/bin/mariadb-dump \
        > /mariadb-dump-package/usr/bin/mariadb-dump; \
    chown root:root /mariadb-dump-package/usr/bin/mariadb-dump; \
    chmod 0555 /mariadb-dump-package/usr/bin/mariadb-dump; \
    mariadb_archive_sha256="$(sha256sum "$mariadb_archive" | awk '{print $1}')"; \
    mariadb_binary_sha256="$(sha256sum /mariadb-dump-package/usr/bin/mariadb-dump | awk '{print $1}')"; \
    printf '%s\n' \
        'Package: backupsheep-mariadb-dump' \
        'Version: 11.8.6-5ubuntu0.1+backupsheep1' \
        'Source: mariadb (1:11.8.6-5ubuntu0.1)' \
        "Architecture: ${mariadb_architecture}" \
        'Maintainer: BackupSheep Security <security@backupsheep.com>' \
        'Depends: libc6, libgcc-s1, libssl3t64 (= 3.5.5-1ubuntu3.4), libstdc++6, libzstd1 (= 1.5.7+dfsg-3), zlib1g (= 1:1.3.dfsg+really1.3.1-1ubuntu3)' \
        'Built-Using: mariadb (= 1:11.8.6-5ubuntu0.1)' \
        'Section: database' \
        'Priority: optional' \
        'Description: Authenticated minimal MariaDB dump client for BackupSheep' \
        > /mariadb-dump-package/DEBIAN/control; \
    printf '{"binary":"/usr/bin/mariadb-dump","binary_sha256":"%s","source_archive_sha256":"%s","source_binary_package":"mariadb-client","source_package":"mariadb","source_version":"1:11.8.6-5ubuntu0.1"}\n' \
        "$mariadb_binary_sha256" "$mariadb_archive_sha256" \
        > /mariadb-dump-package/usr/share/backupsheep/provenance/mariadb-dump.json; \
    chmod 0444 \
        /mariadb-dump-package/DEBIAN/control \
        /mariadb-dump-package/usr/share/backupsheep/provenance/mariadb-dump.json; \
    dpkg-deb --build --root-owner-group /mariadb-dump-package \
        "/runtime-debs/backupsheep-mariadb-dump_11.8.6-5ubuntu0.1+backupsheep1_${mariadb_architecture}.deb"; \
    test "$(dpkg-deb --field /runtime-debs/backupsheep-mariadb-dump_*.deb Package)" = "backupsheep-mariadb-dump"; \
    test "$(dpkg-deb --field /runtime-debs/backupsheep-mariadb-dump_*.deb Version)" = "11.8.6-5ubuntu0.1+backupsheep1"; \
    cd /; \
    DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends \
        -o Dir::Cache::archives=/runtime-debs \
        --download-only install \
        "bsdutils=1:2.41.3-3ubuntu2" \
        "ca-certificates=20260601~26.04.1" \
        "gzip=1.14-1~exp2ubuntu1.1" \
        "lftp=4.9.3-1.1ubuntu2" \
        "libaio1t64=0.3.113-8build1" \
        "libbz2-1.0=1.0.8-6build2" \
        "libcap2=1:2.75-10ubuntu2" \
        "libc6=2.43-2ubuntu2.3" \
        "libdb5.3t64=5.3.28+dfsg2-10ubuntu1" \
        "libexpat1=2.7.4-1" \
        "libffi8=3.5.2-4" \
        "libgcc-s1=16-20260322-1ubuntu1" \
        "libgdbm-compat4t64=1.26-1build1" \
        "libgdbm6t64=1.26-1build1" \
        "liblzma5=5.8.3-1" \
        "libmariadb3=1:11.8.6-5ubuntu0.1" \
        "libncurses6=6.6+20251231-1" \
        "libncursesw6=6.6+20251231-1" \
        "libnuma1=2.0.19-1build1" \
        "libpq5=18.6-0ubuntu0.26.04.1" \
        "libreadline8t64=8.3-4" \
        "libsqlite3-0=3.46.1-9ubuntu0.2" \
        "libssl3t64=3.5.5-1ubuntu3.4" \
        "libstdc++6=16-20260322-1ubuntu1" \
        "libuuid1=2.41.3-3ubuntu2" \
        "libzstd1=1.5.7+dfsg-3" \
        "login=1:4.16.0-2+really2.41.3-3ubuntu2" \
        "mariadb-client-core=1:11.8.6-5ubuntu0.1" \
        "mariadb-common=1:11.8.6-5ubuntu0.1" \
        "mount=2.41.3-3ubuntu2" \
        "mysql-common=5.8+1.1.1ubuntu2" \
        "netbase=6.5build1" \
        "openssh-client=1:10.2p1-2ubuntu3.5" \
        "openssl=3.5.5-1ubuntu3.4" \
        "openssl-provider-legacy=3.5.5-1ubuntu3.4" \
        "passwd=1:4.17.4-2ubuntu3" \
        "tree=2.3.1-1" \
        "tzdata=2026c-0ubuntu0.26.04.1" \
        "unzip=6.0-29ubuntu1" \
        "util-linux=2.41.3-3ubuntu2" \
        "zip=3.0-15ubuntu3" \
        "zlib1g=1:1.3.dfsg+really1.3.1-1ubuntu3"; \
    find /runtime-debs -maxdepth 1 -type f -name '*.deb' -print -quit | grep -q .; \
    find /runtime-debs -maxdepth 1 -type f -name '*.deb' -print0 \
        | sort -z \
        | xargs -0 sha256sum > /runtime-debs/SHA256SUMS; \
    sha256sum -c /runtime-debs/SHA256SUMS; \
    rm -rf /runtime-debs/partial /runtime-debs/lock \
        /extract-debs /mariadb-dump-package /var/lib/apt/lists/*


FROM ubuntu-runtime-base AS runtime

COPY --from=python-runtime /usr/local /usr/local

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_NO_INPUT=1 \
    PIP_CONFIG_FILE=/dev/null \
    HOME=/run/backupsheep \
    XDG_CACHE_HOME=/run/backupsheep/cache \
    XDG_CONFIG_HOME=/run/backupsheep/config \
    TMPDIR=/tmp \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

LABEL org.opencontainers.image.title="BackupSheep" \
      org.opencontainers.image.description="Self-hosted backup orchestration" \
      org.opencontainers.image.source="https://github.com/bilal414/backupsheep" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# Install the authenticated Ubuntu closure and all minimal database-client
# packages offline. The custom packages make upstream source identities, exact
# source/payload hashes and executable ownership visible to dpkg and SBOM tools.
RUN --network=none \
    --mount=from=ubuntu-runtime-packages,source=/runtime-debs,target=/runtime-debs,ro \
    --mount=from=postgres-clients,source=/postgres-client-debs,target=/postgres-client-debs,ro \
    --mount=from=mysql-client,source=/mysql-client-debs,target=/mysql-client-debs,ro \
    set -eux; \
    sha256sum -c /runtime-debs/SHA256SUMS; \
    sha256sum -c /postgres-client-debs/SHA256SUMS; \
    sha256sum -c /mysql-client-debs/SHA256SUMS; \
    dpkg --unpack \
        /runtime-debs/*.deb \
        /postgres-client-debs/*.deb \
        /mysql-client-debs/*.deb; \
    DEBIAN_FRONTEND=noninteractive dpkg --configure --pending; \
    dpkg --purge --force-remove-essential perl-base; \
    dpkg --audit; \
    assert_package() { \
        test "$(dpkg-query -W -f='${Version}' "$1")" = "$2"; \
    }; \
    assert_source() { \
        test "$(dpkg-query -W -f='${source:Package} ${source:Version}' "$1")" = "$2 $3"; \
    }; \
    assert_owner() { \
        test "$(dpkg-query -S "$2" | cut -d: -f1)" = "$1"; \
    }; \
    assert_package backupsheep-mariadb-dump 11.8.6-5ubuntu0.1+backupsheep1; \
    assert_source backupsheep-mariadb-dump mariadb 1:11.8.6-5ubuntu0.1; \
    assert_package backupsheep-oracle-mysql-client 8.4.11+backupsheep1; \
    assert_source backupsheep-oracle-mysql-client mysql-community 8.4.11; \
    assert_package libmariadb3 1:11.8.6-5ubuntu0.1; \
    assert_package libpq5 18.6-0ubuntu0.26.04.1; \
    assert_package libssl3t64 3.5.5-1ubuntu3.4; \
    assert_package mariadb-client-core 1:11.8.6-5ubuntu0.1; \
    assert_package openssh-client 1:10.2p1-2ubuntu3.5; \
    assert_package openssl 3.5.5-1ubuntu3.4; \
    assert_package openssl-provider-legacy 3.5.5-1ubuntu3.4; \
    assert_package tzdata 2026c-0ubuntu0.26.04.1; \
    test ! -e /usr/bin/pebble; \
    test ! -e /usr/bin/perl; \
    if dpkg-query -W perl-base >/dev/null 2>&1; then \
        echo "Perl survived runtime minimization." >&2; \
        exit 1; \
    fi; \
    test -r /usr/share/backupsheep/provenance/mariadb-dump.json; \
    mariadb_binary_sha256="$(sha256sum /usr/bin/mariadb-dump | awk '{print $1}')"; \
    grep -Fq "\"binary_sha256\":\"${mariadb_binary_sha256}\"" \
        /usr/share/backupsheep/provenance/mariadb-dump.json; \
    assert_owner backupsheep-mariadb-dump /usr/bin/mariadb-dump; \
    for metadata in \
        "14 14.24-1.pgdg13+2 2a17bc01dd3c4345d4ac85b084a11d7fb74265aead805e75cf0a296552f0f42e 4ac24008059ecc1993d9a944648ed36d0730b95d01f6a3522407795b2d00a47f 61983f6ae42ee31c3e3477cfed77d7a42c58956e7abbfeed06e4c6e176042454 65a052e5e9563563d2a502f58066c9bb074e4ef63ef2c321bcfba97ab4a15c0b" \
        "15 15.19-1.pgdg13+2 718b5a25eb99db5ee37b165ebeeefea50ecf993c9cde1db26eb401e6bbe0be08 29b55286e8de51c79ad317968e03d7a311c66c101e8536e2b635d860da3648af ec63ed182c6f3719e6b820bdf44a854597574af0a683d1a49e3cc81f68e3d855 0f4126aaa556bf544961f8e20fd2a9926a872f9afdf09924b32bc548231ca760" \
        "16 16.15-1.pgdg13+2 82e1dfb1c8f6aed02811c43bff4ead374343ebafe61bca9af3662fc75a83a4b7 98f1b6ea41235282173901ef49dfb7b4c254810e9e23a2f2b3aeb758aedd2604 3c2bff97c4547d2106e2fd0f9ba2738d1d0a217baf84ea228f1d411d1f0fa620 5964afee95ca55cd1816cb725d0289fba0c6f42159edc5f139676500f1a2157f" \
        "17 17.11-1.pgdg13+2 c36408bb62178bc9193c113da65e30fc6a5237648de5e9db1ea594214df9ae4b 706c9fde003d98ff423a3d73bd5ac1115379481cb86daabf251e02f240d660d3 e2ca95d99073796d6dc4578282cd1f1789f81507b17c97158f024ef05d43eff0 e9fe0d1133b2cd6db2447a8ccc7e92794ca98572909de790a7ec8509cc929877" \
        "18 18.6-1.pgdg13+2 9af40c99f7074f8ff3798155af2f07f1a4e1e3bd4edce44ef928c1e03aea620e 098492efc9f576ffee23e1871d31682b332a3c6582072d3ef8f99b6b72573bc7 17e395f57433689ac3f8ed6cbeb631cf91dbb4e21d10573d4cc7b7f1f36a8f4b 1ac98a12bb3d68cf67413cfa68bc4f96e658eb8bdc88fa43b0a1dd6207c78473"; do \
        set -- $metadata; \
        pg_major="$1"; \
        pg_version="$2"; \
        case "$(dpkg --print-architecture)" in \
            amd64) expected_archive_sha256="$3"; expected_payload_sha256="$5" ;; \
            arm64) expected_archive_sha256="$4"; expected_payload_sha256="$6" ;; \
            *) echo "Unsupported runtime architecture." >&2; exit 1 ;; \
        esac; \
        package="backupsheep-postgresql-client-${pg_major}"; \
        assert_package "$package" "${pg_version}+backupsheep1"; \
        assert_source "$package" "postgresql-${pg_major}" "$pg_version"; \
        provenance="/usr/share/backupsheep/provenance/postgresql-client-${pg_major}.json"; \
        test -r "$provenance"; \
        grep -Fq "\"source_archive_sha256\":\"${expected_archive_sha256}\"" "$provenance"; \
        grep -Fq "\"payload_sha256\":\"${expected_payload_sha256}\"" "$provenance"; \
        payload_sha256="$(cd "/usr/lib/postgresql/${pg_major}" \
            && find . -type f -print0 \
                | LC_ALL=C sort -z \
                | xargs -0 sha256sum \
                | sha256sum \
                | awk '{print $1}')"; \
        test "$payload_sha256" = "$expected_payload_sha256"; \
        for executable in pg_dump pg_restore psql; do \
            assert_owner "$package" "/usr/lib/postgresql/${pg_major}/bin/${executable}"; \
        done; \
        pg_dump_sha256="$(sha256sum "/usr/lib/postgresql/${pg_major}/bin/pg_dump" | awk '{print $1}')"; \
        psql_sha256="$(sha256sum "/usr/lib/postgresql/${pg_major}/bin/psql" | awk '{print $1}')"; \
        grep -Fq "\"pg_dump_sha256\":\"${pg_dump_sha256}\"" "$provenance"; \
        grep -Fq "\"psql_sha256\":\"${psql_sha256}\"" "$provenance"; \
    done; \
    oracle_provenance=/usr/share/backupsheep/provenance/oracle-mysql-client.json; \
    case "$(dpkg --print-architecture)" in \
        amd64) \
            expected_oracle_archive_sha256=94e204cc94dede3746d2773fa5818f28f555cd8368c75ca0612eac124e6f3e58; \
            expected_oracle_signature_sha256=23bcbef86b5125deceef25726a39f165094448c48e5263ba8e8fd89a90f9c17a; \
            expected_oracle_payload_sha256=91f3d13d4d651794a4f746d9503605641d129cf700a7abaa6793768851383346 \
            ;; \
        arm64) \
            expected_oracle_archive_sha256=04b2f9791d314167a9eb83abcb476f45a7cd9e4aa88fa7a638cba40d1bc2a109; \
            expected_oracle_signature_sha256=81fe648f43050d3af5e5f3d5a2b915a5c60c8f04141eafeb34047e75295ee9a1; \
            expected_oracle_payload_sha256=b019990ef3b06aff37c9e7e6c7739cc73fed13de591cacc22f40b010be075a09 \
            ;; \
        *) echo "Unsupported runtime architecture." >&2; exit 1 ;; \
    esac; \
    test -r "$oracle_provenance"; \
    grep -Fq "\"source_archive_sha256\":\"${expected_oracle_archive_sha256}\"" "$oracle_provenance"; \
    grep -Fq "\"source_signature_sha256\":\"${expected_oracle_signature_sha256}\"" "$oracle_provenance"; \
    grep -Fq "\"payload_sha256\":\"${expected_oracle_payload_sha256}\"" "$oracle_provenance"; \
    oracle_payload_sha256="$(cd /opt/mysql \
        && find . -type f -print0 \
            | LC_ALL=C sort -z \
            | xargs -0 sha256sum \
            | sha256sum \
            | awk '{print $1}')"; \
    test "$oracle_payload_sha256" = "$expected_oracle_payload_sha256"; \
    for executable in mysql mysqldump; do \
        assert_owner backupsheep-oracle-mysql-client "/opt/mysql/bin/${executable}"; \
        executable_sha256="$(sha256sum "/opt/mysql/bin/${executable}" | awk '{print $1}')"; \
        grep -Fq "\"${executable}_sha256\":\"${executable_sha256}\"" "$oracle_provenance"; \
    done; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*; \
    python3.14 --version; \
    python3.14 -c 'import bz2,ctypes,curses,dbm.gnu,decimal,lzma,readline,sqlite3,ssl,uuid,zlib'; \
    for version in 14 15 16 17 18; do \
        "/usr/lib/postgresql/${version}/bin/pg_dump" --version; \
        "/usr/lib/postgresql/${version}/bin/psql" --version; \
    done; \
    mariadb --version; \
    mariadb-dump --version; \
    lftp --version; \
    ssh -V; \
    tree --version; \
    unzip -v >/dev/null; \
    zip -v >/dev/null; \
    /opt/mysql/bin/mysql --version; \
    /opt/mysql/bin/mysqldump --version

# pip is a build/install tool, not an application runtime dependency. Its
# vendored package set is otherwise a second, hidden dependency tree that can
# retain fixed vulnerabilities after the application lock is updated.
# Setuptools also ships Windows-only PE launchers. They cannot execute in this
# Linux image, are not part of BackupSheep's runtime, and otherwise appear as
# anonymous binary packages in the SBOM. Remove only the reviewed launcher set
# and fail the build if its contents change or another PE launcher appears.
RUN --mount=from=python-wheels,source=/wheels,target=/wheels,ro \
    python -m pip --isolated install \
        --no-cache-dir \
        --no-index \
        --find-links=/wheels \
        --require-hashes \
        --requirement=/wheels/requirements.runtime.lock \
    && python -m pip --isolated check \
    && rm -rf \
        /usr/local/lib/python3.14/site-packages/pip \
        /usr/local/lib/python3.14/site-packages/pip-*.dist-info \
        /usr/local/bin/pip \
        /usr/local/bin/pip3 \
        /usr/local/bin/pip3.14 \
    && for launcher in \
        cli.exe cli-32.exe cli-64.exe cli-arm64.exe \
        gui.exe gui-32.exe gui-64.exe gui-arm64.exe; do \
        launcher_path="/usr/local/lib/python3.14/site-packages/setuptools/${launcher}"; \
        test -f "$launcher_path"; \
        rm -- "$launcher_path"; \
    done \
    && test ! -e /usr/local/lib/python3.14/site-packages/pip \
    && test -z "$(find /usr/local/bin -maxdepth 1 -type f -name 'pip*' -print -quit)" \
    && test -z "$(find /usr/local/lib/python3.14/site-packages/setuptools \
        -type f -name '*.exe' -print -quit)"

RUN groupadd --gid 10001 backupsheep \
    && groupadd --gid 10002 backupsheep-database \
    && groupadd --gid 10003 backupsheep-files \
    && groupadd --gid 10004 backupsheep-storage \
    && groupadd --gid 10005 backupsheep-logs \
    && groupadd --gid 10006 backupsheep-beat \
    && groupadd --gid 10007 backupsheep-migration \
    && groupadd --gid 10008 backupsheep-cloud \
    && groupadd --gid 10989 backupsheep-db-xfer-w \
    && groupadd --gid 10990 backupsheep-db-xfer-r \
    && groupadd --gid 10991 backupsheep-file-xfer-w \
    && groupadd --gid 10992 backupsheep-file-xfer-r \
    && groupadd --gid 10993 backupsheep-rst-files \
    && groupadd --gid 10994 backupsheep-rst-database \
    && groupadd --gid 10995 backupsheep-rst-writer \
    && useradd --uid 10001 --gid 10001 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep \
    && useradd --uid 10002 --gid 10002 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep-database \
    && useradd --uid 10003 --gid 10003 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep-files \
    && useradd --uid 10004 --gid 10004 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep-storage \
    && useradd --uid 10005 --gid 10005 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep-logs \
    && useradd --uid 10006 --gid 10006 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep-beat \
    && useradd --uid 10007 --gid 10007 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep-migration \
    && useradd --uid 10008 --gid 10008 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep-cloud \
    && install -d -o backupsheep -g backupsheep -m 0700 \
        /run/backupsheep \
    && install -d -o root -g root -m 0555 /code/_storage \
    && install -d -o backupsheep-storage -g backupsheep-storage -m 0700 /backups \
    && install -d -o root -g root -m 0555 /var/lib/backupsheep/transfer \
    && install -d -o root -g backupsheep-db-xfer-w -m 3771 \
        /var/lib/backupsheep/transfer/database \
    && install -d -o root -g backupsheep-file-xfer-w -m 3771 \
        /var/lib/backupsheep/transfer/files \
    && install -d -o root -g backupsheep-rst-writer -m 3771 \
        /var/lib/backupsheep/restore-transfer \
    && install -d -o root -g root -m 0555 /run/backupsheep-installation \
    && install -d -o backupsheep -g backupsheep -m 0700 /code/static

WORKDIR /code

# The build context is allowlisted by .dockerignore and the runtime layer copies
# only application inputs. Keeping tests, docs, Git metadata, installer scripts,
# and arbitrary checkout files out of this layer both reduces attack surface and
# prevents forgotten host credentials from surviving in image history.
COPY --link --chown=0:0 --chmod=0444 .env_sample manage.py /code/
COPY --link --chown=0:0 apps /code/apps
COPY --link --chown=0:0 backupsheep /code/backupsheep
COPY --link --chown=0:0 utils /code/utils
COPY --link --chown=0:0 --chmod=0444 scripts/release_transition.py /usr/local/lib/backupsheep-release/
COPY --link --chown=0:0 --chmod=0555 init.sh /usr/local/bin/init.sh
COPY --link --chown=0:0 --chmod=0555 deploy/staging/provision-volumes.sh /usr/local/bin/backupsheep-provision-staging-volumes
COPY --link --chown=0:0 --chmod=0555 deploy/egress/workload-healthcheck.py /usr/local/bin/backupsheep-egress-workload-healthcheck

# Git records executability, not the complete checkout mode. A source tree created
# under umask 0077 therefore reaches BuildKit with mode-0600 modules and mode-0700
# packages. Normalize the copied inputs before the first unprivileged import. Keep
# the empty static destination private and writable only for the collectstatic step;
# the final hardening layer below makes its generated contents immutable.
RUN set -eux; \
    if find /code -xdev -type l -print -quit | grep -q .; then \
        echo "Refusing symlinks in the runtime application inputs." >&2; \
        exit 1; \
    fi; \
    test -z "$(find /code/static -mindepth 1 -print -quit)"; \
    find /code -xdev \
        \( -path /code/_storage -o -path /code/static \) -prune -o \
        -type d -exec chmod 0555 {} +; \
    find /code -xdev \
        \( -path /code/_storage -o -path /code/static \) -prune -o \
        -type f -exec chmod 0444 {} +; \
    install -d -o backupsheep -g backupsheep -m 0700 /code/static

# Collect static assets as the final unprivileged identity. The step has no
# network and uses only explicitly non-production placeholder configuration, so
# a build cannot depend on a live database or leak an operator's runtime secret.
# Static files then become part of the immutable image rather than a startup
# write, which allows every application role to use a read-only root filesystem.
USER 10001:10001
RUN --network=none \
    --mount=type=tmpfs,target=/code/_storage \
    DJANGO_SERVER=test \
    DJANGO_DEBUG=false \
    DJANGO_SECRET_KEY=build-only-placeholder-not-a-runtime-secret \
    BACKUPSHEEP_ARTIFACT_ENCRYPTION_MODE=legacy-only \
    BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=false \
    python manage.py collectstatic --noinput --clear \
    && test -n "$(find /code/static -type f -print -quit)"

USER 0:0

# Git records only the executable bit, so a checkout created under a restrictive
# umask can otherwise make modules unreadable to UID 10001. Normalize application
# inputs to root-owned, read-only files. Fail on links instead of allowing a
# malicious build context to redirect imports or generated assets elsewhere.
# Mode normalization also copies linked BuildKit snapshots up into this layer;
# any hard link that remains after that is an alias inside the runtime tree and
# is rejected.
# Also clear every setuid/setgid bit in the final filesystem: no image workload
# needs privilege transitions, even if an operator forgets no-new-privileges.
RUN set -eux; \
    if find /code -xdev -type l -print -quit | grep -q .; then \
        echo "Refusing symlinks in the runtime application tree." >&2; \
        exit 1; \
    fi; \
    chown -R 0:0 /code/static; \
    find /code -xdev -path /code/_storage -prune -o -type d -exec chmod 0555 {} +; \
    find /code -xdev -path /code/_storage -prune -o -type f -exec chmod 0444 {} +; \
    if find /code -xdev -type f -links +1 -print -quit | grep -q .; then \
        echo "Refusing hard-linked files in the runtime application tree." >&2; \
        exit 1; \
    fi; \
    install -d -o backupsheep -g backupsheep -m 0700 /run/backupsheep; \
    install -d -o root -g root -m 0555 /code/_storage; \
    install -d -o backupsheep-storage -g backupsheep-storage -m 0700 /backups; \
    install -d -o root -g root -m 0555 /var/lib/backupsheep/transfer; \
    install -d -o root -g backupsheep-db-xfer-w -m 3771 \
        /var/lib/backupsheep/transfer/database; \
    install -d -o root -g backupsheep-file-xfer-w -m 3771 \
        /var/lib/backupsheep/transfer/files; \
    install -d -o root -g backupsheep-rst-writer -m 3771 \
        /var/lib/backupsheep/restore-transfer; \
    find / -xdev -type f -perm /6000 -exec chmod a-s {} +; \
    if find / -xdev -type f -perm /6000 -print -quit | grep -q .; then \
        echo "Setuid/setgid file survived runtime-image hardening." >&2; \
        exit 1; \
    fi

EXPOSE 8000
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/init.sh"]
