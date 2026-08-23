# syntax=docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

# Self-hosted BackupSheep image, shared by the web, Celery worker, and beat
# services. Native compilation, repository tooling, and archive verification stay
# in disposable builder stages. The final stage starts from the digest-pinned slim
# image and receives only offline wheels, authenticated runtime Debian packages,
# and the two signature-verified Oracle MySQL client binaries.

FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS python-wheels

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

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
COPY requirements.txt /build/requirements.txt
RUN python -m pip wheel \
        --wheel-dir=/wheels \
        --requirement=/build/requirements.txt


# Produce the PGDG keyring in an isolated stage. Both the downloaded key bytes
# and its OpenPGP primary fingerprint are pinned before it is trusted by APT.
FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS repository-metadata

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


# Download the exact runtime package set and its dependency closure while APT
# still has the signed Debian/PGDG indexes. The final stage installs these local
# .deb files without repository metadata or network access.
FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS runtime-packages

ARG TARGETARCH
COPY --from=repository-metadata /repository/pgdg.gpg /usr/share/keyrings/pgdg.gpg
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) lftp_version="4.9.2-2+b1" ;; \
        arm64) lftp_version="4.9.2-2" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && install -d -m 0755 /runtime-debs/partial \
    && apt-get update \
    && apt-get -y --no-install-recommends \
        -o Dir::Cache::archives=/runtime-debs \
        --download-only install \
        "ca-certificates=20250419~deb12u1" \
        "lftp=${lftp_version}" \
        "libaio1=0.3.113-4" \
        "libncurses6=6.4-4" \
        "libnuma1=2.0.16-1" \
        "mariadb-client=1:10.11.18-0+deb12u1" \
        "openssh-client=1:9.2p1-2+deb12u10" \
        "postgresql-client-14=14.24-1.pgdg12+2" \
        "postgresql-client-15=15.19-1.pgdg12+2" \
        "postgresql-client-16=16.15-1.pgdg12+2" \
        "postgresql-client-17=17.11-1.pgdg12+2" \
        "postgresql-client-18=18.6-1.pgdg12+2" \
        "tree=2.1.0-1" \
        "unzip=6.0-28+deb12u1" \
        "zip=3.0-13" \
    && find /runtime-debs -maxdepth 1 -type f -name '*.deb' -print -quit \
        | grep -q . \
    && rm -rf /runtime-debs/partial /runtime-debs/lock /var/lib/apt/lists/*


# Oracle MySQL's APT repository does not publish arm64 clients. Extract the two
# required tools from the versioned upstream generic bundle after validating the
# signing key checksum, key fingerprint, and detached artifact signature.
FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS mysql-client

ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg libaio1 libncurses6 libnuma1 xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) mysql_arch="x86_64" ;; \
        arm64) mysql_arch="aarch64" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    mysql_version="8.4.10"; \
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
    gpg --batch --verify /tmp/mysql-client.tar.xz.asc /tmp/mysql-client.tar.xz; \
    install -d -m 0755 /mysql/bin /tmp/mysql-client; \
    tar -xJf /tmp/mysql-client.tar.xz -C /tmp/mysql-client \
        "${pkg}/bin/mysql" "${pkg}/bin/mysqldump"; \
    install -m 0755 "/tmp/mysql-client/${pkg}/bin/mysql" /mysql/bin/mysql; \
    install -m 0755 "/tmp/mysql-client/${pkg}/bin/mysqldump" /mysql/bin/mysqldump; \
    /mysql/bin/mysql --version; \
    /mysql/bin/mysqldump --version


FROM python:3.14.7-slim-bookworm@sha256:23c59390fc717bf09f9336908199a0ae75d9c4264bf296123f94ad772fea3b52 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/backupsheep

# Install the authenticated package closure offline. Unpack all packages before
# configuration so dependency ordering cannot trigger a network repair attempt.
RUN --mount=from=runtime-packages,source=/runtime-debs,target=/runtime-debs,ro \
    set -eux; \
    dpkg --unpack /runtime-debs/*.deb; \
    dpkg --configure --pending; \
    dpkg --audit; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*; \
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
    zip -v >/dev/null

COPY --from=mysql-client /mysql /opt/mysql
RUN /opt/mysql/bin/mysql --version \
    && /opt/mysql/bin/mysqldump --version

RUN --mount=from=python-wheels,source=/wheels,target=/wheels,ro \
    --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt,ro \
    python -m pip install \
        --no-cache-dir \
        --no-index \
        --find-links=/wheels \
        --requirement=/tmp/requirements.txt \
    && python -m pip check

WORKDIR /code
COPY . /code/

# A production checkout may be created by root under a restrictive umask. Git
# records only the executable bit, so COPY can otherwise preserve mode-0600
# modules that the non-root runtime cannot import. Normalize the immutable code
# tree explicitly; writable runtime paths are created for UID 10001 below.
RUN find /code -type d -exec chmod 0755 {} + \
    && find /code -type f -exec chmod 0644 {} + \
    && chmod 0755 /code/install.sh

COPY init.sh /usr/local/bin/init.sh
RUN groupadd --gid 10001 backupsheep \
    && useradd --uid 10001 --gid 10001 \
        --home-dir /home/backupsheep --create-home \
        --shell /usr/sbin/nologin backupsheep \
    && install -d -o backupsheep -g backupsheep -m 0700 \
        /code/_storage /backups \
    && install -d -o backupsheep -g backupsheep -m 0755 /code/static \
    && chmod 0755 /usr/local/bin/init.sh

EXPOSE 8000
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/init.sh"]
