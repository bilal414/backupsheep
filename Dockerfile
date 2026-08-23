# syntax=docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

# Self-hosted BackupSheep image, shared by the web, Celery worker, and beat
# services. Native compilation, repository tooling, and archive verification stay
# in disposable builder stages. The final stage starts from the digest-pinned slim
# image and receives only offline wheels, authenticated runtime Debian packages,
# and the two signature-verified Oracle MySQL client binaries.

FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS python-wheels

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
FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS repository-metadata

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
FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime-packages

ARG TARGETARCH
COPY --from=repository-metadata /repository/pgdg.gpg /usr/share/keyrings/pgdg.gpg
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) lftp_version="4.9.2-3+b1" ;; \
        arm64) lftp_version="4.9.2-3" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt trixie-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && install -d -m 0755 /runtime-debs/partial /extract-debs \
        /runtime-extras/postgresql /runtime-extras/bin \
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
    && for archive in /extract-debs/postgresql-client-*.deb; do \
        dpkg-deb --extract "$archive" /runtime-extras/postgresql; \
    done \
    && apt-get download "mariadb-client=1:11.8.6-0+deb13u1" \
    && dpkg-deb --extract /extract-debs/mariadb-client_*.deb /extract-debs/mariadb \
    && install -m 0555 /extract-debs/mariadb/usr/bin/mariadb-dump \
        /runtime-extras/bin/mariadb-dump \
    && cd / \
    && apt-get -y --no-install-recommends \
        -o Dir::Cache::archives=/runtime-debs \
        --download-only install \
        "ca-certificates=20250419" \
        "lftp=${lftp_version}" \
        "libaio1t64=0.3.113-8+b1" \
        "libncurses6=6.5+20250216-2" \
        "libnuma1=2.0.19-1" \
        "libpq5=18.6-1.pgdg13+2" \
        "mariadb-client-core=1:11.8.6-0+deb13u1" \
        "openssh-client=1:10.0p1-7+deb13u4" \
        "tree=2.2.1-1" \
        "unzip=6.0-29+deb13u1" \
        "zip=3.0-15+deb13u1" \
    && find /runtime-debs -maxdepth 1 -type f -name '*.deb' -print -quit \
        | grep -q . \
    && rm -rf /runtime-debs/partial /runtime-debs/lock /extract-debs \
        /var/lib/apt/lists/*


# Oracle MySQL's APT repository does not publish arm64 clients. Extract the two
# required tools from the versioned upstream generic bundle after validating the
# signing key checksum, key fingerprint, and detached artifact signature.
FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS mysql-client

ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg libaio1t64 libncurses6 libnuma1 xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) mysql_arch="x86_64" ;; \
        arm64) mysql_arch="aarch64" ;; \
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
    gpg --batch --verify /tmp/mysql-client.tar.xz.asc /tmp/mysql-client.tar.xz; \
    install -d -m 0755 /mysql/bin /tmp/mysql-client; \
    tar -xJf /tmp/mysql-client.tar.xz -C /tmp/mysql-client \
        "${pkg}/bin/mysql" "${pkg}/bin/mysqldump"; \
    install -m 0755 "/tmp/mysql-client/${pkg}/bin/mysql" /mysql/bin/mysql; \
    install -m 0755 "/tmp/mysql-client/${pkg}/bin/mysqldump" /mysql/bin/mysqldump; \
    /mysql/bin/mysql --version; \
    /mysql/bin/mysqldump --version


FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime

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

# Install the authenticated package closure offline. Unpack all packages before
# configuration so dependency ordering cannot trigger a network repair attempt.
RUN --mount=from=runtime-packages,source=/runtime-debs,target=/runtime-debs,ro \
    --mount=from=runtime-packages,source=/runtime-extras,target=/runtime-extras,ro \
    set -eux; \
    dpkg --unpack /runtime-debs/*.deb; \
    dpkg --configure --pending; \
    dpkg --audit; \
    cp -a /runtime-extras/postgresql/usr/lib/postgresql /usr/lib/; \
    install -o root -g root -m 0555 /runtime-extras/bin/mariadb-dump \
        /usr/bin/mariadb-dump; \
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
    python -m pip --isolated install \
        --no-cache-dir \
        --no-index \
        --find-links=/wheels \
        --require-hashes \
        --requirement=/wheels/requirements.runtime.lock \
    && python -m pip --isolated check

RUN groupadd --gid 10001 backupsheep \
    && useradd --uid 10001 --gid 10001 \
        --home-dir /run/backupsheep --no-create-home \
        --shell /usr/sbin/nologin backupsheep \
    && install -d -o backupsheep -g backupsheep -m 0700 \
        /run/backupsheep /code/_storage /backups \
        /var/lib/backupsheep/ssh-trust \
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
COPY --link --chown=0:0 --chmod=0555 init.sh /usr/local/bin/init.sh

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
    install -d -o backupsheep -g backupsheep -m 0700 \
        /run/backupsheep /code/_storage /backups \
        /var/lib/backupsheep/ssh-trust; \
    find / -xdev -type f -perm /6000 -exec chmod a-s {} +; \
    if find / -xdev -type f -perm /6000 -print -quit | grep -q .; then \
        echo "Setuid/setgid file survived runtime-image hardening." >&2; \
        exit 1; \
    fi

EXPOSE 8000
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/init.sh"]
