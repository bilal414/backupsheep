# Self-hosted BackupSheep image, shared by the web, Celery worker, and beat services
# (docker-compose runs each from this one image with a different command).
# Built in one step by docker-compose; no separate base image to build first.
#
# The web service runs gunicorn on port 8000 (static files via WhiteNoise); run it
# behind your own TLS-terminating reverse proxy for production HTTPS.
#
# System packages below provide the backup tooling the worker shells out to:
#   - lftp .................. FTP/FTPS storage transfers
#   - mariadb-client ........ mariadb-dump / mysqldump for MariaDB backups
#   - mysql (8.4) ........... Oracle MySQL client in /opt/mysql/bin for MySQL backups
#   - postgresql-client-14..18  version-matched pg_dump (CoreAuthDatabase.bin_path)
#   - gunicorn .............. WSGI server for the web service
FROM python:3.14.7-bookworm@sha256:8771427e2ac3e39208c1632f17e8b09e464333d262844a03705cc5e0023c16e2

# set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get -y install --no-install-recommends libpq-dev gcc software-properties-common gnupg2 python3-dev musl-dev git g++-11 postgresql-server-dev-all \
    && apt-get -y install --no-install-recommends ca-certificates curl dirmngr \
    && curl -fsSL https://r.mariadb.com/downloads/mariadb_repo_setup -o /tmp/mariadb_repo_setup \
    && echo "7325ac7755809ca3312b446bd832542421699298f25b701f9a111bb42df0c7c1  /tmp/mariadb_repo_setup" | sha256sum -c - \
    && bash /tmp/mariadb_repo_setup \
    && rm -f /tmp/mariadb_repo_setup \
    && apt-get update \
    && apt-get -y install --no-install-recommends mariadb-client \
    && apt-get -y install --no-install-recommends tree build-essential libffi-dev libpq-dev python3-dev libjpeg-dev zip unzip libmysqlclient-dev g++ libzmq3-dev gcc \
    && apt-get -y install --no-install-recommends libssl-dev libxml2-dev libxslt1-dev libcurl4-openssl-dev unixodbc unixodbc-dev libsqlite3-dev ncurses-dev libexpat1-dev \
    && apt-get -y install --no-install-recommends pkg-config libreadline6-dev zlib1g-dev autoconf automake libtool \
    && apt-get -y install --no-install-recommends libncurses-dev libgnutls28-dev libreadline-dev libfreetype6-dev \
    && apt-get -y install --no-install-recommends tzdata lftp \
    && rm -rf /var/lib/apt/lists/*

# PostgreSQL client tools (pg_dump / psql / pg_restore) for versions 14-18 from the
# PGDG apt repo, installed side-by-side under /usr/lib/postgresql/<N>/bin. Database
# backups select the exact pg_dump for the target server's version (CoreAuthDatabase.bin_path).
# MariaDB clients (mariadb-dump / mysqldump) come from the mariadb-server install above.
RUN install -d /usr/share/postgresql-common/pgdg \
    && curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get -y install --no-install-recommends postgresql-client-14 postgresql-client-15 postgresql-client-16 postgresql-client-17 postgresql-client-18 \
    && rm -rf /var/lib/apt/lists/*

# Oracle MySQL 8.4 LTS client tools (mysql / mysqldump) for MySQL targets, shipped in
# /opt/mysql/bin (CoreAuthDatabase.bin_path prefers them there; the MariaDB client stays
# untouched in /usr/bin for MariaDB targets). The MySQL apt repo (mysql-apt-config) only
# ships x86 packages, so the official glibc2.28 "Linux - Generic" tarball is used instead
# -- it covers both x86_64 and aarch64. Only the two binaries are kept; they run against
# the stock bookworm system libraries, so /opt/mysql/bin is self-contained.
RUN set -eux; \
    case "$(uname -m)" in \
        x86_64) mysql_arch="x86_64" ;; \
        aarch64) mysql_arch="aarch64" ;; \
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    pkg="mysql-8.4.10-linux-glibc2.28-${mysql_arch}"; \
    mysql_key_fingerprint="BCA43417C3B485DD128EC6D4B7B3B788A8D3785C"; \
    export GNUPGHOME=/tmp/mysql-gnupg; \
    install -d -m 0700 "$GNUPGHOME"; \
    curl -fsSL -o /tmp/mysql-build-key.asc "https://repo.mysql.com/RPM-GPG-KEY-mysql-2025"; \
    actual_fingerprint="$(gpg --batch --with-colons --import-options show-only --import /tmp/mysql-build-key.asc | awk -F: '$1 == "fpr" { print $10; exit }')"; \
    test "$actual_fingerprint" = "$mysql_key_fingerprint"; \
    gpg --batch --import /tmp/mysql-build-key.asc; \
    curl -fsSL -o /tmp/mysql-client.tar.xz "https://dev.mysql.com/get/Downloads/MySQL-8.4/${pkg}.tar.xz"; \
    curl -fsSL -o /tmp/mysql-client.tar.xz.asc "https://cdn.mysql.com/Downloads/MySQL-8.4/${pkg}.tar.xz.asc"; \
    gpg --batch --verify /tmp/mysql-client.tar.xz.asc /tmp/mysql-client.tar.xz; \
    mkdir -p /tmp/mysql-client; \
    tar -xJf /tmp/mysql-client.tar.xz -C /tmp/mysql-client "${pkg}/bin/mysql" "${pkg}/bin/mysqldump"; \
    install -d /opt/mysql/bin; \
    mv "/tmp/mysql-client/${pkg}/bin/mysql" "/tmp/mysql-client/${pkg}/bin/mysqldump" /opt/mysql/bin/; \
    rm -rf /tmp/mysql-client /tmp/mysql-client.tar.xz /tmp/mysql-client.tar.xz.asc /tmp/mysql-build-key.asc "$GNUPGHOME"; \
    /opt/mysql/bin/mysqldump --version

WORKDIR /code

# install python dependencies (kept before the source copy so code changes don't
# invalidate the cached dependency layer)
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade "pip==26.2.1" \
    && pip install --no-cache-dir -r requirements.txt

# copy project
COPY . /code/

EXPOSE 8000

COPY init.sh /usr/local/bin/
RUN groupadd --gid 10001 backupsheep \
    && useradd --uid 10001 --gid 10001 --home-dir /home/backupsheep --create-home --shell /usr/sbin/nologin backupsheep \
    && install -d -o backupsheep -g backupsheep -m 0700 /code/_storage /backups \
    && install -d -o backupsheep -g backupsheep -m 0755 /code/static \
    && chmod 0755 /usr/local/bin/init.sh

ENV HOME=/home/backupsheep
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/init.sh"]
