# Self-hosted BackupSheep image, shared by the web, Celery worker, and beat services
# (docker-compose runs each from this one image with a different command).
# Built in one step by docker-compose; no separate base image to build first.
#
# The web service runs gunicorn on port 8000 (static files via WhiteNoise); run it
# behind your own TLS-terminating reverse proxy for production HTTPS.
#
# System packages below provide the backup tooling the worker shells out to:
#   - lftp .................. FTP/FTPS storage transfers
#   - mariadb-client ........ mariadb-dump / mysqldump for MySQL/MariaDB backups
#   - postgresql-client-14..18  version-matched pg_dump (CoreAuthDatabase.bin_path)
#   - gunicorn .............. WSGI server for the web service
FROM python:3.14-bookworm

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get -y install zsh htop libpq-dev gcc software-properties-common gnupg2 python3-dev musl-dev git g++-11 ruby ruby-full postgresql-server-dev-all \
    && apt-get -y install curl dirmngr \
    && curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | bash \
    && apt-get update \
    && apt-get -y install mariadb-server mariadb-client \
    && apt-get -y install tree build-essential vim openssh-server libffi-dev git libpq-dev python3-dev libffi-dev libjpeg-dev git zip unzip nano libmysqlclient-dev gunicorn g++ libzmq3-dev gcc \
    && apt-get -y install libssl-dev libxml2-dev libxslt1-dev python3-dev libcurl4-openssl-dev libffi-dev unixodbc unixodbc-dev libsqlite3-dev ncurses-dev  libexpat1-dev \
    && apt-get -y install pkg-config ncurses-dev libreadline6-dev zlib1g-dev libssl-dev software-properties-common autoconf automake libtool pkg-config autoconf \
    && apt-get -y install libncurses-dev libgnutls28-dev libexpat1-dev  pkg-config libreadline-dev  zlib1g-dev libssl-dev \
    && apt-get -y install software-properties-common tree libfreetype6-dev \
    && apt-get -y install tzdata \
    && wget http://lftp.yar.ru/ftp/lftp-4.9.2.tar.gz \
    && tar -xvf lftp-4.9.2.tar.gz && cd lftp-4.9.2 && ./configure && make install \
    && pip install psycopg2

# PostgreSQL client tools (pg_dump / psql / pg_restore) for versions 14-18 from the
# PGDG apt repo, installed side-by-side under /usr/lib/postgresql/<N>/bin. Database
# backups select the exact pg_dump for the target server's version (CoreAuthDatabase.bin_path).
# MariaDB clients (mariadb-dump / mysqldump) come from the mariadb-server install above;
# drop a real MySQL client into /opt/mysql/bin to use it for MySQL targets.
RUN install -d /usr/share/postgresql-common/pgdg \
    && curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get -y install postgresql-client-14 postgresql-client-15 postgresql-client-16 postgresql-client-17 postgresql-client-18

RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

WORKDIR /code

# install python dependencies (kept before the source copy so code changes don't
# invalidate the cached dependency layer)
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# copy project
COPY . /code/

EXPOSE 8000

COPY init.sh /usr/local/bin/
RUN chmod u+x /usr/local/bin/init.sh

ENTRYPOINT ["/usr/local/bin/init.sh"]
