#!/bin/bash
# Entrypoint for the web (app) service: collect static assets (served by WhiteNoise),
# then run gunicorn in the foreground. Schema migrations run in the one-shot `migrate`
# service; the Celery worker and beat run as their own services (see docker-compose.yml).
set -e

# Hosted platforms use this image for workers, Beat, and one-off migration commands.
# Docker passes their configured command as arguments to ENTRYPOINT, so honor it before
# running the web-server startup path below.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi

python manage.py collectstatic --noinput

exec gunicorn backupsheep.wsgi:application --workers=4 --timeout=3600 --bind 0.0.0.0:8000
