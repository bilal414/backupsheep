#!/bin/bash
# Entrypoint for the web (app) service: collect static assets (served by WhiteNoise),
# then run gunicorn in the foreground. Schema migrations run in the one-shot `migrate`
# service; the Celery worker and beat run as their own services (see docker-compose.yml).
set -e

python manage.py collectstatic --noinput

exec gunicorn backupsheep.wsgi:application --workers=4 --timeout=3600 --bind 0.0.0.0:8000
