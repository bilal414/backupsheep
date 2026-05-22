#!/bin/bash

# Configure NGINX
#systemctl enable nginx
service nginx start

python manage.py collectstatic --noinput
python manage.py migrate

# Run the web server, the Celery worker (executes backups) and the Celery beat
# scheduler (fires scheduled backups) under supervisor. Requires CELERY_BROKER_URL
# (e.g. a Redis service) to be reachable.
supervisord -c /code/_supervisor/supervisord.conf

