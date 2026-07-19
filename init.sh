#!/bin/bash

# Configure NGINX
#systemctl enable nginx
service nginx start

python manage.py collectstatic --noinput
python manage.py migrate
# The default cache is DatabaseCache on the core_cache table, which no migration
# creates; without it every request 500s on the first cache access.
python manage.py createcachetable

# Run the web server, the Celery worker (executes backups) and the Celery beat
# scheduler (fires scheduled backups) under supervisor. Requires CELERY_BROKER_URL
# (e.g. the RabbitMQ service from docker-compose) to be reachable.
supervisord -c /code/_supervisor/supervisord.conf

