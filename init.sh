#!/bin/bash

# Configure NGINX
#systemctl enable nginx
service nginx start

#tail -f /dev/null
python manage.py collectstatic --noinput
python manage.py migrate
gunicorn backupsheep.wsgi:application --workers=4 --timeout=3600 --bind 0.0.0.0:8000

