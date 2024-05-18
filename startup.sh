#!/bin/bash
python3 manage.py migrate && python3 manage.py collectstatic --noinput && gunicorn backupsheep.wsgi:application --workers=4 --timeout=3600