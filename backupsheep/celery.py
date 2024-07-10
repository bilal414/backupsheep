from __future__ import unicode_literals
import os
from celery import Celery
from django.apps import apps

# set the default Django settings module for the 'celery' program.
# This is already done by settings file.
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backupsheep.settings')

app = Celery('backupsheep')

# Using a string here means the worker don't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
# https://stackoverflow.com/questions/47630459/celery-does-not-registering-tasks
app.config_from_object(settings)
# app.conf.update(
# )
app.autodiscover_tasks(lambda: [n.name for n in apps.get_app_configs()])


@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))
