# Render

BackupSheep can be deployed from this repository with Render Blueprints:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/bilal414/backupsheep/tree/main)

The [render.yaml](../render.yaml) Blueprint creates:

- a public Django web service with a pre-deploy migration command;
- one all-queue Celery worker;
- one singleton Celery Beat scheduler;
- managed Render PostgreSQL; and
- managed Render Key Value (Redis) as the Celery broker.

## Deploy

Click the button and authorize Render to read the repository. During Blueprint creation,
enter a long random `ONBOARDING_INSTALL_TOKEN`; Render generates the Django secret and
connects the managed PostgreSQL and Redis services automatically. Once the web service is
healthy, enter the onboarding token in BackupSheep's first-run wizard.

The Blueprint deliberately sets `autoDeployTrigger: off`: deployments created through a
shared deploy button should not redeploy automatically whenever this upstream repository is
updated. Trigger updates from the Render dashboard after reviewing release notes.

## Important limits

Render services do not share a writable working directory. The included worker consumes all
Celery queues with concurrency 1, so a dump task and its follow-up upload task run in the
same service filesystem. This makes the Blueprint suitable for low-volume, external-storage
backups, not for horizontally scaled local-disk workflows.

- Do **not** use BackupSheep's **Local Storage** destination on this deployment. Use S3,
  DigitalOcean Spaces, B2, R2, or another external object-storage destination.
- Treat the default service/database plans as a starting point. Review sizing and pricing
  before deployment, then increase worker memory/CPU for large database or file backups.
- If you add a custom Render domain, update `APP_DOMAIN` and `DJANGO_ALLOWED_HOSTS` to
  include it before directing users to that domain.

For durable local storage or independently scalable worker pools, use the Docker Compose
installation on a VM instead.
