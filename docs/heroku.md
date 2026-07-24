# Heroku

BackupSheep can be deployed through a Heroku Button with PostgreSQL and a managed
**RabbitMQ** broker:

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://www.heroku.com/deploy?template=https://github.com/bilal414/backupsheep/tree/main)

The repository's `app.json` creates:

- Heroku Postgres, exposed to BackupSheep as `DATABASE_URL`;
- CloudAMQP's **Little Lemur** RabbitMQ plan, exposed as `CLOUDAMQP_URL`;
- a web dyno, one all-queue Celery worker, and one singleton Celery Beat dyno; and
- a release phase that runs database migrations before the new release starts.

`CLOUDAMQP_URL` is accepted only as an AMQP(S) broker URL and is preferred over the local
Compose default. The button pins the RabbitMQ Little Lemur plan (`cloudamqp:lemur`), not a
LavinMQ plan.

## Deploy

1. Click the button and choose the Heroku app name and region.
2. Enter a long, private `ONBOARDING_INSTALL_TOKEN`.
3. Set `APP_DOMAIN` to the exact hostname users will visit, without `https://`. For the
   default Heroku domain, copy it from the app's **Settings → Domains** page. Keep
   `DJANGO_ALLOWED_HOSTS=.herokuapp.com` unless you add a custom domain.
4. Create the app. Heroku builds the Docker image, provisions the add-ons, runs migrations,
   and starts the three process types.
5. Open the app and enter the onboarding token in the first-run wizard.

For a custom domain, change `APP_DOMAIN` and add that hostname to
`DJANGO_ALLOWED_HOSTS` before directing users to it. Keep `DJANGO_HTTPS=true` and
`APP_PROTOCOL=https://`.

## Operating limits

Heroku dyno filesystems are ephemeral and are not shared between processes. The template
therefore runs one worker that consumes every BackupSheep queue at concurrency 1, allowing
each backup's dump and follow-up upload to use the same worker filesystem. It is suitable
for small to moderate jobs sent to external object storage, not for horizontal worker
scaling or **Local Storage** archives.

- Configure S3, B2, R2, Spaces, or another external storage destination in BackupSheep.
- Do not use the Local Storage destination on Heroku.
- The default Little Lemur RabbitMQ plan is intended for development/small workloads.
  Upgrade to a RabbitMQ CloudAMQP plan such as `cloudamqp:tiger` before relying on it for
  production volume.
- The manifest starts three Basic dynos, so review Heroku and add-on charges before
  deployment.

For sustained large database or file backups, use the complete Docker Compose stack on a
[cloud VM](cloud-vms.md) instead.

## Useful commands

Replace `APP` with the Heroku application name:

```bash
heroku logs --tail --app APP
heroku ps --app APP
heroku ps:scale web=1 worker=1 beat=1 --app APP
```

Never scale `beat` above one process, or scheduled backups will be dispatched more than
once.
