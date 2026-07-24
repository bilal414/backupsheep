# Railway

Railway deploy buttons are published from a Railway account as a multi-service template.
This repository includes the service configuration files needed to create that template:

| Railway service | Source | Config-as-Code file |
|---|---|---|
| `Web` | this repository | [`deploy/railway/web.railway.json`](../deploy/railway/web.railway.json) |
| `Worker` | this repository | [`deploy/railway/worker.railway.json`](../deploy/railway/worker.railway.json) |
| `Beat` | this repository | [`deploy/railway/beat.railway.json`](../deploy/railway/beat.railway.json) |
| `Postgres` | Railway PostgreSQL template | Railway-managed |
| `RabbitMQ` | `rabbitmq:4.3.4-management-alpine` | Private Docker-image service with a persistent volume |

The worker consumes all queues with concurrency 1, because separate Railway services do
not share a writable working directory. Use an external object-storage destination for
backups; **Local Storage** is not suitable for this layout.

## Publish the deploy template

1. In Railway, create a project and add Railway's **PostgreSQL** database service. Name it
   `Postgres`.
2. Add a **Docker Image** service named `RabbitMQ` using
   `rabbitmq:4.3.4-management-alpine`. Attach a Railway Volume at
   `/var/lib/rabbitmq`; do not generate a public domain. Add these RabbitMQ-only variables:

   ```text
   RABBITMQ_DEFAULT_USER=backupsheep
   RABBITMQ_DEFAULT_PASS=<a long random password>
   RABBITMQ_DEFAULT_VHOST=backupsheep
   ```

   When configuring the published template, replace the source project's password with
   Railway's `secret(48)` template function so each deployer receives a fresh password.

3. Add three services from this GitHub repository, naming them `Web`, `Worker`, and `Beat`.
   Point their Config-as-Code paths to the matching files in the table above. Generate a
   public domain for `Web` only.
4. In each application service, add these references:

   ```text
   DATABASE_URL=${{Postgres.DATABASE_URL}}
   RABBITMQ_HOST=${{RabbitMQ.RAILWAY_PRIVATE_DOMAIN}}
   RABBITMQ_PORT=5672
   RABBITMQ_USER=${{RabbitMQ.RABBITMQ_DEFAULT_USER}}
   RABBITMQ_PASSWORD=${{RabbitMQ.RABBITMQ_DEFAULT_PASS}}
   RABBITMQ_VHOST=${{RabbitMQ.RABBITMQ_DEFAULT_VHOST}}
   ```

   For `Web`, also add:

   ```text
   APP_DOMAIN=${{RAILWAY_PUBLIC_DOMAIN}}
   DJANGO_ALLOWED_HOSTS=${{RAILWAY_PUBLIC_DOMAIN}}
   ```

   For `Worker` and `Beat`, reference the web service's public domain instead:

   ```text
   APP_DOMAIN=${{Web.RAILWAY_PUBLIC_DOMAIN}}
   DJANGO_ALLOWED_HOSTS=${{Web.RAILWAY_PUBLIC_DOMAIN}}
   ```

5. Add these shared variables to all three application services. Let Railway generate fresh
   values for them in the template; do not commit real secrets:

   ```text
   DJANGO_SERVER=prod
   DJANGO_DEBUG=false
   DJANGO_HTTPS=true
   APP_NAME=BackupSheep
   APP_PROTOCOL=https://
   DJANGO_SECRET_KEY=${{ secret(64) }}
   ONBOARDING_INSTALL_TOKEN=${{ secret(48) }}
   ```

   Keep the onboarding token visible long enough for the deployer to enter it in the
   first-run wizard; seal the Django secret after it has been generated.

6. Verify the `Web` health check at `/healthz/`, complete the BackupSheep onboarding
   wizard with the token, then choose **Create Template** from the Railway project settings.
   Publish it and copy the generated template code into the README deploy-button URL.

Railway will create the deploy button only after the account owner publishes this template.
The service configuration is kept in the repository so future template updates remain
reviewable and versioned.

## Operations

- Run migrations only from the `Web` service's pre-deploy command; do not add it to Worker
  or Beat.
- Keep RabbitMQ private. The `RABBITMQ_*` application references use Railway's private DNS
  name and must not be replaced with a public TCP proxy.
- Keep exactly one Beat replica. Scale workers only after moving backup working files to a
  shared durable filesystem; otherwise retain the single all-queue worker.
- Use a VM/Docker Compose installation when local-disk backups or large temporary backup
  files are required.
