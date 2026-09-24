"""Create or update a first-party OAuth 2.0 client such as the BackupSheep mobile app.

The mobile apps are public clients (they cannot keep a secret) that rely on
PKCE and an exact redirect URI.  Installers and operators run this command so
every install exposes the same well-known ``client_id``; the command is
idempotent and never prints or stores a plaintext secret for public clients.
"""

from __future__ import annotations

import re

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from oauth2_provider.generators import generate_client_secret
from oauth2_provider.models import get_application_model

from apps.api.v1.utils.api_scopes import validate_scopes

_CLIENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,99}$")


class Command(BaseCommand):
    help = "Create or update a first-party OAuth 2.0 client (idempotent)."

    def add_arguments(self, parser):
        parser.add_argument("--client-id", required=True, help="Stable client identifier.")
        parser.add_argument("--name", required=True, help="Display name shown on the consent page.")
        parser.add_argument(
            "--owner-email",
            required=True,
            help="Email of the member who owns the application record.",
        )
        parser.add_argument(
            "--redirect-uri",
            action="append",
            default=[],
            help="Exact redirect URI (repeatable). Required for authorization-code clients.",
        )
        parser.add_argument(
            "--confidential",
            action="store_true",
            help="Create a confidential client and print its secret once.",
        )
        parser.add_argument(
            "--client-credentials",
            action="store_true",
            help="Use the client-credentials grant (implies --confidential).",
        )
        parser.add_argument(
            "--skip-consent",
            action="store_true",
            help="Trusted first-party client: do not show the consent screen.",
        )
        parser.add_argument(
            "--scope",
            action="append",
            default=[],
            help="Scope the client is expected to request (validated only; repeatable).",
        )

    def handle(self, *args, **options):
        Application = get_application_model()
        client_id = options["client_id"].strip()
        if not _CLIENT_ID.fullmatch(client_id):
            raise CommandError(
                "--client-id must be 3-100 lowercase letters, digits, dots, dashes or underscores."
            )
        if options["scope"]:
            try:
                validate_scopes(options["scope"])
            except ValueError as error:
                raise CommandError(str(error))

        owner = get_user_model().objects.filter(email__iexact=options["owner_email"]).first()
        if owner is None:
            raise CommandError("No member with that email exists.")

        confidential = options["confidential"] or options["client_credentials"]
        grant = (
            Application.GRANT_CLIENT_CREDENTIALS
            if options["client_credentials"]
            else Application.GRANT_AUTHORIZATION_CODE
        )
        redirect_uris = [uri.strip() for uri in options["redirect_uri"] if uri.strip()]
        if grant == Application.GRANT_AUTHORIZATION_CODE and not redirect_uris:
            raise CommandError("Authorization-code clients need at least one --redirect-uri.")
        if grant == Application.GRANT_CLIENT_CREDENTIALS and redirect_uris:
            raise CommandError("Client-credentials clients do not use redirect URIs.")

        application = Application.objects.filter(client_id=client_id).first()
        created = application is None
        secret = ""
        if created:
            secret = generate_client_secret() if confidential else ""
            application = Application(client_id=client_id, client_secret=secret, user=owner)
        elif application.user_id != owner.pk:
            raise CommandError("That client_id is owned by a different member.")

        application.name = options["name"].strip()
        application.client_type = (
            Application.CLIENT_CONFIDENTIAL if confidential else Application.CLIENT_PUBLIC
        )
        application.authorization_grant_type = grant
        application.redirect_uris = " ".join(redirect_uris)
        application.skip_authorization = bool(options["skip_consent"])
        try:
            application.full_clean(exclude=["user", "client_secret"])
        except Exception as error:  # ValidationError carries the per-field detail
            raise CommandError(f"Invalid application configuration: {error}")
        application.save()

        verb = "Created" if created else "Updated"
        self.stdout.write(
            f"{verb} OAuth client {application.client_id} ({application.get_client_type_display()}, "
            f"{application.authorization_grant_type})."
        )
        if secret:
            self.stdout.write("Client secret (shown once; store it now):")
            self.stdout.write(secret)
