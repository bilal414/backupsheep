"""Helpers that revoke OAuth credentials completely (access + refresh + grants)."""

from django.db import transaction
from django.utils import timezone
from oauth2_provider.models import (
    get_access_token_model,
    get_grant_model,
    get_refresh_token_model,
)


def revoke_access_token(access_token):
    """Revoke one access token together with the refresh token that renews it."""
    RefreshToken = get_refresh_token_model()
    with transaction.atomic():
        RefreshToken.objects.filter(access_token=access_token, revoked__isnull=True).update(
            revoked=timezone.now()
        )
        access_token.revoke()


def revoke_application_grants(user, application):
    """Withdraw every credential ``application`` holds for ``user``.

    Returns the number of access tokens removed.  Refresh tokens are marked
    revoked (their rows carry the audit trail) and pending authorization codes
    are deleted.
    """
    AccessToken = get_access_token_model()
    RefreshToken = get_refresh_token_model()
    Grant = get_grant_model()
    with transaction.atomic():
        RefreshToken.objects.filter(
            user=user, application=application, revoked__isnull=True
        ).update(revoked=timezone.now())
        Grant.objects.filter(user=user, application=application).delete()
        removed, _ = AccessToken.objects.filter(user=user, application=application).delete()
    return removed
