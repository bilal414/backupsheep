"""BackupSheep policy on top of django-oauth-toolkit's request validator.

Every token must resolve to a Django user who is active and still holds an
ACTIVE workspace membership; the DRF authenticator repeats that check on each
API request, this validator applies it at issuance time.
"""

from oauth2_provider.oauth2_validators import OAuth2Validator


def _user_is_usable(user):
    if user is None or not getattr(user, "is_active", False):
        return False
    member = getattr(user, "member", None)
    if member is None:
        return False
    return member.get_active_current_membership() is not None


class BackupSheepOAuth2Validator(OAuth2Validator):
    def validate_user(self, username, password, client, request, *args, **kwargs):
        # The resource-owner password grant is never available: passwords are
        # only accepted by the console login, which also runs the MFA challenge.
        return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        allowed = super().validate_grant_type(client_id, grant_type, client, request, *args, **kwargs)
        if allowed and grant_type == "client_credentials":
            # A client-credentials token acts as the application owner, so the
            # owner must still be a usable BackupSheep identity.
            return _user_is_usable(getattr(client, "user", None))
        return allowed

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        valid = super().validate_refresh_token(refresh_token, client, request, *args, **kwargs)
        if valid and not _user_is_usable(getattr(request, "user", None)):
            return False
        return valid

    def validate_bearer_token(self, token, scopes, request):
        valid = super().validate_bearer_token(token, scopes, request)
        if valid and getattr(request, "user", None) is None:
            application = getattr(request, "client", None)
            owner = getattr(application, "user", None)
            if not _user_is_usable(owner):
                return False
            # Client-credentials tokens are stored without a user; resource
            # requests run as the owner who registered the application.
            request.user = owner
        return valid
