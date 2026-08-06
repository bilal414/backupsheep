import logging

from rest_framework.views import APIView
from rest_framework.response import Response
from firebase_admin import auth
from firebase_admin.exceptions import FirebaseError


logger = logging.getLogger(__name__)


class APICheckLogin(APIView):
    permission_classes = ()

    def get(self, request):
        login = False
        firebase_login_token = None

        if request.user.is_authenticated:
            uid = request.user.username
            additional_claims = {"staff": True}
            try:
                firebase_login_token = auth.create_custom_token(uid, additional_claims)
                if isinstance(firebase_login_token, bytes):
                    firebase_login_token = firebase_login_token.decode("utf-8")
            except (FirebaseError, ValueError):
                # Firebase is an optional legacy integration. A self-hosted instance
                # may not configure Firebase Admin at all, but token authentication
                # itself is still valid and this endpoint is used as its probe.
                logger.debug("Firebase custom token unavailable for login probe", exc_info=True)
            login = True
        content = {"login": login, "firebase_login_token": firebase_login_token}
        return Response(content)
