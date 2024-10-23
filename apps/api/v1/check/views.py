from rest_framework.views import APIView
from rest_framework.response import Response
from firebase_admin import auth


class APICheckLogin(APIView):
    permission_classes = ()

    def get(self, request):
        login = False
        firebase_login_token = None

        if request.user.is_authenticated:
            uid = request.user.username
            additional_claims = {"staff": True}
            firebase_login_token = auth.create_custom_token(uid, additional_claims)
            login = True
        content = {"login": login, "firebase_login_token": firebase_login_token}
        return Response(content)
