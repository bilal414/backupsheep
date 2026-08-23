from rest_framework.views import APIView
from rest_framework.response import Response


class APICheckLogin(APIView):
    permission_classes = ()

    def get(self, request):
        # Keep the legacy response key temporarily so existing clients do not
        # fail while removing the privileged Firebase custom-token surface.
        content = {
            "login": request.user.is_authenticated,
            "firebase_login_token": None,
        }
        return Response(content)
