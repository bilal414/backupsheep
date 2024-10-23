import stripe
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from firebase_admin import auth
from sentry_sdk import capture_exception

from apps.console.api.v1._tasks.helper.tasks import billing_sync_all
from apps.console.billing.models import CoreBilling


class APIIncomingStripe(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        try:
            payload = request.data
            synced = None
            message = None

            if payload["type"] == "customer.subscription.updated":
                subscription = payload["data"]["object"]
                if CoreBilling.objects.filter(stripe_customer_id=subscription["customer"]).exists():
                    billing = CoreBilling.objects.get(stripe_customer_id=subscription["customer"])
                    billing_sync_all(
                        billing.id,
                    )
                    # create new storage on upgrade
                    billing.account.setup_bs_storage()
                    synced = True
            content = {"synced": synced, "message": message}
            return Response(content)

        except Exception as e:
            capture_exception(e)
