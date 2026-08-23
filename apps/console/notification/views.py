from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.shortcuts import redirect
from django.utils import timezone
from django.views.generic import TemplateView, DetailView
from apps.console.notification.models import CoreNotificationEmail
from datetime import timedelta


class IntegrationOpenView(LoginRequiredMixin, TemplateView):
    template_name = "console/home/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)

        verify_code = self.kwargs.get("verify_code")

        cutoff = timezone.now() - timedelta(
            hours=CoreNotificationEmail.VERIFY_TOKEN_TTL_HOURS
        )
        with transaction.atomic():
            notification_email = (
                CoreNotificationEmail.objects.select_for_update()
                .filter(
                    verify_code=verify_code,
                    member=request.user.member,
                    status=CoreNotificationEmail.Status.UN_VERIFIED,
                    created__gte=cutoff,
                )
                .first()
            )
            if notification_email is not None:
                notification_email.status = CoreNotificationEmail.Status.VERIFIED
                notification_email.verify_code = None
                notification_email.save(
                    update_fields=["status", "verify_code", "modified"]
                )

        if notification_email is not None:
            messages.add_message(request, messages.SUCCESS, "Your email is successfully verified.")
        else:
            messages.add_message(
                request, messages.ERROR, "Unable to verify your email. Contact support if you link doesn't work."
            )

        return redirect("console:home:index")
