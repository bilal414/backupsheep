from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.views.generic import TemplateView, DetailView
from apps.console.notification.models import CoreNotificationEmail


class IntegrationOpenView(LoginRequiredMixin, TemplateView):
    template_name = "console/home/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)

        verify_code = self.kwargs.get("verify_code")

        if CoreNotificationEmail.objects.filter(verify_code=verify_code).exists():
            notification_email = CoreNotificationEmail.objects.get(verify_code=verify_code)
            notification_email.status = CoreNotificationEmail.Status.VERIFIED
            notification_email.verify_code = None
            notification_email.save()
            messages.add_message(request, messages.SUCCESS, "Your email is successfully verified.")
        else:
            messages.add_message(
                request, messages.ERROR, "Unable to verify your email. Contact support if you link doesn't work."
            )

        return redirect("console:home:index")
