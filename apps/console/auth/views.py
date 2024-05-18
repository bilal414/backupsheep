from django.contrib.auth.views import *
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView

from apps.console.member.models import CoreMember


class LoginView(TemplateView):
    template_name = "console/auth/login.html"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("console:home:index")
        return super(LoginView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        request.session["next"] = request.GET.get("next", None)
        return self.render_to_response(context)


class LogoutView(TemplateView):
    template_name = None

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return logout_then_login(request, login_url=reverse("console:home:index"))
        else:
            return redirect("home")


class ResetView(TemplateView):
    template_name = "console/auth/reset.html"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("console:home:index")
        return super(ResetView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Reset Password"
        return self.render_to_response(context)


class SetNewPasswordView(TemplateView):
    template_name = "console/auth/set_new_password.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        password_reset_token = self.kwargs.get("password_reset_token")

        if CoreMember.objects.filter(password_reset_token=password_reset_token).exists():
            context["password_reset_token"] = password_reset_token
        else:
            context["password_reset_token"] = None
        context["heading"] = "Set New Password"
        return self.render_to_response(context)
