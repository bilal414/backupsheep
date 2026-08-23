import pytz
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView
from apps.console.account.models import CoreAccountGroup
from apps.console.notification.models import CoreNotificationSlack, CoreNotificationTelegram
from apps.api.v1.utils.api_permissions import current_account_is_primary
from apps.api.v1.utils.oauth_security import issue_oauth_state


class AccountView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/account.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Account"
        context["active_url"] = "account"
        context["account"] = self.request.user.member.get_current_account()
        context["timezones"] = pytz.all_timezones
        return self.render_to_response(context)


class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/profile.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Profile"
        context["active_url"] = "profile"
        context["account"] = self.request.user.member.get_current_account()
        context["timezones"] = pytz.all_timezones
        return self.render_to_response(context)


class PasswordView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/password.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Password"
        context["active_url"] = "password"
        context["account"] = self.request.user.member.get_current_account()
        return self.render_to_response(context)


class MultiFactorView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/multifactor.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Multi-Factor Auth"
        context["active_url"] = "multifactor"
        context["account"] = self.request.user.member.get_current_account()
        return self.render_to_response(context)


class GroupView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/group.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Group"
        context["active_url"] = "group"
        context["types"] = CoreAccountGroup.Type.choices
        context["account"] = self.request.user.member.get_current_account()
        return self.render_to_response(context)


class UserView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/user.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Users"
        context["active_url"] = "user"
        context[
            "enrollments"
        ] = self.request.user.member.get_current_account().enrollments.all()
        context["account"] = self.request.user.member.get_current_account()
        context["member"] = self.request.user.member
        return self.render_to_response(context)

class InviteView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/invite.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Invite"
        context["active_url"] = "invite"
        context["app_url"] = f"{settings.APP_PROTOCOL}{settings.APP_DOMAIN}/invites"
        context[
            "enrollments"
        ] = self.request.user.member.get_current_account().enrollments.all()
        context["account"] = self.request.user.member.get_current_account()
        invites_received = self.request.user.member.invites_received()
        # Lazily flip past-expiry pending invites so the page shows the real state.
        for invite in invites_received:
            invite.expire_if_needed()
        context["invites_received"] = invites_received
        return self.render_to_response(context)


class NotificationView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/notification.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Notification"
        context["active_url"] = "notifications"
        context["account"] = self.request.user.member.get_current_account()
        context["notifications_slack"] = CoreNotificationSlack.objects.filter(
            account=self.request.user.member.get_current_account()
        )
        context["notifications_telegram"] = CoreNotificationTelegram.objects.filter(
            account=self.request.user.member.get_current_account()
        )
        if (
            current_account_is_primary(request)
            and settings.SLACK_CLIENT_ID
            and settings.SLACK_CLIENT_SECRET
            and settings.SLACK_TOKEN_URL
        ):
            oauth_state = issue_oauth_state(
                request,
                provider="slack",
                member=request.user.member,
                account=context["account"],
            )
            context["slack_oauth_url"] = (
                "https://slack.com/oauth/v2/authorize?"
                + urlencode(
                    {
                        "client_id": settings.SLACK_CLIENT_ID,
                        "scope": "incoming-webhook",
                        "redirect_uri": f"{settings.APP_URL}/api/v1/callback/slack/",
                        "state": oauth_state["state"],
                    }
                )
            )
        return self.render_to_response(context)
