import pytz
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView
from twilio.rest.verify.v2.service.entity.new_factor import NewFactorInstance

from apps.console.account.models import CoreAccountGroup
from apps.console.notification.models import CoreNotificationSlack, CoreNotificationTelegram


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


class AppSumoView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/appsumo.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)

        account = self.request.user.member.get_current_account()

        if account.appsumo_code_count > 0:
            context["heading"] = "Settings - AppSumo"
            context["active_url"] = "account"
            context["account"] = account
            context["timezones"] = pytz.all_timezones
            return self.render_to_response(context)
        else:
            return redirect("console:home:index")



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
        if context["account"].billing.plan.name == "AppSumo":
            return redirect("console:home:index")
        else:
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
        if context["account"].billing.plan.name == "AppSumo":
            return redirect("console:home:index")
        else:
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
        context["invites_received"] = self.request.user.member.invites_received()
        if context["account"].billing.plan.name == "AppSumo":
            return redirect("console:home:index")
        else:
            return self.render_to_response(context)

class BillingView(LoginRequiredMixin, TemplateView):
    template_name = "console/setting/billing.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Billing"
        context["active_url"] = "billing"
        member = self.request.user.member
        account = member.get_current_account()
        context["account"] = account
        context["stripe_customer_portal_url"] = account.billing.stripe_customer_portal_url

        # return redirect(account.billing.stripe_customer_portal_url)
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
        context[
            "slack_oauth_url"
        ] = f"https://slack.com/oauth/v2/authorize?client_id=2942549037255.2957176196498&scope=incoming-webhook&redirect_uri={settings.APP_URL}/api/v1/callback/slack/"
        if context["account"].billing.plan.name == "AppSumo":
            return redirect("console:home:index")
        else:
            return self.render_to_response(context)