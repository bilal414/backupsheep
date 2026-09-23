import pytz
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.password_validation import password_validators_help_texts
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView
from apps.console.account.models import CoreAccountGroup
from apps.console.member.models import CoreMemberAccount
from apps.console.notification.models import CoreNotificationSlack, CoreNotificationTelegram
from apps.api.v1.utils.api_permissions import current_account_is_primary
from apps.api.v1.utils.oauth_security import get_or_issue_oauth_state


class SettingsContextMixin:
    """Shared, server-authoritative scope and capability context for Settings.

    Settings combines identity-owned controls with current-workspace controls.  The
    templates must not infer that boundary from the presence of a button because
    the API correctly reserves workspace mutations for the primary membership.
    """

    settings_scope = "workspace"
    settings_owner_only = False

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        member = self.request.user.member
        account = member.get_current_account()
        membership = None
        if account is not None:
            membership = member.memberships.filter(
                account=account,
                status=CoreMemberAccount.Status.ACTIVE,
            ).first()

        can_manage_workspace = bool(membership and membership.primary)
        context.update(
            {
                "account": account,
                "settings_scope": self.settings_scope,
                "settings_owner_only": self.settings_owner_only,
                "settings_can_manage_workspace": can_manage_workspace,
                "settings_read_only": (
                    self.settings_owner_only and not can_manage_workspace
                ),
                "settings_current_membership": membership,
                "settings_role_label": (
                    "Owner" if can_manage_workspace else "Member"
                ),
                "settings_mfa_enabled": member.mfa_enabled,
                "content_owns_h1": True,
                "shell_heading": "Settings",
            }
        )
        return context


class AccountView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/account.html"
    settings_owner_only = True

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Account"
        context["active_url"] = "account"
        context["account"] = self.request.user.member.get_current_account()
        context["timezones"] = pytz.all_timezones
        context["other_memberships"] = [
            {
                "membership": membership,
                "can_leave": (
                    membership.status == CoreMemberAccount.Status.ACTIVE
                    and not membership.primary
                ),
            }
            for membership in self.request.user.member.memberships.select_related(
                "account"
            ).exclude(account=context["account"])
        ]
        return self.render_to_response(context)


class ProfileView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/profile.html"
    settings_scope = "identity"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Profile"
        context["active_url"] = "profile"
        context["account"] = self.request.user.member.get_current_account()
        context["timezones"] = pytz.all_timezones
        membership = context["settings_current_membership"]
        context["profile_initial"] = {
            "id": self.request.user.member.id,
            "user": {
                "id": self.request.user.id,
                "first_name": self.request.user.first_name,
                "last_name": self.request.user.last_name,
                "email": self.request.user.email,
            },
            "timezone": self.request.user.member.timezone,
            "memberships": (
                [
                    {
                        # NULL is an enabled preference in the delivery pipeline.
                        "notify_on_success": membership.notify_on_success is not False,
                        "notify_on_fail": membership.notify_on_fail is not False,
                    }
                ]
                if membership
                else []
            ),
        }
        return self.render_to_response(context)


class PasswordView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/password.html"
    settings_scope = "identity"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Password"
        context["active_url"] = "password"
        context["account"] = self.request.user.member.get_current_account()
        context["settings_has_usable_password"] = request.user.has_usable_password()
        context["password_help_texts"] = password_validators_help_texts()
        return self.render_to_response(context)


class MultiFactorView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/multifactor.html"
    settings_scope = "identity"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Multi-Factor Auth"
        context["active_url"] = "multifactor"
        context["account"] = self.request.user.member.get_current_account()
        context["mfa_initial"] = {
            "id": self.request.user.member.id,
            "state": (
                "enabled" if self.request.user.member.mfa_enabled else "disabled"
            ),
            "display_name": self.request.user.member.auth_multi_factor_display_name,
        }
        return self.render_to_response(context)


class GroupView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/group.html"
    settings_owner_only = True

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Group"
        context["active_url"] = "group"
        context["types"] = CoreAccountGroup.Type.choices
        context["account"] = self.request.user.member.get_current_account()
        context["account_groups"] = (
            context["account"].enrollments.all()
            if context["settings_can_manage_workspace"]
            else context["account"].enrollments.none()
        )
        return self.render_to_response(context)


class UserView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/user.html"
    settings_owner_only = True

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Users"
        context["active_url"] = "user"
        context["account"] = self.request.user.member.get_current_account()
        context["enrollments"] = (
            context["account"].enrollments.all()
            if context["settings_can_manage_workspace"]
            else context["account"].enrollments.none()
        )
        context["member"] = self.request.user.member
        return self.render_to_response(context)


class InviteView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/invite.html"
    settings_owner_only = True

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Invite"
        context["active_url"] = "invite"
        context["app_url"] = f"{settings.APP_PROTOCOL}{settings.APP_DOMAIN}/invites"
        context["account"] = self.request.user.member.get_current_account()
        context["enrollments"] = (
            context["account"].enrollments.all()
            if context["settings_can_manage_workspace"]
            else context["account"].enrollments.none()
        )
        if context["settings_can_manage_workspace"]:
            context["outbound_invites"] = context["account"].invites.all()
        else:
            context["outbound_invites"] = context["account"].invites.none()
        invites_received = self.request.user.member.invites_received()
        # Lazily flip past-expiry pending invites so the page shows the real state.
        for invite in invites_received:
            invite.expire_if_needed()
        context["invites_received"] = invites_received
        return self.render_to_response(context)


class NotificationView(SettingsContextMixin, LoginRequiredMixin, TemplateView):
    template_name = "console/setting/notification.html"
    settings_owner_only = True

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["heading"] = "Settings - Notification"
        context["active_url"] = "notifications"
        context["account"] = self.request.user.member.get_current_account()
        if context["settings_can_manage_workspace"]:
            context["notifications_slack"] = CoreNotificationSlack.objects.filter(
                account=context["account"]
            )
            context["notifications_telegram"] = CoreNotificationTelegram.objects.filter(
                account=context["account"]
            )
        else:
            # Provider destinations are owner-managed.  Do not hydrate credential-
            # adjacent model objects into a member-readable server template.
            context["notifications_slack"] = CoreNotificationSlack.objects.none()
            context["notifications_telegram"] = CoreNotificationTelegram.objects.none()
        if (
            current_account_is_primary(request)
            and settings.SLACK_CLIENT_ID
            and settings.SLACK_CLIENT_SECRET
            and settings.SLACK_TOKEN_URL
        ):
            oauth_state = get_or_issue_oauth_state(
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
