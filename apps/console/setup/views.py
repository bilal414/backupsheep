import os
import secrets
import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView, DetailView
from django.core.paginator import Paginator
from apps.console.connection.models import CoreConnection, CoreIntegration
from apps.console.storage.models import CoreStorage, CoreStorageType
from requests_oauthlib import OAuth2Session
from apps.api.v1.utils.api_permissions import member_has_perm


PCLOUD_OAUTH_STATE_SESSION_KEY = "pcloud_oauth_state"


class IntegrationSelectView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/1_integration_select.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)

        context["heading"] = "Integrations"
        context["active_url"] = "setup"
        return self.render_to_response(context)


class IntegrationOpenView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/2_integration_open.html"

    # def get_template_names(self):
    #     context = self.get_context_data(self.kwargs)
    #     return ['%s.html' % self.kwargs['template']]

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["active_url"] = "setup"
        p_no = self.request.GET.get("p_no", 1)
        p_size = self.request.GET.get("p_size", 10)
        integration_code = self.kwargs.get("integration_code")
        i_name = self.request.GET.get("i_name")
        member = self.request.user.member

        if CoreIntegration.objects.filter(code=integration_code).exists():
            integration = CoreIntegration.objects.get(code=integration_code)

            if integration.code == "basecamp":
                context[
                    "connect_url"
                ] = f"{settings.BASECAMP_OAUTH_ENDPOINT}?" \
                    f"client_id={settings.BASECAMP_CLIENT_ID}" \
                    f"&type=web_server" \
                    f"&response_type=code" \
                    f"&redirect_uri={settings.APP_URL}{settings.BASECAMP_REDIRECT_URL}"

            query = Q(
                account=member.get_current_account(),
                integration=integration,
            )
            if i_name:
                query &= Q(name=i_name)
            connections = CoreConnection.objects.filter(query).order_by("-created")
            context["connections_count"] = connections.count()

            context["heading"] = f"Integrations - {integration.name}"

            page = Paginator(connections, p_size).page(p_no)
            context["page"] = page
            context["elided_page_range"] = page.paginator.get_elided_page_range(p_no)
            context["i_name"] = i_name
            context["show_link_icon"] = True
            context["show_link_url"] = reverse("console:setup:integration_select")
            context["integration"] = integration
            context["ssh_managed_public_key"] = settings.SSH_MANAGED_PUBLIC_KEY
            context["ssh_managed_key_enabled"] = bool(
                settings.SSH_MANAGED_PUBLIC_KEY
                and settings.SSH_MANAGED_PRIVATE_KEY_PATH
                and os.path.isfile(settings.SSH_MANAGED_PRIVATE_KEY_PATH)
            )
        else:
            return redirect("console:setup:integration_select")

        return self.render_to_response(context)


class StorageOpenView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/2_integration_open.html"

    # def get_template_names(self):
    #     context = self.get_context_data(self.kwargs)
    #     return ['%s.html' % self.kwargs['template']]

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["active_url"] = "setup"
        p_no = self.request.GET.get("p_no", 1)
        p_size = self.request.GET.get("p_size", 10)
        integration_code = self.kwargs.get("integration_code")
        i_name = self.request.GET.get("i_name")
        member = self.request.user.member

        if CoreStorageType.objects.filter(code=integration_code).exists() and integration_code != "bs":
            storage_type = CoreStorageType.objects.get(code=integration_code)

            query = Q(
                account=member.get_current_account(),
                type=storage_type,
            )

            storage_list = list(CoreStorage.objects.filter(query).order_by("-created"))
            cost_by_storage_id = {
                item["storage_id"]: item
                for item in CoreStorage.cost_summary_for_account(
                    member.get_current_account()
                )["destinations"]
            }
            for storage_item in storage_list:
                storage_item.cost_estimate = cost_by_storage_id.get(
                    storage_item.id,
                    {
                        "stored_bytes": 0,
                        "estimated_monthly_storage_usd": 0,
                        "estimated_full_retrieval_usd": 0,
                        "categories": {},
                    },
                )
                categories = storage_item.cost_estimate.get("categories", {})
                for field_name, category_name in (
                    ("website", "website"),
                    ("database", "database"),
                    ("wordpress", "saas"),
                ):
                    usage = categories.get(category_name, {})
                    setattr(
                        storage_item,
                        f"stats_{field_name}_count",
                        usage.get("source_count", 0),
                    )
                    setattr(
                        storage_item,
                        f"stats_{field_name}_backup_count",
                        usage.get("backup_count", 0),
                    )
                    setattr(
                        storage_item,
                        f"stats_{field_name}_size",
                        usage.get("stored_bytes", 0),
                    )
            context["storage_count"] = len(storage_list)
            context["heading"] = f"Integrations - {storage_type.name}"

            page = Paginator(storage_list, p_size).page(p_no)
            context["page"] = page
            context["elided_page_range"] = page.paginator.get_elided_page_range(p_no)
            context["storage"] = storage_type

            if storage_type.code == "dropbox":
                # DROPBOX
                context[
                    "connect_url"
                ] = f"https://www.dropbox.com/oauth2/authorize?" \
                    f"client_id={settings.DROPBOX_APP_KEY}" \
                    f"&response_type=code" \
                    f"&token_access_type=offline" \
                    f"&redirect_uri={settings.APP_URL}/api/v1/callback/dropbox"
            elif storage_type.code == "google_drive":
                # GOOGLE DRIVE
                scope = ["https://www.googleapis.com/auth/drive.file"]
                oauth = OAuth2Session(
                    settings.GOOGLE_CLIENT_ID,
                    redirect_uri=f"{settings.APP_URL}/api/v1/callback/google_drive/",
                    scope=scope,
                )
                authorization_url, state = oauth.authorization_url(
                    "https://accounts.google.com/o/oauth2/v2/auth",
                    access_type="offline",
                    prompt="consent",
                )
                context["connect_url"] = authorization_url
            elif storage_type.code == "pcloud":
                if member_has_perm(request, "storage_changes"):
                    state = secrets.token_urlsafe(32)
                    request.session[PCLOUD_OAUTH_STATE_SESSION_KEY] = {
                        "state": state,
                        "member_id": member.pk,
                        "account_id": member.get_current_account().pk,
                        "issued_at": time.time(),
                    }
                    context["connect_url"] = (
                        f"{settings.PCLOUD_AUTH_URL}?"
                        + urlencode(
                            {
                                "client_id": settings.PCLOUD_CLIENT_ID,
                                "response_type": settings.PCLOUD_RESPONSE_TYPE,
                                "redirect_uri": settings.APP_URL + settings.PCLOUD_REDIRECT_URL,
                                "state": state,
                            }
                        )
                    )
            elif storage_type.code == "onedrive":
                context[
                    "connect_url"
                ] = f"{settings.MS_OAUTH_ENDPOINT}?" \
                    f"client_id={settings.MS_CLIENT_ID}" \
                    f"&response_type={settings.MS_RESPONSE_TYPE}" \
                    f"&scope={settings.MS_SCOPE}" \
                    f"&prompt=select_account" \
                    f"&redirect_uri={settings.APP_URL}{settings.MS_REDIRECT_URL}"
        else:
            return redirect("console:setup:integration_select")

        return self.render_to_response(context)


class IntegrationCreateNodeView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/3_integration_create_node.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["active_url"] = "setup"
        integration_code = self.kwargs.get("integration_code")
        connection_id = self.kwargs.get("connection_id")

        member = self.request.user.member

        integration = CoreIntegration.objects.get(code=integration_code)

        query = Q(
            account=member.get_current_account(),
            integration=integration,
            status=CoreStorage.Status.ACTIVE,
            id=connection_id,
        )
        connection = CoreConnection.objects.get(query)

        context["heading"] = f"Setup Node - {integration.name} - {connection.name}"

        context["integration"] = integration
        context["connection"] = connection
        context["show_link_icon"] = True
        context["show_link_url"] = reverse(
            "console:setup:integration_open",
            kwargs={"integration_code": integration_code},
        )
        return self.render_to_response(context)


class IntegrationModifyNodeView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/3_integration_create_node.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["active_url"] = "setup"
        integration_code = self.kwargs.get("integration_code")
        connection_id = self.kwargs.get("connection_id")
        node_id = self.kwargs.get("node_id")

        member = self.request.user.member

        integration = CoreIntegration.objects.get(code=integration_code)

        query = Q(
            account=member.get_current_account(),
            integration=integration,
            status=CoreStorage.Status.ACTIVE,
            id=connection_id,
        )
        connection = CoreConnection.objects.get(query)

        node = connection.nodes.get(id=node_id)

        context["heading"] = f"Modify Node - {integration.name} - {connection.name} - {node.name}"

        context["integration"] = integration
        context["connection"] = connection
        context["node"] = node
        context["show_link_icon"] = True
        context["show_link_url"] = reverse(
            "console:node:detail",
            kwargs={"pk": node.id},
        )
        return self.render_to_response(context)
