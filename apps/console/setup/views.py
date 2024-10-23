from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q, Sum, Count
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView, DetailView
from django.core.paginator import Paginator
from apps.console.connection.models import CoreConnection, CoreIntegration
from apps.console.storage.models import CoreStorage, CoreStorageType
from requests_oauthlib import OAuth2Session


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
                    f"&response_type={settings.GOOGLE_RESPONSE_TYPE}" \
                    f"&scope=https://www.googleapis.com/auth/cloud-platform" \
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
        p_no = self.request.GET.get("p_no", 1)
        p_size = self.request.GET.get("p_size", 10)
        integration_code = self.kwargs.get("integration_code")
        i_name = self.request.GET.get("i_name")
        member = self.request.user.member

        if CoreStorageType.objects.filter(code=integration_code).exists() and integration_code != "bs":
            storage_type = CoreStorageType.objects.get(code=integration_code)

            if storage_type.code == "bs":
                query = Q(
                    account=member.get_current_account(),
                    type=storage_type,
                    status=CoreStorage.Status.ACTIVE
                )
            else:
                query = Q(
                    account=member.get_current_account(),
                    type=storage_type,
                )

            storage_list = CoreStorage.objects.filter(query).order_by("-created")
            # storage_list = (
            #     CoreStorage.objects.filter(query)
            #     .annotate(
            #         Sum("website_backups__size"),
            #         Sum("database_backups__size"),
            #         Count("database_backups", distinct=True),
            #         Count("website_backups", distinct=True),
            #         Count("database_backups__database", distinct=True),
            #         Count("website_backups__website", distinct=True),
            #     )
            #     .order_by("-created")
            # )
            context["storage_count"] = storage_list.count()
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
                    "https://accounts.google.com/o/oauth2/auth",
                    access_type="offline",
                    prompt="consent",
                )
                context["connect_url"] = authorization_url
            elif storage_type.code == "pcloud":
                context[
                    "connect_url"
                ] = f"{settings.PCLOUD_AUTH_URL}?" \
                    f"client_id={settings.PCLOUD_CLIENT_ID}" \
                    f"&response_type={settings.PCLOUD_RESPONSE_TYPE}" \
                    f"&redirect_uri={settings.APP_URL}{settings.PCLOUD_REDIRECT_URL}"
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
