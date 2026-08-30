from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.views.generic import TemplateView, DetailView
from django.core.paginator import Paginator
from apps.console.connection.models import CoreConnection, CoreIntegration
from apps.console.storage.models import CoreStorage, CoreStorageType
from requests_oauthlib import OAuth2Session
from apps.api.v1.utils.api_helpers import visible_connections, visible_nodes
from apps.api.v1.utils.api_permissions import (
    member_has_perm,
    member_has_perm_for_node,
)
from apps.api.v1.utils.oauth_security import (
    get_or_issue_oauth_state,
    validated_https_endpoint,
)
from backupsheep.source_recovery_policy import (
    SOURCE_RECOVERY_UNAVAILABLE_MESSAGE,
    source_backup_creation_available,
)


CONNECTION_PAGE_SIZES = (10, 25, 50)

OAUTH_RECONNECT_INTEGRATIONS = frozenset(
    {"digitalocean", "ovh_ca", "ovh_eu", "ovh_us"}
)

SOURCE_RESOURCE_LABELS = {
    "cloud": ("server", "servers"),
    "volume": ("volume", "volumes"),
    "s3": ("S3 bucket", "S3 buckets"),
    "dynamodb": ("DynamoDB table", "DynamoDB tables"),
    "vultr_database": ("managed database", "managed databases"),
}

SOURCE_OBJECT_CODES_BY_INTEGRATION = {
    "aws": frozenset({"cloud", "volume", "s3", "dynamodb"}),
    "aws_rds": frozenset({"cloud"}),
    "basecamp": frozenset({"objects"}),
    "database": frozenset({"objects"}),
    "digitalocean": frozenset({"cloud", "volume"}),
    "google_cloud": frozenset({"cloud", "volume"}),
    "hetzner": frozenset({"cloud"}),
    "lightsail": frozenset({"cloud", "volume"}),
    "oracle": frozenset({"cloud", "volume"}),
    "ovh_ca": frozenset({"cloud", "volume"}),
    "ovh_eu": frozenset({"cloud", "volume"}),
    "ovh_us": frozenset({"cloud", "volume"}),
    "upcloud": frozenset({"cloud", "volume"}),
    "vultr": frozenset({"cloud", "volume", "vultr_database"}),
    "website": frozenset({"objects"}),
    "wordpress": frozenset({"objects"}),
}


def _require_supported_source_object_code(integration_code, object_code):
    """Reject routes that cannot render or register the requested resource."""

    supported_codes = SOURCE_OBJECT_CODES_BY_INTEGRATION.get(integration_code)
    if supported_codes is None or object_code not in supported_codes:
        raise Http404("This provider resource type is not supported.")


def _bounded_page_size(raw_value):
    """Keep public pagination inputs predictable and inexpensive."""

    try:
        page_size = int(raw_value)
    except (TypeError, ValueError):
        return CONNECTION_PAGE_SIZES[0]
    return (
        page_size
        if page_size in CONNECTION_PAGE_SIZES
        else CONNECTION_PAGE_SIZES[0]
    )


class IntegrationSelectView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/1_integration_select.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)

        context["heading"] = "Integrations"
        context["active_url"] = "setup"
        context["content_owns_h1"] = True
        context["shell_heading"] = "Add source"
        member = request.user.member
        account = member.get_current_account()
        can_manage_integrations = member_has_perm(request, "integration_changes")
        can_manage_storage = member_has_perm(request, "storage_changes")
        connection_queryset = CoreConnection.objects.filter(account=account).exclude(
            status=CoreConnection.Status.DELETE_REQUESTED
        )
        if not can_manage_integrations:
            connection_queryset = connection_queryset.filter(
                nodes__in=visible_nodes(member)
            ).distinct()
        context["connected_account_count"] = connection_queryset.count()
        context["active_connection_count"] = connection_queryset.filter(
            status=CoreConnection.Status.ACTIVE
        ).count()
        context["connected_storage_count"] = (
            CoreStorage.objects.filter(account=account).count()
            if can_manage_storage
            else None
        )
        context["protected_source_count"] = visible_nodes(member).count()
        context["can_manage_integrations"] = can_manage_integrations
        context["can_manage_storage"] = can_manage_storage
        context["wordpress_source_protection_available"] = (
            source_backup_creation_available("wordpress")
        )
        context["basecamp_source_protection_available"] = (
            source_backup_creation_available("basecamp")
        )
        return self.render_to_response(context)


class IntegrationOpenView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/2_integration_open.html"

    # def get_template_names(self):
    #     context = self.get_context_data(self.kwargs)
    #     return ['%s.html' % self.kwargs['template']]

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["active_url"] = "setup"
        context["content_owns_h1"] = True
        context["shell_heading"] = "Provider accounts"
        p_no = self.request.GET.get("p_no", 1)
        p_size = _bounded_page_size(self.request.GET.get("p_size"))
        integration_code = self.kwargs.get("integration_code")
        i_name = self.request.GET.get("i_name")
        member = self.request.user.member

        if CoreIntegration.objects.filter(code=integration_code).exists():
            integration = CoreIntegration.objects.get(code=integration_code)
            source_protection_available = source_backup_creation_available(
                integration.code
            )
            context["source_protection_available"] = (
                source_protection_available
            )
            context["source_recovery_unavailable_message"] = (
                SOURCE_RECOVERY_UNAVAILABLE_MESSAGE
            )

            if source_protection_available and integration.code == "basecamp" and member_has_perm(
                request, "integration_changes"
            ):
                authorization_endpoint = validated_https_endpoint(
                    settings.BASECAMP_OAUTH_ENDPOINT,
                    allowed_hostnames={"launchpad.37signals.com"},
                    allowed_paths={"/authorization/new"},
                )
                if authorization_endpoint:
                    account = member.get_current_account()
                    oauth_state = get_or_issue_oauth_state(
                        request,
                        provider="basecamp",
                        member=member,
                        account=account,
                    )
                    context["connect_url"] = authorization_endpoint + "?" + urlencode(
                        {
                            "client_id": settings.BASECAMP_CLIENT_ID,
                            "type": "web_server",
                            "response_type": "code",
                            "redirect_uri": settings.APP_URL
                            + settings.BASECAMP_REDIRECT_URL,
                            "state": oauth_state["state"],
                        }
                    )

            can_manage_integrations = member_has_perm(
                request, "integration_changes"
            )
            visible_node_queryset = visible_nodes(member)
            query = Q(
                account=member.get_current_account(),
                integration=integration,
            )
            if not can_manage_integrations:
                query &= Q(nodes__in=visible_node_queryset)
            if i_name:
                query &= Q(name=i_name)
            connections = CoreConnection.objects.filter(query).distinct().order_by(
                "-created"
            )
            context["connections_count"] = connections.count()

            source_count = (
                Count("nodes", distinct=True)
                if can_manage_integrations
                else Count(
                    "nodes",
                    filter=Q(nodes__in=visible_node_queryset),
                    distinct=True,
                )
            )
            summary = connections.aggregate(
                active=Count(
                    "id",
                    filter=Q(status=CoreConnection.Status.ACTIVE),
                    distinct=True,
                ),
                paused=Count(
                    "id",
                    filter=Q(status=CoreConnection.Status.PAUSED),
                    distinct=True,
                ),
                review=Count(
                    "id",
                    filter=Q(
                        status__in=(
                            CoreConnection.Status.PENDING,
                            CoreConnection.Status.SUSPENDED,
                            CoreConnection.Status.TOKEN_REFRESH_FAIL,
                        )
                    ),
                    distinct=True,
                ),
                protected_sources=source_count,
            )
            context["connection_summary"] = summary
            context["can_manage_integrations"] = can_manage_integrations
            context["can_create_sources"] = context[
                "can_manage_integrations"
            ] and member_has_perm(request, "node_changes")

            context["heading"] = f"Integrations - {integration.name}"

            attachment_count = (
                Count("nodes", distinct=True)
                if can_manage_integrations
                else Count(
                    "nodes",
                    filter=Q(nodes__in=visible_node_queryset),
                    distinct=True,
                )
            )
            connections = connections.select_related(
                "location",
                "integration",
                "added_by__user",
                "auth_digitalocean",
            ).annotate(
                total_nodes_count=attachment_count
            )
            page = Paginator(connections, p_size).get_page(p_no)
            source_registration_connection_ids = set()
            if context["can_create_sources"]:
                source_registration_connection_ids = set(
                    visible_connections(member)
                    .filter(
                        integration=integration,
                        status=CoreConnection.Status.ACTIVE,
                    )
                    .values_list("id", flat=True)
                )
            for connection in page.object_list:
                connection.provider_identity = self._provider_identity(connection)
                connection.operator_name = self._operator_name(connection)
                connection.source_registration_allowed = (
                    connection.id in source_registration_connection_ids
                )
            context["page"] = page
            context["elided_page_range"] = page.paginator.get_elided_page_range(
                page.number
            )
            context["page_sizes"] = CONNECTION_PAGE_SIZES
            context["i_name"] = i_name
            context["show_link_icon"] = True
            context["show_link_url"] = reverse("console:setup:integration_select")
            context["integration"] = integration
            from apps.console.connection.managed_ssh import (
                ManagedSSHOperationError,
                assert_managed_ssh_single_account,
                managed_public_key_for_lane,
                managed_public_key_fingerprint,
            )

            lane = {"database": "database", "website": "files"}.get(
                integration.code
            )
            managed_public_key = ""
            if lane is not None:
                try:
                    assert_managed_ssh_single_account(member.get_current_account().pk)
                    configured_key = managed_public_key_for_lane(lane)
                    managed_public_key_fingerprint(configured_key)
                    fields = configured_key.split()
                    managed_public_key = f"{fields[0]} {fields[1]}"
                except (ManagedSSHOperationError, IndexError):
                    managed_public_key = ""
            context["ssh_managed_public_key"] = managed_public_key
            # The web role deliberately cannot inspect either private key. Each
            # source worker proves only its lane's public/private match at startup.
            context["ssh_managed_key_enabled"] = bool(managed_public_key)
        else:
            return redirect("console:setup:integration_select")

        return self.render_to_response(context)

    @staticmethod
    def _operator_name(connection):
        """Return a safe, human-readable ownership label for the register."""

        added_by = connection.added_by
        if added_by is None:
            return "Not recorded"
        user = getattr(added_by, "user", None)
        if user is None:
            return "Not recorded"
        full_name = user.get_full_name().strip()
        return full_name or user.email

    @staticmethod
    def _provider_identity(connection):
        """Expose a non-secret provider identity witness when one is available."""

        if connection.integration.code != "digitalocean":
            return ""
        try:
            auth = connection.auth_digitalocean
        except ObjectDoesNotExist:
            return ""
        return auth.info_email or auth.info_name or auth.info_uuid or ""


class StorageOpenView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/2_integration_open.html"

    # def get_template_names(self):
    #     context = self.get_context_data(self.kwargs)
    #     return ['%s.html' % self.kwargs['template']]

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        context["active_url"] = "setup"
        context["content_owns_h1"] = True
        context["shell_heading"] = "Destinations"
        p_no = self.request.GET.get("p_no", 1)
        p_size = _bounded_page_size(self.request.GET.get("p_size"))
        integration_code = self.kwargs.get("integration_code")
        i_name = self.request.GET.get("i_name")
        member = self.request.user.member

        if (
            CoreStorageType.objects.filter(code=integration_code).exists()
            and integration_code != "bs"
        ):
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

            page = Paginator(storage_list, p_size).get_page(p_no)
            context["page"] = page
            context["elided_page_range"] = page.paginator.get_elided_page_range(
                page.number
            )
            context["page_sizes"] = CONNECTION_PAGE_SIZES
            context["storage"] = storage_type

            can_change_storage = member_has_perm(request, "storage_changes")

            if storage_type.code == "dropbox" and can_change_storage:
                # DROPBOX
                oauth_state = get_or_issue_oauth_state(
                    request,
                    provider="dropbox",
                    member=member,
                    account=member.get_current_account(),
                    use_pkce=True,
                )
                context["connect_url"] = (
                    "https://www.dropbox.com/oauth2/authorize?"
                    + urlencode(
                        {
                            "client_id": settings.DROPBOX_APP_KEY,
                            "response_type": "code",
                            "token_access_type": "offline",
                            "redirect_uri": f"{settings.APP_URL}/api/v1/callback/dropbox",
                            "state": oauth_state["state"],
                            "code_challenge": oauth_state["code_challenge"],
                            "code_challenge_method": "S256",
                        }
                    )
                )
            elif storage_type.code == "google_drive" and can_change_storage:
                # GOOGLE DRIVE
                scope = ["https://www.googleapis.com/auth/drive.file"]
                oauth_state = get_or_issue_oauth_state(
                    request,
                    provider="google_drive",
                    member=member,
                    account=member.get_current_account(),
                    use_pkce=True,
                )
                oauth = OAuth2Session(
                    settings.GOOGLE_CLIENT_ID,
                    redirect_uri=f"{settings.APP_URL}/api/v1/callback/google_drive/",
                    scope=scope,
                )
                authorization_url, state = oauth.authorization_url(
                    "https://accounts.google.com/o/oauth2/v2/auth",
                    state=oauth_state["state"],
                    access_type="offline",
                    prompt="consent",
                    code_challenge=oauth_state["code_challenge"],
                    code_challenge_method="S256",
                )
                context["connect_url"] = authorization_url
            elif storage_type.code == "pcloud":
                if can_change_storage:
                    oauth_state = get_or_issue_oauth_state(
                        request,
                        provider="pcloud",
                        member=member,
                        account=member.get_current_account(),
                        legacy_session_key="pcloud_oauth_state",
                    )
                    context["connect_url"] = (
                        f"{settings.PCLOUD_AUTH_URL}?"
                        + urlencode(
                            {
                                "client_id": settings.PCLOUD_CLIENT_ID,
                                "response_type": settings.PCLOUD_RESPONSE_TYPE,
                                "redirect_uri": settings.APP_URL + settings.PCLOUD_REDIRECT_URL,
                                "state": oauth_state["state"],
                            }
                        )
                    )
            elif storage_type.code == "onedrive" and can_change_storage:
                authorization_endpoint = validated_https_endpoint(
                    settings.MS_OAUTH_ENDPOINT,
                    allowed_hostnames={"login.microsoftonline.com"},
                    allowed_path_suffixes={"/oauth2/v2.0/authorize"},
                )
                if authorization_endpoint:
                    oauth_state = get_or_issue_oauth_state(
                        request,
                        provider="microsoft",
                        member=member,
                        account=member.get_current_account(),
                        use_pkce=True,
                    )
                    context["connect_url"] = authorization_endpoint + "?" + urlencode(
                        {
                            "client_id": settings.MS_CLIENT_ID,
                            "response_type": settings.MS_RESPONSE_TYPE,
                            "scope": settings.MS_SCOPE,
                            "prompt": "select_account",
                            "redirect_uri": settings.APP_URL + settings.MS_REDIRECT_URL,
                            "state": oauth_state["state"],
                            "code_challenge": oauth_state["code_challenge"],
                            "code_challenge_method": "S256",
                        }
                    )
        else:
            return redirect("console:setup:integration_select")

        return self.render_to_response(context)


class IntegrationCreateNodeView(LoginRequiredMixin, TemplateView):
    template_name = "console/setup/3_integration_create_node.html"

    def get(self, request, *args, **kwargs):
        if not (
            member_has_perm(request, "node_changes")
            and member_has_perm(request, "integration_changes")
        ):
            raise PermissionDenied(
                "You don't have permission to configure sources."
            )

        context = self.get_context_data(**kwargs)
        context["active_url"] = "setup"
        context["content_owns_h1"] = True
        context["shell_heading"] = "Add provider resources"
        integration_code = self.kwargs.get("integration_code")
        connection_id = self.kwargs.get("connection_id")
        object_code = self.kwargs.get("object_code")

        integration = get_object_or_404(CoreIntegration, code=integration_code)
        _require_supported_source_object_code(integration.code, object_code)

        if not source_backup_creation_available(integration_code):
            messages.error(request, SOURCE_RECOVERY_UNAVAILABLE_MESSAGE)
            return redirect(
                "console:setup:integration_open",
                integration_code=integration_code,
            )

        member = self.request.user.member

        query = Q(
            integration=integration,
            status=CoreConnection.Status.ACTIVE,
            id=connection_id,
        )
        connection = get_object_or_404(visible_connections(member), query)

        context["heading"] = f"Setup Node - {integration.name} - {connection.name}"

        context["integration"] = integration
        context["connection"] = connection
        (
            context["resource_label"],
            context["resource_label_plural"],
        ) = SOURCE_RESOURCE_LABELS.get(object_code, ("resource", "resources"))
        context["oauth_reconnect_available"] = (
            integration.code in OAUTH_RECONNECT_INTEGRATIONS
        )
        context["can_browse_source"] = True
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
        context["active_url"] = "nodes"
        context["content_owns_h1"] = True
        context["shell_heading"] = "Source configuration"
        integration_code = self.kwargs.get("integration_code")
        connection_id = self.kwargs.get("connection_id")
        node_id = self.kwargs.get("node_id")
        object_code = self.kwargs.get("object_code")

        member = self.request.user.member

        integration = get_object_or_404(CoreIntegration, code=integration_code)
        _require_supported_source_object_code(integration.code, object_code)

        query = Q(
            account=member.get_current_account(),
            integration=integration,
            status=CoreConnection.Status.ACTIVE,
            id=connection_id,
        )
        connection = get_object_or_404(CoreConnection, query)

        node = get_object_or_404(
            visible_nodes(member),
            id=node_id,
            connection=connection,
        )
        if not member_has_perm_for_node(request, "node_changes", node):
            raise PermissionDenied(
                "You don't have permission to configure this source."
            )

        context["heading"] = f"Modify Node - {integration.name} - {connection.name} - {node.name}"

        context["integration"] = integration
        context["connection"] = connection
        context["node"] = node
        (
            context["resource_label"],
            context["resource_label_plural"],
        ) = SOURCE_RESOURCE_LABELS.get(object_code, ("resource", "resources"))
        context["oauth_reconnect_available"] = (
            integration.code in OAUTH_RECONNECT_INTEGRATIONS
        )
        context["can_browse_source"] = member_has_perm(
            request, "integration_changes"
        )
        context["show_link_icon"] = True
        context["show_link_url"] = reverse(
            "console:node:detail",
            kwargs={"pk": node.id},
        )
        return self.render_to_response(context)
