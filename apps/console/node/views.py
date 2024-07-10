import pytz
from django.db.models import Q, Sum, Count
from django.views.generic import TemplateView, DetailView
from django.core.paginator import Paginator
from rest_framework.permissions import IsAuthenticated

from apps.console.backup.models import CoreWebsiteBackupStoragePoints, CoreDatabaseBackupStoragePoints, \
    CoreWordPressBackupStoragePoints
from apps.console.connection.models import CoreConnection
from apps.console.node.models import CoreNode, CoreDigitalOcean
from apps.console.storage.models import CoreStorage
from apps.api.v1.node.serializers import CoreNodeSerializer
from django.contrib.auth.mixins import AccessMixin, LoginRequiredMixin

from apps.console.utils.models import UtilBackup


class NodeView(LoginRequiredMixin, TemplateView):
    template_name = "console/node/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        p_no = self.request.GET.get("p_no", 1)
        p_size = self.request.GET.get("p_size", 10)
        node_type = self.request.GET.get("type")

        s_node = self.request.GET.get("s_node")
        s_integration = self.request.GET.get("s_integration")
        s_status = self.request.GET.get("s_status")
        s_type = self.request.GET.get("s_type")
        s_endpoint = self.request.GET.get("s_endpoint")

        member = self.request.user.member
        query = Q(connection__account=member.get_current_account())
        query_total = query

        if node_type == "server":
            query &= Q(type=CoreNode.Type.CLOUD)
        elif node_type == "volume":
            query &= Q(type=CoreNode.Type.VOLUME)
        elif node_type == "website":
            query &= Q(type=CoreNode.Type.WEBSITE)
        elif node_type == "database":
            query &= Q(type=CoreNode.Type.DATABASE)
        elif node_type == "saas":
            query &= Q(type=CoreNode.Type.SAAS)

        # search filters
        if s_node:
            query &= Q(name__icontains=s_node)
        if s_integration:
            query &= Q(connection__name__icontains=s_integration)
        if s_status:
            query &= Q(status=s_status)
        if s_type:
            query &= Q(type=s_type)
        if s_endpoint:
            query &= Q(connection__location__name__icontains=s_endpoint)

        nodes = CoreNode.objects.filter(query).order_by("-created")

        context["heading"] = "Nodes"
        context["active_url"] = "nodes"
        context["account"] = member.get_current_account()
        context["node_type"] = node_type
        context["node_count"] = CoreNode.objects.filter(
            connection__account=member.get_current_account()
        ).count()
        context["total_clouds"] = CoreNode.objects.filter(
            Q(type=CoreNode.Type.CLOUD), query_total
        ).count()
        context["total_volumes"] = CoreNode.objects.filter(
            Q(type=CoreNode.Type.VOLUME), query_total
        ).count()
        context["total_websites"] = CoreNode.objects.filter(
            Q(type=CoreNode.Type.WEBSITE), query_total
        ).count()
        context["total_database"] = CoreNode.objects.filter(
            Q(type=CoreNode.Type.DATABASE), query_total
        ).count()
        context["total_saas"] = CoreNode.objects.filter(
            Q(type=CoreNode.Type.SAAS), query_total
        ).count()



        s_query = Q(account=member.get_current_account())
        s_query &= ~Q(status=CoreStorage.Status.PAUSED)
        storage_list = CoreStorage.objects.filter(s_query).order_by("type__position")
        context["storage_list"] = storage_list

        page = Paginator(nodes, p_size).page(p_no)
        context["page"] = page
        context["type"] = node_type
        context["elided_page_range"] = page.paginator.get_elided_page_range(p_no)
        context["s_node"] = self.request.GET.get("s_node")
        context["s_integration"] = self.request.GET.get("s_integration")
        context["s_storage"] = self.request.GET.get("s_storage")
        context["s_endpoint"] = self.request.GET.get("s_endpoint")
        context["s_status"] = self.request.GET.get("s_status")
        context["s_type"] = self.request.GET.get("s_type")
        return self.render_to_response(context)


class NodeDetailView(LoginRequiredMixin, DetailView):
    model = CoreNode
    template_name = "console/node/detail.html"
    permission_denied_message = "You don't have access to this node"

    def get_context_data(self, **kwargs):
        # Call the base implementation first to get a context
        context = super().get_context_data(**kwargs)
        member = self.request.user.member
        p_no = self.request.GET.get("p_no", 1)
        p_size = self.request.GET.get("p_size", 10)
        list_all_backups = self.request.GET.get("list_all_backups", False)

        if list_all_backups == "true" or list_all_backups == "True":
            list_all_backups = True
        page = Paginator(
            self.get_object().list_backups(list_all_backups).order_by("-created"),
            p_size,
        ).page(p_no)

        query = Q(account=member.get_current_account())
        query &= ~Q(status=CoreStorage.Status.PAUSED)
        storage_list = CoreStorage.objects.filter(query).order_by("type__position")

        # Add in a QuerySet of all the books
        context[
            "heading"
        ] = f"{self.get_object().get_type_display()} | {self.get_object().get_integration_alt_name()} | {self.get_object().name}"
        context["active_url"] = "nodes"
        context["page"] = page
        context["elided_page_range"] = page.paginator.get_elided_page_range(p_no)
        context["storage_list"] = storage_list
        context["timezones"] = pytz.all_timezones
        context["list_all_backups"] = list_all_backups
        context["backup_count"] = (
            self.get_object().list_backups(list_all_backups).count()
        )
        return context

    def get_queryset(self, **kwargs):
        member = self.request.user.member
        query = Q(connection__account=member.get_current_account())
        # query &= ~Q(status=CoreNode.Status.DELETE_REQUESTED)
        queryset = CoreNode.objects.filter(query)
        return queryset
