from django.db.models import Q
from django.views.generic import TemplateView
from django.core.paginator import Paginator

from apps.console.log.models import CoreLog
from django.contrib.auth.mixins import AccessMixin, LoginRequiredMixin


class LogView(LoginRequiredMixin, TemplateView):
    template_name = "console/log/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        p_no = self.request.GET.get("p_no", 1)
        p_size = self.request.GET.get("p_size", 50)
        node = self.request.GET.get("node")
        backup = self.request.GET.get("backup")
        integration = self.request.GET.get("integration")
        message = self.request.GET.get("message")
        error = self.request.GET.get("error")

        if p_size:
            if int(p_size) > 100:
                p_size = 100

        member = self.request.user.member
        query = Q(account=member.get_current_account())

        if node:
            query &= Q(data__node_id=int(node))

        if backup:
            query &= Q(data__backup_id=int(backup))

        if integration:
            query &= Q(data__connection_id=int(integration))

        logs = CoreLog.objects.filter(query).order_by("-created")

        context["heading"] = "Logs"
        context["active_url"] = "logs"
        context["account"] = member.get_current_account()
        context["node"] = node
        context["backup"] = backup
        context["logs_count"] = logs.count()
        context["integration"] = integration

        page = Paginator(logs, p_size).page(p_no)
        context["page"] = page
        context["elided_page_range"] = page.paginator.get_elided_page_range(p_no)
        return self.render_to_response(context)
