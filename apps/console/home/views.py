from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "console/home/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        member = self.request.user.member

        context["member"] = member
        context["heading"] = "Dashboard"
        context["active_url"] = "dashboard"
        return self.render_to_response(context)
