from django.views.generic import TemplateView


class ErrorView(TemplateView):
    template_name = "console/error/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        error_type = self.kwargs.get("error_type")
        heading = "Error"

        if error_type == "member_not_exist":
            heading = "Member does not exist"

        context["heading"] = heading
        return self.render_to_response(context)
