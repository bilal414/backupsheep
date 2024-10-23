from random import randint

import requests
from django.conf import settings
from django.utils.text import slugify
from django.views.generic import TemplateView
from django.contrib.auth.mixins import AccessMixin, LoginRequiredMixin
from requests.auth import HTTPBasicAuth

from apps.console.member.models import CoreMember


class ReferralView(LoginRequiredMixin, TemplateView):
    template_name = "console/referral/index.html"

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        member = request.user.member
        context["affiliate"] = None
        context["affiliate_sso_url"] = None

        if not member.affiliate_id:
            params = {
                "email": member.user.email,
            }
            r = requests.get(
                f"https://api.getrewardful.com/v1/affiliates",
                params=params,
                auth=HTTPBasicAuth(settings.REWARDFUL_API_SECRET, None),
            )
            if r.status_code == 200:
                if len(r.json()["data"]) == 1:
                    affiliate = r.json()["data"][0]
                    member.affiliate_id = affiliate["id"]
                    member.save()
                elif len(r.json()["data"]) == 0:
                    data = {
                        "first_name": slugify(
                            member.user.first_name
                            if (member.user.first_name and member.user.first_name != "")
                            else "n/a"
                        ),
                        "last_name": slugify(
                            member.user.last_name if (member.user.last_name and member.user.last_name != "") else "n/a"
                        ),
                        "email": f"{member.user.email}",
                        "token": slugify(f"bs-{member.id}"),
                    }
                    r = requests.post(
                        "https://api.getrewardful.com/v1/affiliates",
                        data=data,
                        auth=HTTPBasicAuth(settings.REWARDFUL_API_SECRET, None),
                    )

                    if r.status_code == 200:
                        affiliate = r.json()
                        member.affiliate_id = affiliate["id"]
                        member.save()

        if member.affiliate_id:
            # get login url
            r = requests.get(
                f"https://api.getrewardful.com/v1/affiliates/{member.affiliate_id}/sso",
                auth=HTTPBasicAuth(settings.REWARDFUL_API_SECRET, None),
            )

            if r.status_code == 200:
                context["affiliate_sso_url"] = r.json()["sso"]["url"]

            # get affiliate data
            r = requests.get(
                f"https://api.getrewardful.com/v1/affiliates/{member.affiliate_id}",
                auth=HTTPBasicAuth(settings.REWARDFUL_API_SECRET, None),
            )

            if r.status_code == 200:
                context["affiliate"] = r.json()

        context["heading"] = "Referral Program"

        return self.render_to_response(context)
