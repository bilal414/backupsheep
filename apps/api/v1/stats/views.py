from datetime import datetime, time, timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.v1.utils.api_helpers import visible_nodes
from apps.console.backup.models import (
    CoreAWSBackup,
    CoreAWSRDSBackup,
    CoreBasecampBackup,
    CoreDatabaseBackup,
    CoreDigitalOceanBackup,
    CoreGoogleCloudBackup,
    CoreHetznerBackup,
    CoreLightsailBackup,
    CoreOracleBackup,
    CoreOVHCABackup,
    CoreOVHEUBackup,
    CoreOVHUSBackup,
    CoreUpCloudBackup,
    CoreVultrBackup,
    CoreVultrDatabaseBackup,
    CoreWebsiteBackup,
    CoreWordPressBackup,
)
from apps.console.utils.models import UtilBackup


class BackupActivityView(APIView):
    """Return the dashboard backup activity shape used by the iOS client."""

    permission_classes = (IsAuthenticated,)

    SOURCES = {
        "Database": (
            (CoreDatabaseBackup, "database"),
        ),
        "Website": (
            (CoreWebsiteBackup, "website"),
            (CoreWordPressBackup, "wordpress"),
        ),
        "Cloud": (
            (CoreBasecampBackup, "basecamp"),
            (CoreDigitalOceanBackup, "digitalocean"),
            (CoreAWSBackup, "aws"),
            (CoreAWSRDSBackup, "aws_rds"),
            (CoreLightsailBackup, "lightsail"),
            (CoreHetznerBackup, "hetzner"),
            (CoreUpCloudBackup, "upcloud"),
            (CoreOVHCABackup, "ovh_ca"),
            (CoreOVHEUBackup, "ovh_eu"),
            (CoreOVHUSBackup, "ovh_us"),
            (CoreVultrBackup, "vultr"),
            (CoreVultrDatabaseBackup, "vultr_database"),
            (CoreOracleBackup, "oracle"),
            (CoreGoogleCloudBackup, "google_cloud"),
        ),
    }

    @staticmethod
    def _day_range():
        today = timezone.localdate()
        first_day = today - timedelta(days=29)
        current_timezone = timezone.get_current_timezone()
        start = timezone.make_aware(
            datetime.combine(first_day, time.min), current_timezone
        )
        end = timezone.make_aware(
            datetime.combine(today + timedelta(days=1), time.min), current_timezone
        )
        days = [first_day + timedelta(days=offset) for offset in range(30)]
        return days, start, end, current_timezone

    @classmethod
    def _counts_for_source(cls, nodes, model, relation, start, end, current_timezone):
        node_filter = {f"{relation}__node__in": nodes}
        rows = (
            model.objects.filter(
                **node_filter,
                created__gte=start,
                created__lt=end,
            )
            .exclude(status=UtilBackup.Status.DELETE_REQUESTED)
            .annotate(day=TruncDate("created", tzinfo=current_timezone))
            .values("day")
            .annotate(total=Count("id"))
        )
        return {row["day"]: row["total"] for row in rows}

    def get(self, request):
        days, start, end, current_timezone = self._day_range()
        nodes = visible_nodes(request.user.member)
        series = []

        for name, sources in self.SOURCES.items():
            counts = {}
            for model, relation in sources:
                for day, total in self._counts_for_source(
                    nodes, model, relation, start, end, current_timezone
                ).items():
                    counts[day] = counts.get(day, 0) + total

            series.append(
                {
                    "name": name,
                    "data": [counts.get(day, 0) for day in days],
                }
            )

        return Response(
            {
                "categories": [f"{day.day} {day.strftime('%b')}" for day in days],
                "series": series,
            }
        )
