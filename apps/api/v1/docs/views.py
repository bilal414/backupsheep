"""OpenAPI document and bundled documentation UIs.

The schema is generated once per process and memoized: generating ~900
operations is CPU-bound, so an unauthenticated (or authenticated) client must
not be able to turn each request into a fresh generation run.
"""

from django.utils import translation
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework.response import Response

from apps.api.v1.utils.api_throttles import ApiDocsRateThrottle

# Import for the side effect of registering the authentication extensions.
from apps.api.v1.docs import schema  # noqa: F401


class ApiSchemaView(SpectacularAPIView):
    throttle_classes = [ApiDocsRateThrottle]
    _schema_cache = {}

    def _get_schema_response(self, request):
        version = self.api_version or request.version or self._get_version_parameter(request)
        key = (version, self.serve_public, translation.get_language())
        document = self._schema_cache.get(key)
        if document is None:
            generator = self.generator_class(
                urlconf=self.urlconf, api_version=version, patterns=self.patterns
            )
            document = generator.get_schema(request=request, public=self.serve_public)
            self._schema_cache[key] = document
        return Response(
            data=document,
            headers={
                "Content-Disposition": f'inline; filename="{self._get_filename(request, version)}"'
            },
        )


class ApiRedocView(SpectacularRedocView):
    # Local template: no third-party font or script origins.
    template_name = "console/api_docs/redoc.html"
    throttle_classes = [ApiDocsRateThrottle]


class ApiSwaggerView(SpectacularSwaggerView):
    throttle_classes = [ApiDocsRateThrottle]
