from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase

from utils.middleware import BrowserSecurityHeadersMiddleware


class BrowserSecurityHeadersTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = BrowserSecurityHeadersMiddleware(
            lambda request: HttpResponse("ok")
        )

    def test_dynamic_responses_are_non_cacheable_and_browser_constrained(self):
        response = self.middleware(self.factory.get("/console/settings/users/"))

        self.assertEqual(response["Cache-Control"], "no-store, private, max-age=0")
        self.assertEqual(response["Pragma"], "no-cache")
        self.assertIn("object-src 'none'", response["Content-Security-Policy"])
        self.assertIn("form-action 'self'", response["Content-Security-Policy"])
        self.assertIn("camera=()", response["Permissions-Policy"])

    def test_static_and_health_responses_keep_their_existing_cache_policy(self):
        for path in ("/static/console/app.js", "/healthz/"):
            with self.subTest(path=path):
                response = self.middleware(self.factory.get(path))
                self.assertNotIn("Cache-Control", response)
                self.assertIn("Content-Security-Policy", response)
                self.assertIn("Permissions-Policy", response)
