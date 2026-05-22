from django.test import TestCase

from apps.tests import factories


class BaseTestCase(TestCase):
    """Common base: a ready-made account/member/user, and a reset of the onboarding
    middleware's process-global latch so gating tests are deterministic."""

    def setUp(self):
        super().setUp()
        try:
            from utils.middleware import OnboardingMiddleware
            OnboardingMiddleware._completed = False
        except Exception:
            pass
        self.account, self.member, self.user = factories.make_account()
