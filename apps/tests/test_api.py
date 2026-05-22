from unittest import mock

from rest_framework.test import APIRequestFactory

from apps.api.v1.storage.views import CoreStorageView
from apps.tests import factories
from apps.tests.base import BaseTestCase


class ApiAuthTests(BaseTestCase):
    def test_protected_endpoint_rejects_anonymous(self):
        view = CoreStorageView.as_view({"get": "list"})
        resp = view(APIRequestFactory().get("/api/storage/"))
        self.assertIn(resp.status_code, (401, 403))


class ApiAccountScopingTests(BaseTestCase):
    def test_storage_queryset_is_scoped_to_current_account(self):
        # my storage
        mine = factories.make_storage(self.account, self.member)
        # another tenant's storage must never appear
        other_account, other_member, _ = factories.make_account()
        theirs = factories.make_storage(other_account, other_member)

        request = mock.MagicMock()
        request.user = self.user
        view = CoreStorageView()
        view.request = request
        view.kwargs = {}

        ids = set(view.get_queryset().values_list("id", flat=True))
        self.assertIn(mine.id, ids)
        self.assertNotIn(theirs.id, ids)
