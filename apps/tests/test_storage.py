from unittest import mock

from apps.console.storage.models import CoreStorage, CoreStorageAWSS3
from apps.tests import factories
from apps.tests.base import BaseTestCase


class StorageValidateTests(BaseTestCase):
    def test_validate_dispatches_to_provider(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        with mock.patch.object(CoreStorageAWSS3, "validate", return_value=True) as m:
            self.assertTrue(storage.validate())
            m.assert_called_once()
        with mock.patch.object(CoreStorageAWSS3, "validate", return_value=False):
            self.assertFalse(storage.validate())

    def test_aws_s3_validate_success(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        client = mock.MagicMock()
        client.put_object.return_value = {"ETag": "abc"}
        client.get_object.return_value = {"ETag": "abc"}
        client.delete_object.return_value = {"ResponseMetadata": {"HTTPStatusCode": 204}}
        with mock.patch("boto3.client", return_value=client):
            self.assertTrue(storage.storage_aws_s3.validate())
        client.put_object.assert_called_once()
        client.delete_object.assert_called_once()  # cleanup of the test object

    def test_aws_s3_validate_failure_when_upload_has_no_etag(self):
        storage = factories.make_storage(self.account, self.member, code="aws_s3")
        client = mock.MagicMock()
        client.put_object.return_value = {}  # no ETag -> failure
        with mock.patch("boto3.client", return_value=client):
            self.assertFalse(storage.storage_aws_s3.validate())

    def test_storage_defaults_active_and_is_account_scoped(self):
        storage = factories.make_storage(self.account, self.member)
        self.assertEqual(storage.status, CoreStorage.Status.ACTIVE)
        self.assertEqual(storage.account, self.account)
