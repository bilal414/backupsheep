from django.test import TestCase

from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from apps.console.member.models import CoreMemberAccount
from apps.console.setting.models import CoreSiteSettings
from apps.console.utils.models import UtilBackup
from apps.console.backup.models import CoreDigitalOceanBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


class EncryptionTests(BaseTestCase):
    def test_account_key_roundtrip(self):
        key = self.account.get_encryption_key()
        token = bs_encrypt("hunter2", key)
        self.assertNotIn(b"hunter2", bytes(token))
        self.assertEqual(bs_decrypt(token, key), "hunter2")

    def test_decrypt_none_is_none(self):
        self.assertIsNone(bs_decrypt(None, self.account.get_encryption_key()))


class AccountGraphTests(BaseTestCase):
    def test_owner_chain_is_wired(self):
        membership = CoreMemberAccount.objects.get(member=self.member, account=self.account)
        self.assertTrue(membership.primary and membership.current)
        self.assertEqual(self.member.user, self.user)
        self.assertIn(self.account, self.member.accounts.all())


class SiteSettingsFallbackTests(TestCase):
    def test_getters_fall_back_to_env(self):
        s = CoreSiteSettings.load()  # all blank
        from django.conf import settings as dj
        self.assertEqual(s.get_app_name(), getattr(dj, "APP_NAME", "BackupSheep"))
        self.assertEqual(s.get_email_provider(), getattr(dj, "EMAIL_PROVIDER", "none"))

    def test_db_value_overrides_env(self):
        s = CoreSiteSettings.load()
        s.app_name = "Custom Name"
        s.save()
        self.assertEqual(CoreSiteSettings.load().get_app_name(), "Custom Name")

    def test_email_cred_prefers_db_then_env(self):
        s = CoreSiteSettings.load()
        s.email_provider = "postmark"
        s.set_email_credentials({"postmark": {"api_key": "db-key"}})
        s.save()
        s = CoreSiteSettings.load()
        self.assertEqual(s.email_cred("api_key", "POSTMARK_API_KEY"), "db-key")
        # unset cred -> env fallback
        from django.conf import settings as dj
        self.assertEqual(s.email_cred("api_url", "POSTMARK_API_URL"),
                         getattr(dj, "POSTMARK_API_URL", None))


class NodeHelperTests(BaseTestCase):
    def test_get_cloud_backup_returns_provider_backup(self):
        node = factories.make_cloud_node(self.account, self.member, code="digitalocean")
        backup = CoreDigitalOceanBackup.objects.create(
            digitalocean=node.digitalocean, status=UtilBackup.Status.IN_PROGRESS,
        )
        self.assertEqual(node.get_cloud_backup(backup.id).id, backup.id)
        self.assertIsNone(node.get_cloud_backup(999999))
