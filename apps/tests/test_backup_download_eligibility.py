import uuid
from unittest import mock

from django.test import override_settings
from rest_framework import status
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.api.v1.backup.basecamp.serializers import (
    CoreBasecampBackupStoragePointsSerializer,
)
from apps.api.v1.backup.basecamp.views import CoreBasecampBackupView
from apps.api.v1.backup.database.views import CoreDatabaseBackupView
from apps.api.v1.backup.database.serializers import (
    CoreDatabaseBackupStoragePointsSerializer,
)
from apps.api.v1.backup.wordpress.serializers import (
    CoreWordPressBackupStoragePointsSerializer,
)
from apps.api.v1.backup.wordpress.views import CoreWordPressBackupView
from apps.api.v1.backup.website.serializers import (
    CoreWebsiteBackupStoragePointsSerializer,
)
from apps.api.v1.backup.website.views import CoreWebsiteBackupView
from apps.console.backup.models import (
    CoreBasecampBackup,
    CoreBasecampBackupStoragePoints,
    CoreDatabaseBackup,
    CoreDatabaseBackupStoragePoints,
    CoreWebsiteBackup,
    CoreWebsiteBackupStoragePoints,
    CoreWordPressBackup,
    CoreWordPressBackupStoragePoints,
)
from apps.console.node.models import (
    CoreBasecamp,
    CoreDatabase,
    CoreNode,
    CoreWordPress,
)
from apps.console.utils.models import UtilBackup
from apps.tests import factories
from apps.tests.base import BaseTestCase


@override_settings(
    BACKUPSHEEP_ARTIFACT_ALLOW_LEGACY_RESTORE=True,
    BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=False,
)
class BackupDownloadEligibilityTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()
        self.storage = factories.make_storage(
            self.account,
            self.member,
            code="aws_s3",
            bucket="download-eligibility",
        )
        self.website_node = factories.make_website_node(self.account, self.member)

        database_connection = factories.make_connection(
            self.account,
            self.member,
            code="database",
        )
        self.database_node = CoreNode.objects.create(
            connection=database_connection,
            type=CoreNode.Type.DATABASE,
            name="database source",
            added_by=self.member,
        )
        CoreDatabase.objects.create(
            node=self.database_node,
            name="database source",
        )

    def _case(
        self,
        family,
        *,
        backup_status=UtilBackup.Status.COMPLETE,
        point_status=None,
        storage_file_id="backups/complete-copy.zip",
    ):
        if family == "website":
            backup = CoreWebsiteBackup.objects.create(
                website=self.website_node.website,
                uuid=f"download-{uuid.uuid4().hex}",
                status=backup_status,
                type=UtilBackup.Type.ON_DEMAND,
            )
            point_model = CoreWebsiteBackupStoragePoints
            point = point_model.objects.create(
                backup=backup,
                storage=self.storage,
                status=(
                    point_status
                    if point_status is not None
                    else point_model.Status.UPLOAD_COMPLETE
                ),
                storage_file_id=storage_file_id,
            )
            return CoreWebsiteBackupView, backup, point

        if family == "database":
            backup = CoreDatabaseBackup.objects.create(
                database=self.database_node.database,
                uuid=f"download-{uuid.uuid4().hex}",
                status=backup_status,
                type=UtilBackup.Type.ON_DEMAND,
            )
            point_model = CoreDatabaseBackupStoragePoints
            view_class = CoreDatabaseBackupView
        else:
            source_model, backup_model, point_model, view_class = {
                "wordpress": (
                    CoreWordPress,
                    CoreWordPressBackup,
                    CoreWordPressBackupStoragePoints,
                    CoreWordPressBackupView,
                ),
                "basecamp": (
                    CoreBasecamp,
                    CoreBasecampBackup,
                    CoreBasecampBackupStoragePoints,
                    CoreBasecampBackupView,
                ),
            }[family]
            connection = factories.make_connection(
                self.account,
                self.member,
                code=family,
                name=f"{family}-{uuid.uuid4().hex[:8]}",
            )
            node = CoreNode.objects.create(
                connection=connection,
                type=CoreNode.Type.SAAS,
                name=f"{family} source",
                added_by=self.member,
            )
            source = source_model.objects.create(
                node=node,
                name=f"{family} source",
            )
            backup = backup_model.objects.create(
                **{family: source},
                uuid=f"download-{uuid.uuid4().hex}",
                status=backup_status,
                type=UtilBackup.Type.ON_DEMAND,
            )
        point = point_model.objects.create(
            backup=backup,
            storage=self.storage,
            status=(
                point_status
                if point_status is not None
                else point_model.Status.UPLOAD_COMPLETE
            ),
            storage_file_id=storage_file_id,
        )
        return view_class, backup, point

    def _download(self, view_class, backup, point, *, user=None):
        request = self.factory.get(
            f"/api/v1/backups/{backup.pk}/download/",
            {"storage_point_id": point.pk},
        )
        force_authenticate(request, user=user or self.user)
        view = view_class.as_view({"get": "download"})
        return view(request, pk=backup.pk)

    def test_complete_uploaded_copy_with_object_id_can_generate_download(self):
        for family in ("website", "database", "wordpress", "basecamp"):
            with self.subTest(family=family):
                view_class, backup, point = self._case(family)
                with mock.patch.object(
                    type(point),
                    "generate_download_url",
                    return_value="https://download.invalid/complete-copy",
                ) as generate:
                    response = self._download(view_class, backup, point)

                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                self.assertEqual(
                    response.data["url"],
                    "https://download.invalid/complete-copy",
                )
                generate.assert_called_once_with()

    def test_exact_local_stream_target_is_allowed_for_each_backup_family(self):
        for family in ("website", "database", "wordpress", "basecamp"):
            with self.subTest(family=family):
                view_class, backup, point = self._case(family)
                expected = (
                    f"/api/v1/storage/local/file/{family}/{point.pk}/"
                )
                with mock.patch.object(
                    type(point),
                    "generate_download_url",
                    return_value=expected,
                ) as generate:
                    response = self._download(view_class, backup, point)

                self.assertEqual(response.status_code, status.HTTP_201_CREATED)
                self.assertEqual(response.data["url"], expected)
                generate.assert_called_once_with()

    def test_unsafe_provider_targets_are_rejected_by_each_download_api(self):
        unsafe_targets = (
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
            "http://download.invalid/archive.zip",
            "//download.invalid/archive.zip",
            "/api/v1/storage/local/file/website/1/?redirect=javascript:alert(1)",
            "https://download.invalid\\@attacker.invalid/archive.zip",
            "https://user:password@download.invalid/archive.zip",
            "https://download.invalid:99999/archive.zip",
        )

        for family in ("website", "database", "wordpress", "basecamp"):
            for unsafe_target in unsafe_targets:
                with self.subTest(family=family, target=unsafe_target):
                    view_class, backup, point = self._case(family)
                    with mock.patch.object(
                        type(point),
                        "generate_download_url",
                        return_value=unsafe_target,
                    ) as generate:
                        response = self._download(view_class, backup, point)

                    self.assertEqual(
                        response.status_code,
                        status.HTTP_503_SERVICE_UNAVAILABLE,
                    )
                    self.assertNotIn(unsafe_target, str(response.data))
                    generate.assert_called_once_with()

    def test_incomplete_backup_or_copy_never_reaches_download_provider(self):
        for family in ("website", "database", "wordpress", "basecamp"):
            point_model = {
                "website": CoreWebsiteBackupStoragePoints,
                "database": CoreDatabaseBackupStoragePoints,
                "wordpress": CoreWordPressBackupStoragePoints,
                "basecamp": CoreBasecampBackupStoragePoints,
            }[family]
            invalid_cases = (
                {
                    "name": "backup_not_complete",
                    "backup_status": UtilBackup.Status.IN_PROGRESS,
                },
                {
                    "name": "copy_not_uploaded",
                    "point_status": point_model.Status.UPLOAD_IN_PROGRESS,
                },
                {"name": "object_id_null", "storage_file_id": None},
                {"name": "object_id_empty", "storage_file_id": ""},
            )
            for invalid in invalid_cases:
                case_name = invalid["name"]
                overrides = {
                    key: value
                    for key, value in invalid.items()
                    if key != "name"
                }
                with self.subTest(family=family, case=case_name):
                    view_class, backup, point = self._case(family, **overrides)
                    with mock.patch.object(
                        type(point),
                        "generate_download_url",
                        return_value="https://download.invalid/unsafe",
                    ) as generate, mock.patch(
                        "apps.api.v1.backup.website.views.capture_exception"
                    ):
                        response = self._download(view_class, backup, point)

                    self.assertEqual(
                        response.status_code,
                        status.HTTP_503_SERVICE_UNAVAILABLE,
                    )
                    generate.assert_not_called()

    def test_hidden_backup_remains_scoped_as_not_found(self):
        _other_account, _other_member, other_user = factories.make_account()

        for family in ("website", "database", "wordpress", "basecamp"):
            with self.subTest(family=family):
                view_class, backup, point = self._case(family)
                with mock.patch.object(
                    type(point),
                    "generate_download_url",
                    return_value="https://download.invalid/hidden",
                ) as generate:
                    response = self._download(
                        view_class,
                        backup,
                        point,
                        user=other_user,
                    )

                self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
                generate.assert_not_called()

    def test_provider_failure_remains_generic(self):
        provider_detail = "credential=provider-secret-canary"

        for family in ("website", "database", "wordpress", "basecamp"):
            with self.subTest(family=family):
                view_class, backup, point = self._case(family)
                with mock.patch.object(
                    type(point),
                    "generate_download_url",
                    side_effect=RuntimeError(provider_detail),
                ), mock.patch(
                    "apps.api.v1.backup.website.views.capture_exception"
                ):
                    response = self._download(view_class, backup, point)

                self.assertEqual(
                    response.status_code,
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                )
                self.assertNotIn(provider_detail, str(response.data))

    def test_enterprise_policy_is_exposed_and_rejected_before_provider_access(self):
        serializers = {
            "website": CoreWebsiteBackupStoragePointsSerializer,
            "database": CoreDatabaseBackupStoragePointsSerializer,
            "wordpress": CoreWordPressBackupStoragePointsSerializer,
            "basecamp": CoreBasecampBackupStoragePointsSerializer,
        }
        with override_settings(BACKUPSHEEP_ARTIFACT_ENTERPRISE_MODE=True):
            for family in ("website", "database", "wordpress", "basecamp"):
                with self.subTest(family=family):
                    view_class, backup, point = self._case(family)
                    self.assertFalse(
                        serializers[family](point).data[
                            "direct_download_permitted"
                        ]
                    )
                    with mock.patch.object(
                        type(point),
                        "generate_download_url",
                        return_value="https://download.invalid/policy-bypass",
                    ) as generate:
                        response = self._download(view_class, backup, point)
                    self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
                    self.assertEqual(
                        response.data["code"],
                        "direct_download_not_permitted",
                    )
                    generate.assert_not_called()
