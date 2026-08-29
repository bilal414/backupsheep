import json
import os
import uuid
from datetime import timedelta
from decimal import Decimal

from apps.api.v1.utils.http import request_timeout, requests
from apps.api.v1.utils.boto import (
    bounded_boto3_client,
    bounded_ibm_boto3_client,
)
from django.db import models
from django.utils import timezone
from model_utils.models import TimeStampedModel
from sentry_sdk import capture_message, capture_exception

from ..account.models import CoreAccount
from ..connection.models import CoreAWSRegion, CoreWasabiRegion, CoreDoSpacesRegion, CoreFilebaseRegion, \
    CoreExoscaleRegion, CoreOracleRegion, CoreScalewayRegion, CoreTencentRegion, CoreAlibabaRegion, CoreIonosRegion, \
    CoreRackCorpRegion, CoreIBMRegion, _BoundedGoogleAuthorizedSession, _provider_sdk_timeout
from ..member.models import CoreMember
from apps.api.v1.utils.api_helpers import bs_encrypt, bs_decrypt


def _validation_object_key(prefix):
    """Return a collision-resistant probe key owned by this validation call."""
    normalized = str(prefix or "")
    if normalized and not normalized.endswith("/"):
        normalized += "/"
    return f"{normalized}backupsheep_test_{uuid.uuid4().hex}.txt"


def _read_validation_url(url):
    """Read a validation URL through the bounded provider HTTP facade."""
    try:
        response = requests.get(url, verify=True)
    except Exception:
        return None
    try:
        if int(getattr(response, "status_code", 0) or 0) != 200:
            return None
        return bytes(getattr(response, "content", b"") or b"")
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


class S3StorageConfigurationError(ValueError):
    """Typed, bounded S3 configuration error safe for an API response."""

    MESSAGES = {
        "OBJECT_LOCK_PAIR_REQUIRED": (
            "Object Lock mode and retention days must be configured together."
        ),
        "OBJECT_LOCK_RETENTION_INVALID": (
            "Object Lock retention must be at least one day."
        ),
        "EXPECTED_BUCKET_OWNER_INVALID": (
            "Expected bucket owner must be a 12-digit AWS account ID."
        ),
        "LIFECYCLE_PAIR_REQUIRED": (
            "Lifecycle transition days and storage class must be configured together."
        ),
        "LIFECYCLE_DAYS_INVALID": (
            "Lifecycle transition must be at least one day."
        ),
        "LIFECYCLE_PREFIX_REQUIRED": (
            "A folder prefix is required before BackupSheep can manage an S3 "
            "lifecycle rule."
        ),
        "OBJECT_LOCK_NOT_ENABLED": (
            "S3 Object Lock is not enabled for this bucket. Enable it before "
            "configuring retention."
        ),
    }
    DEFAULT_MESSAGE = "The S3 storage configuration is invalid."

    def __init__(self, code):
        self.code = str(code or "INVALID_CONFIGURATION")
        super().__init__(self.public_message(self.code))

    @classmethod
    def public_message(cls, code):
        return cls.MESSAGES.get(str(code or ""), cls.DEFAULT_MESSAGE)


class CoreStorageType(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    is_enabled = models.BooleanField(default=False)
    position = models.IntegerField(null=True)
    description = models.TextField(null=True)
    image = models.TextField(null=True)

    class Meta:
        db_table = "core_storage_type"


class CoreStorageDropbox(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_dropbox", on_delete=models.CASCADE
    )
    access_token = models.BinaryField(null=True)
    refresh_token = models.BinaryField(null=True)
    expiry = models.DateTimeField(null=True)
    token_type = models.CharField(max_length=255)
    account_id = models.CharField(max_length=255, null=True)
    team_id = models.CharField(max_length=255, null=True)
    uid = models.CharField(max_length=255, null=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_dropbox"

    def validate(self):
        import os
        import dropbox
        from dropbox.files import WriteMode
        from django.conf import settings

        file_name = str(uuid.uuid4()).split("-")[0]

        local_txt_file = f"_upload_test_files/backupsheep.txt"
        file_size = os.path.getsize(local_txt_file)
        chunk_size = 140 * 1024 * 1024
        dest_path = f"/{file_name}.txt"
        encryption_key = self.storage.account.get_encryption_key()
        access_token = bs_decrypt(self.access_token, encryption_key)
        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        dbx = dropbox.Dropbox(
            oauth2_access_token=access_token,
            oauth2_refresh_token=refresh_token,
            app_key=settings.DROPBOX_APP_KEY,
            app_secret=settings.DROPBOX_APP_SECRET,
            timeout=_provider_sdk_timeout()[1],
            max_retries_on_error=0,
            max_retries_on_rate_limit=0,
        )

        with open(local_txt_file, "rb") as file_to_upload:
            if file_size <= chunk_size:
                dbx_file = dbx.files_upload(
                    file_to_upload.read(),
                    str(dest_path),
                    dropbox.files.WriteMode.overwrite,
                )
                storage_file_id = dbx_file.id
            else:
                upload_session_start_result = dbx.files_upload_session_start(
                    file_to_upload.read(chunk_size)
                )
                session_id = upload_session_start_result.session_id
                cursor = dropbox.files.UploadSessionCursor(
                    session_id, offset=file_to_upload.tell()
                )
                commit = dropbox.files.CommitInfo(
                    path=dest_path, mode=dropbox.files.WriteMode.overwrite
                )
                while file_to_upload.tell() < file_size:
                    print((file_size - file_to_upload.tell()))
                    if (file_size - file_to_upload.tell()) <= chunk_size:
                        dbx_file = dbx.files_upload_session_finish(
                            file_to_upload.read(chunk_size), cursor, commit
                        )
                        storage_file_id = dbx_file.id

                    else:
                        print(cursor.offset)
                        dbx.files_upload_session_append_v2(
                            file_to_upload.read(chunk_size), cursor
                        )
                        # This is needed to upload. Ignore read only warning
                        cursor.offset = file_to_upload.tell()

        if storage_file_id:
            if not self.no_delete:
                dbx.files_delete_v2(dest_path)
            return True

    def get_refresh_token(self):
        from django.conf import settings
        from datetime import datetime
        import time

        encryption_key = self.storage.account.get_encryption_key()
        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        dropbox_url = "https://api.dropboxapi.com/oauth2/token"

        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.DROPBOX_APP_KEY,
            "client_secret": settings.DROPBOX_APP_SECRET,
        }

        token_request = requests.post(
            dropbox_url,
            data=params,
            headers={"Accept": "application/json"},
            allow_redirects=False,
            verify=True,
            timeout=request_timeout(),
        )

        if token_request.status_code == 200:
            token_data = token_request.json()
            self.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            self.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
            self.save()


class CoreStoragePCloud(TimeStampedModel):
    API_HOSTNAMES = frozenset({"api.pcloud.com", "eapi.pcloud.com"})

    class Location(models.IntegerChoices):
        US = 1, "US"
        EUROPE = 2, "EUROPE"

    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_pcloud", on_delete=models.CASCADE
    )
    access_token = models.BinaryField(null=True)
    token_type = models.CharField(max_length=255)
    userid = models.CharField(max_length=255, null=True)
    location = models.IntegerField(choices=Location.choices, null=True)
    hostname = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = "core_storage_pcloud"

    def get_client(self, file_upload=None, data=None):
        if data:
            access_token = data["access_token"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_token = bs_decrypt(self.access_token, encryption_key)

        client = {
            "Authorization": f"Bearer {access_token}",
        }

        if not file_upload:
            client["content-type"] = "application/json"
        # else:
        #     client["content-type"] = "application/json"

        return client

    def get_access_token(self):
        encryption_key = self.storage.account.get_encryption_key()

        return bs_decrypt(self.access_token, encryption_key)

    def validate(self, data=None, raise_exp=None):
        if data:
            hostname = data["hostname"]
            no_delete = data.get("no_delete")
        else:
            hostname = self.hostname
            no_delete = getattr(self, "no_delete", False)

        hostname = str(hostname or "").strip().lower().rstrip(".")
        if hostname not in self.API_HOSTNAMES:
            return False

        local_txt_file = "_upload_test_files/backupsheep.txt"
        filename = f"backupsheep_{uuid.uuid4().hex}.txt"
        pcloud_path = f"/validate/{filename}"
        headers = self.get_client(data=data)
        folder_response = requests.post(
            f"https://{hostname}/createfolderifnotexists",
            params={"path": "/validate"},
            headers=headers,
            verify=True,
            timeout=request_timeout(),
            allow_redirects=False,
        )
        if int(getattr(folder_response, "status_code", 0) or 0) >= 400:
            return False

        with open(local_txt_file, "rb") as file_to_upload:
            upload_response = requests.post(
                f"https://{hostname}/uploadfile",
                data={"path": "/validate", "renameifexists": 0},
                headers=headers,
                files={"file": (filename, file_to_upload, "text/plain")},
                verify=True,
                timeout=request_timeout(),
                allow_redirects=False,
            )
        if int(getattr(upload_response, "status_code", 0) or 0) >= 400:
            return False
        try:
            payload = upload_response.json()
        except Exception:
            return False
        metadata = payload.get("metadata") or []
        if metadata and metadata[0].get("path") == pcloud_path:
            if not no_delete:
                requests.post(
                    f"https://{hostname}/deletefile",
                    data={
                        "path": pcloud_path,
                        "fileid": metadata[0].get("fileid"),
                    },
                    headers=headers,
                    verify=True,
                    timeout=request_timeout(),
                    allow_redirects=False,
                )
            return True


class CoreStorageOneDrive(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_onedrive", on_delete=models.CASCADE
    )
    access_token = models.BinaryField(null=True)
    refresh_token = models.BinaryField(null=True)
    expiry = models.DateTimeField(null=True)
    token_type = models.CharField(max_length=255)
    scope = models.CharField(max_length=255)
    user_id = models.CharField(max_length=255, null=True)
    drive_id = models.CharField(max_length=255, null=True)
    drive_type = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_storage_onedrive"

    def get_client(self, data=None):
        encryption_key = self.storage.account.get_encryption_key()

        if data:
            access_token = data["access_token"]
            token_type = data["token_type"]
        else:
            access_token = bs_decrypt(self.access_token, encryption_key)
            token_type = self.token_type

        client = {
            "Authorization": f"{token_type.capitalize()} {access_token}",
            "content-type": "application/json"
        }

        return client

    def get_refresh_token(self):
        from django.conf import settings
        from datetime import datetime
        import time
        from apps.api.v1.utils.oauth_security import validated_https_endpoint

        encryption_key = self.storage.account.get_encryption_key()

        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.MS_CLIENT_ID,
            "client_secret": settings.MS_CLIENT_SECRET_VALUE,
        }

        token_endpoint = validated_https_endpoint(
            settings.MS_OAUTH_TOKEN_URL,
            allowed_hostnames={"login.microsoftonline.com"},
            allowed_path_suffixes={"/oauth2/v2.0/token"},
        )
        if token_endpoint is None:
            return False

        token_request = requests.post(
            token_endpoint,
            data=params,
            headers={"Accept": "application/json"},
            allow_redirects=False,
            verify=True,
            timeout=request_timeout(),
        )

        if token_request.status_code == 200:
            token_data = token_request.json()
            self.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            self.refresh_token = bs_encrypt(token_data["refresh_token"], encryption_key)
            self.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
            self.scope = token_data["scope"]
            self.save()
            return True
        else:
            return False

    def validate(self, data=None, raise_exp=None):
        from django.conf import settings

        url = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.drive_id}"

        drive_request = requests.request("GET", url, headers=self.get_client(data))

        if drive_request.status_code == 200:
            file_name = f"backupsheep_{uuid.uuid4().hex}.txt"
            local_file_path = "_upload_test_files/backupsheep.txt"
            target_file_path = f"backupsheep/{file_name}"

            onedrive_path = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.drive_id}/root:/{target_file_path}"

            # Upload file
            with open(local_file_path, "rb") as file_data:
                r = requests.put(
                    onedrive_path + ":/content", data=file_data, headers=self.get_client()
                )
            if r.status_code == 201 or r.status_code == 200:
                pass

            # Get file
            url = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.drive_id}/root:/{target_file_path}"
            file_request = requests.request("GET", url, headers=self.get_client(data))

            if file_request.status_code == 200:
                # Delete file
                delete_request = requests.request("DELETE", url, headers=self.get_client(data))
                if delete_request.status_code == 204:
                    return True


class CoreStorageGoogleDrive(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_google_drive", on_delete=models.CASCADE
    )
    access_token = models.BinaryField(null=True)
    refresh_token = models.BinaryField(null=True)
    expiry = models.DateTimeField(null=True)
    email_address = models.CharField(max_length=255)
    display_name = models.CharField(max_length=255, null=True)
    created_at = models.BigIntegerField(null=True)
    modified = models.BigIntegerField(null=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_google_drive"

    def get_client(self, data=None):
        import google.oauth2.credentials
        from django.conf import settings

        encryption_key = self.storage.account.get_encryption_key()
        access_token = bs_decrypt(self.access_token, encryption_key)
        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        credentials = google.oauth2.credentials.Credentials(
            access_token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
        )

        return _BoundedGoogleAuthorizedSession(credentials)

    def get_refresh_token(self):
        import google.oauth2.credentials
        from django.conf import settings
        from google.auth.transport.requests import Request

        encryption_key = self.storage.account.get_encryption_key()
        access_token = bs_decrypt(self.access_token, encryption_key)
        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        credentials = google.oauth2.credentials.Credentials(
            access_token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
        )

        # Token exchange is a provider POST. It gets the same finite timeout as
        # every other provider request and the shared session does not retry POST,
        # so a lost token response cannot be replayed by the HTTP adapter.
        refresh_session = requests.Session()
        refresh_session.max_redirects = 0
        request = Request(session=refresh_session)

        def bounded_request(**kwargs):
            kwargs["timeout"] = _provider_sdk_timeout()
            return request(**kwargs)

        credentials.refresh(bounded_request)
        self.access_token = bs_encrypt(credentials.token, encryption_key)
        self.refresh_token = bs_encrypt(credentials.refresh_token, encryption_key)
        self.expiry = credentials.expiry
        self.save()

    def validate(self):
        local_txt_file = "_upload_test_files/backupsheep.txt"
        bs_folder = None

        client = self.get_client()

        search_params = {
            "q": "name='BackupSheep' and trashed = False and mimeType='application/vnd.google-apps.folder'",
            "fields": "files(id, name, trashed)",
        }

        result = client.get(
            f"https://www.googleapis.com/drive/v3/files",
            params=search_params,
            headers={"Content-Type": "application/json; charset=UTF-8"},
        )

        if result.status_code == 200:
            files = result.json().get("files")

            bs_folder_list = [d['id'] for d in files if d['name'] == 'BackupSheep' and d['trashed'] is False]

            if len(bs_folder_list) > 0:
                bs_folder = bs_folder_list[0]
            else:
                file_metadata = {
                    "name": "BackupSheep",
                    "mimeType": "application/vnd.google-apps.folder",
                    # 'parents': [folder_id]
                }

                file_withmetadata = {"data": ("metadata", json.dumps(file_metadata), "application/json; charset=UTF-8")}

                result = client.post(
                    f"https://www.googleapis.com/upload/drive/v3/files",
                    files=file_withmetadata,
                )

                bs_folder = result.json()["id"]

        if bs_folder:
            file_metadata = {
                "name": f"backupsheep_{uuid.uuid4().hex}.txt",
                "mimeType": "text/plain",
                "parents": [bs_folder],
            }
            result = client.post(
                f"https://www.googleapis.com/upload/drive/v3/files/?uploadType=resumable",
                data=json.dumps(file_metadata),
                headers={"Content-Type": "application/json; charset=UTF-8"}
            )

            gdrive_upload_url = result.headers.get("Location")

            with open(local_txt_file, "rb") as f:
                total_file_size = os.path.getsize(local_txt_file)
                chunk_size = 6553600
                chunk_number = total_file_size // chunk_size
                chunk_leftover = total_file_size - chunk_size * chunk_number
                i = 0
                while True:
                    chunk_data = f.read(chunk_size)
                    start_index = i * chunk_size
                    end_index = start_index + chunk_size
                    # If end of file, break
                    if not chunk_data:
                        break
                    if i == chunk_number:
                        end_index = start_index + chunk_leftover
                    # Setting the header with the appropriate chunk data location in the file
                    headers = {
                        "Content-Length": "{}".format(total_file_size),
                        "Content-Range": "bytes {}-{}/{}".format(start_index, end_index - 1, total_file_size),
                    }
                    # Upload one chunk at a time
                    r = client.put(gdrive_upload_url, data=chunk_data, headers=headers)
                    i = i + 1

                    # Chunk accepted
                    if r.status_code == 201 or r.status_code == 200:
                        storage_file_id = r.json()["id"]

                        if self.no_delete:
                            return True
                        result = client.delete(
                            f"https://www.googleapis.com/drive/v3/files/{storage_file_id}",
                            headers={"Content-Type": "application/json; charset=UTF-8"},
                        )

                        if result.status_code == 204:
                            return True


class CoreStorageAWSS3(TimeStampedModel):
    class ObjectLockMode(models.TextChoices):
        GOVERNANCE = "GOVERNANCE", "Governance"
        COMPLIANCE = "COMPLIANCE", "Compliance"

    class LifecycleStorageClass(models.TextChoices):
        STANDARD_IA = "STANDARD_IA", "Standard-IA"
        ONEZONE_IA = "ONEZONE_IA", "One Zone-IA"
        INTELLIGENT_TIERING = "INTELLIGENT_TIERING", "Intelligent-Tiering"
        GLACIER_IR = "GLACIER_IR", "Glacier Instant Retrieval"
        GLACIER = "GLACIER", "Glacier Flexible Retrieval"
        DEEP_ARCHIVE = "DEEP_ARCHIVE", "Glacier Deep Archive"

    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_aws_s3", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField(null=True)
    access_key = models.BinaryField(null=True)
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    region = models.ForeignKey(
        CoreAWSRegion, related_name="storage_aws_s3", on_delete=models.PROTECT, null=True
    )
    encryption_updated = models.BooleanField(default=False)
    object_lock_mode = models.CharField(
        choices=ObjectLockMode.choices, max_length=16, blank=True, default=""
    )
    object_lock_retain_days = models.PositiveIntegerField(null=True, blank=True)
    expected_bucket_owner = models.CharField(max_length=12, null=True, blank=True)
    lifecycle_transition_days = models.PositiveIntegerField(null=True, blank=True)
    lifecycle_storage_class = models.CharField(
        choices=LifecycleStorageClass.choices, max_length=32, blank=True, default=""
    )
    lifecycle_last_synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "core_storage_aws_s3"

    @staticmethod
    def normalize_prefix(prefix):
        if prefix and not prefix.endswith("/"):
            return f"{prefix}/"
        return prefix or ""

    @staticmethod
    def expected_bucket_owner_kwargs(expected_bucket_owner):
        if expected_bucket_owner:
            return {"ExpectedBucketOwner": str(expected_bucket_owner)}
        return {}

    def object_lock_is_configured(self):
        return bool(self.object_lock_mode and self.object_lock_retain_days)

    def lifecycle_is_configured(self):
        return bool(self.lifecycle_transition_days and self.lifecycle_storage_class)

    def lifecycle_rule_id(self):
        return f"backupsheep-storage-{self.storage_id}-lifecycle"

    def _connection_values(self, data=None):
        if data:
            return {
                "access_key": data["access_key"],
                "secret_key": data["secret_key"],
                "bucket_name": data["bucket_name"],
                "prefix": data.get("prefix") or "",
                "region": data.get("region"),
                "no_delete": data.get("no_delete"),
                "object_lock_mode": data.get("object_lock_mode") or "",
                "object_lock_retain_days": data.get("object_lock_retain_days"),
                "expected_bucket_owner": data.get("expected_bucket_owner") or "",
                "lifecycle_transition_days": data.get("lifecycle_transition_days"),
                "lifecycle_storage_class": data.get("lifecycle_storage_class") or "",
            }

        encryption_key = self.storage.account.get_encryption_key()
        return {
            "access_key": bs_decrypt(self.access_key, encryption_key),
            "secret_key": bs_decrypt(self.secret_key, encryption_key),
            "bucket_name": self.bucket_name,
            "prefix": self.prefix or "",
            "region": self.region,
            "no_delete": self.no_delete,
            "object_lock_mode": self.object_lock_mode,
            "object_lock_retain_days": self.object_lock_retain_days,
            "expected_bucket_owner": self.expected_bucket_owner or "",
            "lifecycle_transition_days": self.lifecycle_transition_days,
            "lifecycle_storage_class": self.lifecycle_storage_class,
        }

    @staticmethod
    def _s3_client(values):

        kwargs = {
            "aws_access_key_id": values["access_key"],
            "aws_secret_access_key": values["secret_key"],
        }
        region = values.get("region")
        if region and getattr(region, "code", None):
            kwargs["region_name"] = region.code
        return bounded_boto3_client("s3", **kwargs)

    @staticmethod
    def validate_immutability_settings(data):
        mode = data.get("object_lock_mode") or ""
        retain_days = data.get("object_lock_retain_days")
        expected_bucket_owner = data.get("expected_bucket_owner") or ""
        transition_days = data.get("lifecycle_transition_days")
        lifecycle_class = data.get("lifecycle_storage_class") or ""

        if bool(mode) != bool(retain_days):
            raise S3StorageConfigurationError("OBJECT_LOCK_PAIR_REQUIRED")
        if retain_days is not None and retain_days < 1:
            raise S3StorageConfigurationError("OBJECT_LOCK_RETENTION_INVALID")
        if expected_bucket_owner and (not expected_bucket_owner.isdigit() or len(expected_bucket_owner) != 12):
            raise S3StorageConfigurationError("EXPECTED_BUCKET_OWNER_INVALID")
        if bool(transition_days) != bool(lifecycle_class):
            raise S3StorageConfigurationError("LIFECYCLE_PAIR_REQUIRED")
        if transition_days is not None and transition_days < 1:
            raise S3StorageConfigurationError("LIFECYCLE_DAYS_INVALID")
        if transition_days and not (data.get("prefix") or ""):
            raise S3StorageConfigurationError("LIFECYCLE_PREFIX_REQUIRED")

    def validate(self, data=None, raise_exp=None):
        import time

        values = self._connection_values(data)
        self.validate_immutability_settings(values)
        s3_client = self._s3_client(values)
        owner_kwargs = self.expected_bucket_owner_kwargs(values["expected_bucket_owner"])

        # A test upload into an Object Lock bucket can itself become immutable. For
        # protected destinations, verify the bucket capability without creating an
        # object that neither BackupSheep nor the customer can clean up.
        if values["object_lock_mode"]:
            response = s3_client.get_object_lock_configuration(
                Bucket=values["bucket_name"], **owner_kwargs
            )
            configuration = response.get("ObjectLockConfiguration") or {}
            if configuration.get("ObjectLockEnabled") != "Enabled":
                raise S3StorageConfigurationError("OBJECT_LOCK_NOT_ENABLED")
            s3_client.head_bucket(Bucket=values["bucket_name"], **owner_kwargs)
            return True

        # A deletion-protected destination should not accumulate validation files.
        # We can still verify access to the intended bucket without a write/delete
        # probe that conflicts with the user's deletion-protection policy.
        if values["no_delete"]:
            s3_client.head_bucket(Bucket=values["bucket_name"], **owner_kwargs)
            return True

        prefix = self.normalize_prefix(values["prefix"])
        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=values["bucket_name"], Key=filename, **owner_kwargs
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(
            Bucket=values["bucket_name"], Key=filename, **owner_kwargs
        )

        if not s3_object.get("ETag"):
            return False

        if not values["no_delete"]:
            s3_delete = s3_client.delete_object(
                Bucket=values["bucket_name"], Key=filename, **owner_kwargs
            )
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True

    def sync_lifecycle_configuration(self):
        """Merge BackupSheep's lifecycle rule without replacing user-owned rules."""
        from botocore.exceptions import ClientError

        values = self._connection_values()
        s3_client = self._s3_client(values)
        owner_kwargs = self.expected_bucket_owner_kwargs(values["expected_bucket_owner"])
        try:
            response = s3_client.get_bucket_lifecycle_configuration(
                Bucket=self.bucket_name, **owner_kwargs
            )
            existing_rules = response.get("Rules") or []
        except ClientError as exc:
            error_code = (exc.response.get("Error") or {}).get("Code")
            if error_code not in {"NoSuchLifecycleConfiguration", "NoSuchLifecycle"}:
                raise
            existing_rules = []

        rule_id = self.lifecycle_rule_id()
        rules = [rule for rule in existing_rules if rule.get("ID") != rule_id]
        if self.lifecycle_is_configured():
            rules.append(
                {
                    "ID": rule_id,
                    "Status": "Enabled",
                    "Filter": {"Prefix": self.normalize_prefix(self.prefix)},
                    "Transitions": [
                        {
                            "Days": self.lifecycle_transition_days,
                            "StorageClass": self.lifecycle_storage_class,
                        }
                    ],
                }
            )

        if rules:
            s3_client.put_bucket_lifecycle_configuration(
                Bucket=self.bucket_name,
                LifecycleConfiguration={"Rules": rules},
                **owner_kwargs,
            )
        elif existing_rules:
            s3_client.delete_bucket_lifecycle(
                Bucket=self.bucket_name, **owner_kwargs
            )

        self.lifecycle_last_synced_at = timezone.now()
        self.save(update_fields=["lifecycle_last_synced_at", "modified"])
        return {
            "rule_id": rule_id,
            "enabled": self.lifecycle_is_configured(),
            "transition_days": self.lifecycle_transition_days,
            "storage_class": self.lifecycle_storage_class,
        }


class CoreStorageWasabi(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_wasabi", on_delete=models.CASCADE
    )
    region = models.ForeignKey(
        CoreWasabiRegion, related_name="storage_wasabi", on_delete=models.PROTECT
    )
    secret_key = models.BinaryField(null=True)
    access_key = models.BinaryField(null=True)
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_wasabi"

    def validate(self, data=None, raise_exp=None):
        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            region = data["region"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{region.endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageDoSpaces(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_do_spaces", on_delete=models.CASCADE
    )
    region = models.ForeignKey(
        CoreDoSpacesRegion, related_name="storage_do_spaces", on_delete=models.PROTECT
    )
    secret_key = models.BinaryField(null=True)
    access_key = models.BinaryField(null=True)
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_do_spaces"

    def validate(self, data=None, raise_exp=None):
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            region = data["region"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{region.endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        # Storage validation can run concurrently when duplicate backup tasks
        # race through backup_initiate. A second-resolution timestamp lets one
        # probe overwrite/delete another and report a false validation failure.
        filename = f"{prefix}backupsheep_test_{uuid.uuid4().hex}.txt"

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageFilebase(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_filebase", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField(null=True)
    access_key = models.BinaryField(null=True)
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    region = models.ForeignKey(
        CoreFilebaseRegion, related_name="storage_filebase", on_delete=models.PROTECT, null=True
    )
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_filebase"

    def validate(self, data=None, raise_exp=None):
        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            region = data["region"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://s3.filebase.io",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageExoscale(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_exoscale", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField(null=True)
    access_key = models.BinaryField(null=True)
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    region = models.ForeignKey(
        CoreExoscaleRegion, related_name="storage_exoscale", on_delete=models.PROTECT
    )
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_exoscale"

    def validate(self, data=None, raise_exp=None):
        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            region = data["region"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{region.endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageBackBlazeB2(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_backblaze_b2", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    endpoint = models.CharField(max_length=255)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_backblaze_b2"

    def validate(self, data=None, raise_exp=None):
        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            endpoint = data["endpoint"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            endpoint = self.endpoint
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageLinode(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_linode", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    endpoint = models.CharField(max_length=255)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_linode"

    def validate(self, data=None, raise_exp=None):
        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            endpoint = data["endpoint"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            endpoint = self.endpoint
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageVultr(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_vultr", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    endpoint = models.CharField(max_length=255)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_vultr"

    def validate(self, data=None, raise_exp=None):
        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            endpoint = data["endpoint"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            endpoint = self.endpoint
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageUpCloud(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_upcloud", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    endpoint = models.CharField(max_length=255)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_upcloud"

    def validate(self, data=None, raise_exp=None):
        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            endpoint = data["endpoint"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            endpoint = self.endpoint
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageOracle(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_oracle", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    namespace = models.CharField(max_length=255)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    region = models.ForeignKey(
        CoreOracleRegion, related_name="storage_oracle", on_delete=models.PROTECT
    )
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_oracle"

    @property
    def endpoint(self):
        endpoint = f"{self.namespace}.compat.objectstorage.{self.region.code}.oraclecloud.com"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            region = data["region"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
            namespace = data["namespace"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name
            namespace = self.namespace

        endpoint = f"{namespace}.compat.objectstorage.{region.code}.oraclecloud.com"

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            region_name=region.code, endpoint_url=f"https://{endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageScaleway(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_scaleway", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    region = models.ForeignKey(
        CoreScalewayRegion, related_name="storage_scaleway", on_delete=models.PROTECT
    )
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_scaleway"

    @property
    def endpoint(self):
        endpoint = f"s3.{self.region.code}.scw.cloud"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from botocore.client import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            region = data["region"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        endpoint = f"s3.{region.code}.scw.cloud"

        s3_client = bounded_boto3_client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region.code,
            endpoint_url=f"https://{endpoint}",
            config=Config(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageCloudflare(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_cloudflare", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    account_id = models.CharField(max_length=1024)
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_cloudflare"

    @property
    def endpoint(self):
        endpoint = f"{self.account_id}.r2.cloudflarestorage.com"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from botocore.config import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            account_id = data["account_id"]
            endpoint = f"{account_id}.r2.cloudflarestorage.com"
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            endpoint = self.endpoint
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name="auto",
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageLeviia(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_leviia", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_leviia"

    @property
    def endpoint(self):
        endpoint = f"s3.eu-west.leviia.com"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from botocore.config import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            endpoint = f"s3.eu-west.leviia.com"
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            endpoint = self.endpoint
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name="auto",
            endpoint_url=f"https://{endpoint}", config=Config(
                signature_version='s3v4',
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            )
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageTencent(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_tencent", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    region = models.ForeignKey(
        CoreTencentRegion, related_name="storage_tencent", on_delete=models.PROTECT, null=True
    )
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_tencent"

    @property
    def endpoint(self):
        endpoint = f"{self.bucket_name}.cos.{self.region.code}.myqcloud.com"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from qcloud_cos import CosConfig
        from qcloud_cos import CosS3Client

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
            region = data["region"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        timeout = _provider_sdk_timeout()[1]
        config = CosConfig(
            Region=region.code,
            SecretId=access_key,
            SecretKey=secret_key,
            Scheme="https",
            Timeout=timeout,
        )
        # COS retries are deliberately owned by the durable task.  Every write
        # uses the exact validation key and is followed by explicit verification.
        client = CosS3Client(config, retry=0)

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        file_content = "BackupSheep test upload."

        result = client.put_object(
            Bucket=bucket_name,
            Body=file_content,
            Key=filename,
            StorageClass='STANDARD',
            EnableMD5=True
        )

        if not result.get("ETag"):
            return False

        s3_object = client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        object_url = client.get_presigned_url(
            Method='GET',
            Bucket=bucket_name,
            Key=filename,
            Expired=120
        )

        url_response = _read_validation_url(object_url)
        if url_response != file_content.encode():
            if raise_exp:
                raise ValueError(
                    f"We were unable to validate uploaded file. Check your file {filename} in your bucket")
            return False

        if not no_delete:
            client.delete_object(Bucket=bucket_name, Key=filename)
        return True


class CoreStorageAliBaba(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_alibaba", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    region = models.ForeignKey(
        CoreAlibabaRegion, related_name="storage_alibaba", on_delete=models.PROTECT, null=True
    )
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_alibaba"

    @property
    def endpoint(self):
        endpoint = self.region.endpoint
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        import oss2

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
            region = data["region"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        endpoint = region.endpoint

        auth = oss2.AuthV4(access_key, secret_key)

        # Signature V4 requires the region ID, e.g. "us-east-1" from endpoint "oss-us-east-1.aliyuncs.com".
        region_id = endpoint.split(".")[0].removeprefix("oss-").removesuffix("-internal")

        bucket = oss2.Bucket(
            auth,
            f"https://{endpoint}",
            bucket_name,
            region=region_id,
            connect_timeout=_provider_sdk_timeout()[0],
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        file_content = "BackupSheep test upload."

        result = bucket.put_object(filename, file_content)

        if not result.etag:
            return False

        s3_object = bucket.get_object(filename)

        if not s3_object.etag:
            return False

        object_url = bucket.sign_url('GET', filename, 3600 * 24, headers={'content-disposition': 'attachment'},
                                     slash_safe=True)

        url_response = _read_validation_url(object_url)
        if url_response != file_content.encode():
            if raise_exp:
                raise ValueError(
                    f"We were unable to validate uploaded file. Check your file {filename} in your bucket")
            return False

        if not no_delete:
            s3_delete = bucket.delete_object(filename)
            if s3_delete.status != 204:
                return False
        return True


class CoreStorageAzure(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_azure", on_delete=models.CASCADE
    )
    connection_string = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_azure"

    def get_client(self, data=None):
        import json
        from azure.storage.blob import BlobServiceClient

        if data:
            connection_string = data["connection_string"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            connection_string = bs_decrypt(self.connection_string, encryption_key)

        connect_timeout, read_timeout = _provider_sdk_timeout()
        return BlobServiceClient.from_connection_string(
            connection_string,
            connection_timeout=connect_timeout,
            read_timeout=read_timeout,
            retry_total=0,
            retry_connect=0,
            retry_read=0,
            retry_status=0,
            retry_to_secondary=False,
        )

    def validate(self, data=None, raise_exp=None):
        import time
        import datetime
        from azure.storage.blob import BlobSasPermissions, generate_blob_sas
        from datetime import timedelta

        if data:
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        blob_service_client = self.get_client(data)
        blob_client = blob_service_client.get_blob_client(container=bucket_name, blob=filename)

        file_content = "BackupSheep test upload."

        operation_timeout = _provider_sdk_timeout()[1]
        blob_client.upload_blob(
            file_content,
            blob_type="BlockBlob",
            timeout=operation_timeout,
        )

        # Create a SAS token that expires in 1 hour
        sas_expiry = datetime.datetime.now(datetime.timezone.utc) + timedelta(hours=1)
        sas_permissions = BlobSasPermissions(read=True, write=False, delete=False)
        sas_token = generate_blob_sas(
            account_name=blob_service_client.account_name,
            container_name=bucket_name,
            blob_name=filename,
            account_key=blob_service_client.credential.account_key,
            permission=sas_permissions,
            expiry=sas_expiry,
        )

        # Use the SAS token to create a shared access URL
        blob_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{bucket_name}/{filename}?{sas_token}"

        url_response = _read_validation_url(blob_url)
        if url_response != file_content.encode():
            if raise_exp:
                raise ValueError(
                    f"We were unable to validate uploaded file. Check your file {filename} in your bucket")
            return False

        if not no_delete:
            blob_client.delete_blob(timeout=operation_timeout)
        return True


class CoreStorageGoogleCloud(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_google_cloud", on_delete=models.CASCADE
    )
    service_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    # access_token = models.CharField(max_length=255)
    # refresh_token = models.CharField(max_length=255)
    # Todo: Delete following later
    access_token = models.BinaryField(null=True)
    refresh_token = models.BinaryField(null=True)
    email_address = models.CharField(max_length=255, null=True)
    display_name = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = "core_storage_google_cloud"

    def get_credentials(self, data=None):
        import json
        from google.oauth2 import service_account

        if data:
            service_key_json = json.loads(data["service_key"])
        else:
            encryption_key = self.storage.account.get_encryption_key()
            service_key_json = json.loads(bs_decrypt(self.service_key, encryption_key))

        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        return credentials

    def validate(self, data=None, raise_exp=None):
        import time
        from google.cloud import storage as gc_storage
        from datetime import timedelta

        if data:
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        timeout = _provider_sdk_timeout()
        credentials = self.get_credentials(data)
        session = _BoundedGoogleAuthorizedSession(credentials, timeout=timeout)
        storage_client = gc_storage.Client(
            credentials=credentials, _http=session
        )
        bucket = storage_client.bucket(bucket_name)

        if not bucket.exists(timeout=timeout, retry=None):
            if raise_exp:
                raise ValueError(
                    f"The bucket {bucket_name} doesn't exists. "
                    f"Make sure the bucket exists and service key can access the bucket."
                )
            else:
                return False

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        # Create file
        blob = bucket.blob(filename)

        # blob.upload_from_filename(filename, if_generation_match=generation_match_precondition)
        file_content = "BackupSheep test upload."

        blob.upload_from_string(file_content, timeout=timeout, retry=None)

        blob.reload(timeout=timeout, retry=None)

        url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=15),
            method="GET",
        )

        url_response = _read_validation_url(url)
        if url_response != file_content.encode():
            if raise_exp:
                raise ValueError(
                    f"We were unable to validate uploaded file. Check your file {filename} in your bucket"
                )
            return False

        if not no_delete:
            blob.delete(timeout=timeout, retry=None)
        return True


class CoreStorageIDrive(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_idrive", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    endpoint = models.CharField(max_length=1024)
    bucket_name = models.CharField(max_length=1024)
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_idrive"

    @staticmethod
    def build_endpoint_url(endpoint):
        """Normalize a bare S3-compatible host or an explicit URL once."""
        endpoint = (endpoint or "").strip().rstrip("/")
        return endpoint if "://" in endpoint else f"https://{endpoint}"

    @property
    def endpoint_url(self):
        return self.build_endpoint_url(self.endpoint)

    def validate(self, data=None, raise_exp=None):

        import time
        from botocore.config import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            endpoint = data["endpoint"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            endpoint = self.endpoint
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        # Allow a full URL (e.g. http://minio:9000) for S3-compatible/self-hosted
        # endpoints; bare hostnames keep the original https:// default.
        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=self.build_endpoint_url(endpoint),
            config=Config(
                signature_version='s3v4',
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            )
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


# https://docs.ionos.com/cloud/managed-services/s3-object-storage/s3-tools/boto3-python-sdk
class CoreStorageIonos(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_ionos", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    region = models.ForeignKey(
        CoreIonosRegion, related_name="storage_ionos", on_delete=models.PROTECT, null=True
    )
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_ionos"

    @property
    def endpoint(self):
        endpoint = f"{self.region.endpoint}"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from botocore.config import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
            region = data["region"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        endpoint = region.endpoint

        # boto3 >= 1.36 sends checksums IONOS rejects (InvalidTrailer) unless
        # checksum calculation/validation is set to "when_required".
        # https://docs.ionos.com/cloud/managed-services/s3-object-storage/s3-tools/boto3-python-sdk
        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region.code,
            endpoint_url=f"https://{endpoint}", config=Config(
                signature_version='s3v4',
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            )
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageRackCorp(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_rackcorp", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    region = models.ForeignKey(
        CoreRackCorpRegion, related_name="storage_rackcorp", on_delete=models.PROTECT, null=True
    )
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_rackcorp"

    @property
    def endpoint(self):
        endpoint = f"{self.region.code}.s3.rackcorp.com"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from botocore.config import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
            region = data["region"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        endpoint = f"{region.code}.s3.rackcorp.com"

        s3_client = bounded_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region.code,
            endpoint_url=f"https://{endpoint}", config=Config(
                signature_version='s3v4',
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            )
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        result = s3_client.put_object(
            Body=filename, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorageIBM(TimeStampedModel):
    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_ibm", on_delete=models.CASCADE
    )
    secret_key = models.BinaryField()
    access_key = models.BinaryField()
    bucket_name = models.CharField(max_length=1024)
    region = models.ForeignKey(
        CoreIBMRegion, related_name="storage_ibm", on_delete=models.PROTECT
    )
    prefix = models.CharField(max_length=255, null=True, blank=True)
    no_delete = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_storage_ibm"

    @property
    def endpoint(self):
        endpoint = f"s3.{self.region.code}.cloud-object-storage.appdomain.cloud"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import time
        from ibm_botocore.client import Config

        if data:
            secret_key = data["secret_key"]
            access_key = data["access_key"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
            region = data["region"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            access_key = bs_decrypt(self.access_key, encryption_key)
            region = self.region
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        endpoint = f"s3.{region.code}.cloud-object-storage.appdomain.cloud"

        s3_client = bounded_ibm_boto3_client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region.code,
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = _validation_object_key(prefix)

        file_content = "BackupSheep test upload."

        result = s3_client.put_object(
            Body=file_content, Bucket=bucket_name, Key=filename
        )

        if not result.get("ETag"):
            return False

        s3_object = s3_client.get_object(Bucket=bucket_name, Key=filename)

        if not s3_object.get("ETag"):
            return False

        if not no_delete:
            s3_delete = s3_client.delete_object(Bucket=bucket_name, Key=filename)
            if s3_delete["ResponseMetadata"]["HTTPStatusCode"] != 204:
                return False
        return True


class CoreStorage(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        PENDING = 2, "Pending"
        SUSPENDED = 3, "Suspended"
        PAUSED = 4, "Paused"
        DELETE_REQUESTED = 5, "Delete Requested"

    account = models.ForeignKey(
        CoreAccount, related_name="storage", on_delete=models.CASCADE
    )
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    type = models.ForeignKey(
        CoreStorageType, related_name="storage", on_delete=models.PROTECT
    )
    name = models.CharField(max_length=255)
    added_by = models.ForeignKey(
        CoreMember,
        related_name="added_storages",
        on_delete=models.CASCADE,
        null=True,
    )
    # Counts
    stats_website_count = models.BigIntegerField(null=True)
    stats_database_count = models.BigIntegerField(null=True)
    # Backups
    stats_website_backup_count = models.BigIntegerField(null=True)
    stats_database_backup_count = models.BigIntegerField(null=True)
    # Size
    stats_website_size = models.BigIntegerField(null=True)
    stats_database_size = models.BigIntegerField(null=True)
    # Protection and pricing are destination-level settings. Pricing is deliberately
    # explicit: provider rates vary by region, agreement, and storage class.
    is_air_gapped = models.BooleanField(default=False)
    storage_cost_usd_per_gib_month = models.DecimalField(
        max_digits=12, decimal_places=6, default=Decimal("0")
    )
    cold_storage_cost_usd_per_gib_month = models.DecimalField(
        max_digits=12, decimal_places=6, default=Decimal("0")
    )
    retrieval_cost_usd_per_gib = models.DecimalField(
        max_digits=12, decimal_places=6, default=Decimal("0")
    )

    class Meta:
        db_table = "core_storage"

    # Todo: If Storage is deleted then switch to default storage.
    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    def quota_websites(self):
        from ..backup.models import CoreWebsiteBackupStoragePoints
        from django.db.models import Count, Min, Sum, Avg, Q
        import humanfriendly

        website = CoreWebsiteBackupStoragePoints.objects.filter(
            storage=self,
            backup__size__isnull=False,
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE,
        ).aggregate(Sum("backup__size"), Count("backup__website", distinct=True), Count("backup", distinct=True))

        website["backup__size__sum"] = humanfriendly.format_size(website["backup__size__sum"] or 0)
        return website

    def quota_databases(self):
        from ..backup.models import CoreDatabaseBackupStoragePoints
        from django.db.models import Count, Min, Sum, Avg, Q
        import humanfriendly

        database = CoreDatabaseBackupStoragePoints.objects.filter(
            storage=self,
            backup__size__isnull=False,
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE,
        ).aggregate(Sum("backup__size"), Count("backup__database", distinct=True), Count("backup", distinct=True))

        database["backup__size__sum"] = humanfriendly.format_size(database["backup__size__sum"] or 0)
        return database

    @staticmethod
    def _format_cost(value):
        return float(value.quantize(Decimal("0.0001")))

    @staticmethod
    def _storage_cold_cutoff(storage, now):
        """Backups older than this timestamp are billed at the cold-storage rate."""
        try:
            aws_s3 = storage.storage_aws_s3
        except CoreStorageAWSS3.DoesNotExist:
            return None
        if not aws_s3.lifecycle_is_configured():
            return None
        return now - timedelta(days=aws_s3.lifecycle_transition_days)

    @classmethod
    def cost_summary_for_account(cls, account):
        """Return current per-destination and per-source cost estimates in USD.

        Costs are based on BackupSheep's recorded successful uploads. A configured
        lifecycle transition is treated as cold storage after its age threshold;
        actual provider billing remains authoritative because transitions can be
        asynchronous and contracts vary by customer and region.

        Byte totals are aggregated in SQL (one grouped query per backup type)
        instead of iterating every destination or storage-point row in Python, so
        the dashboard and /api/v1/storage/costs/ stay fast as destinations grow.
        """
        from django.db.models import BigIntegerField, Case, Count, F, Sum, Value, When

        from ..backup.models import (
            CoreBasecampBackupStoragePoints,
            CoreDatabaseBackupStoragePoints,
            CoreWebsiteBackupStoragePoints,
        )

        storages = {
            storage.id: storage
            for storage in cls.objects.filter(account=account).select_related(
                "type", "storage_aws_s3"
            )
        }
        destinations = {
            storage.id: {
                "storage_id": storage.id,
                "storage_name": storage.name,
                "storage_type": storage.type.name,
                "is_air_gapped": storage.is_air_gapped,
                "stored_bytes": 0,
                "standard_stored_bytes": 0,
                "cold_stored_bytes": 0,
                "estimated_monthly_storage_usd": Decimal("0"),
                "estimated_full_retrieval_usd": Decimal("0"),
                "categories": {
                    category: {
                        "source_count": 0,
                        "backup_count": 0,
                        "stored_bytes": 0,
                    }
                    for category in ("website", "database", "saas")
                },
            }
            for storage in storages.values()
        }
        sources = {}
        point_models = (
            (
                CoreWebsiteBackupStoragePoints,
                "backup__website__node_id",
                "backup__website__node__name",
                "website",
            ),
            (
                CoreDatabaseBackupStoragePoints,
                "backup__database__node_id",
                "backup__database__node__name",
                "database",
            ),
            (
                CoreBasecampBackupStoragePoints,
                "backup__basecamp__node_id",
                "backup__basecamp__node__name",
                "saas",
            ),
        )
        gib = Decimal(1024 ** 3)
        now = timezone.now()
        cold_cutoffs = {
            storage.id: cls._storage_cold_cutoff(storage, now)
            for storage in storages.values()
        }
        cold_size_conditions = [
            When(
                storage_id=storage_id,
                backup__created__lte=cutoff,
                then=F("backup__size"),
            )
            for storage_id, cutoff in cold_cutoffs.items()
            if cutoff is not None
        ]
        category_sources = {}

        # One grouped query per backup family keeps the query count fixed as the
        # number of destinations grows. Querying the concrete through tables also
        # avoids the cross-join multiplication caused by annotating every M2M on
        # CoreStorage in one queryset.
        for point_model, node_id_field, node_name_field, category in point_models:
            annotations = {
                "stored": Sum("backup__size"),
                "backup_count": Count("backup_id", distinct=True),
            }
            if cold_size_conditions:
                annotations["cold_stored"] = Sum(
                    Case(
                        *cold_size_conditions,
                        default=Value(0),
                        output_field=BigIntegerField(),
                    )
                )
            rows = (
                point_model.objects.filter(
                    storage_id__in=storages,
                    storage__account=account,
                    status=point_model.Status.UPLOAD_COMPLETE,
                )
                .values("storage_id", node_id_field, node_name_field)
                .annotate(**annotations)
                .order_by()
            )
            for row in rows:
                storage_id = row["storage_id"]
                storage = storages[storage_id]
                destination = destinations[storage_id]
                stored = int(row["stored"] or 0)
                cold = int(row.get("cold_stored") or 0)
                standard = max(0, stored - cold)

                monthly_cost = (
                    (Decimal(cold) / gib)
                    * storage.cold_storage_cost_usd_per_gib_month
                    + (Decimal(standard) / gib)
                    * storage.storage_cost_usd_per_gib_month
                )
                retrieval_cost = (
                    (Decimal(stored) / gib) * storage.retrieval_cost_usd_per_gib
                )

                destination["stored_bytes"] += stored
                destination["cold_stored_bytes"] += cold
                destination["standard_stored_bytes"] += standard
                destination["estimated_monthly_storage_usd"] += monthly_cost
                destination["estimated_full_retrieval_usd"] += retrieval_cost
                destination["categories"][category]["backup_count"] += int(
                    row["backup_count"] or 0
                )
                destination["categories"][category]["stored_bytes"] += stored
                category_sources.setdefault((storage_id, category), set()).add(
                    (point_model._meta.label_lower, row.get(node_id_field))
                )

                source_key = (
                    row.get(node_id_field),
                    row.get(node_name_field) or "Unknown source",
                )
                source = sources.setdefault(
                    source_key,
                    {
                        "source_id": source_key[0],
                        "source_name": source_key[1],
                        "stored_bytes": 0,
                        "estimated_monthly_storage_usd": Decimal("0"),
                        "estimated_full_retrieval_usd": Decimal("0"),
                    },
                )
                source["stored_bytes"] += stored
                source["estimated_monthly_storage_usd"] += monthly_cost
                source["estimated_full_retrieval_usd"] += retrieval_cost

        for (storage_id, category), source_ids in category_sources.items():
            destinations[storage_id]["categories"][category]["source_count"] = len(
                source_ids
            )

        destination_rows = []
        for destination in destinations.values():
            destination["estimated_monthly_storage_usd"] = cls._format_cost(
                destination["estimated_monthly_storage_usd"]
            )
            destination["estimated_full_retrieval_usd"] = cls._format_cost(
                destination["estimated_full_retrieval_usd"]
            )
            destination_rows.append(destination)
        source_rows = []
        for source in sources.values():
            source["estimated_monthly_storage_usd"] = cls._format_cost(
                source["estimated_monthly_storage_usd"]
            )
            source["estimated_full_retrieval_usd"] = cls._format_cost(
                source["estimated_full_retrieval_usd"]
            )
            source_rows.append(source)

        destination_rows.sort(key=lambda item: item["storage_name"].lower())
        source_rows.sort(key=lambda item: item["source_name"].lower())
        return {
            "currency": "USD",
            "stored_bytes": sum(row["stored_bytes"] for row in destination_rows),
            "estimated_monthly_storage_usd": cls._format_cost(
                sum(
                    (Decimal(str(row["estimated_monthly_storage_usd"])) for row in destination_rows),
                    Decimal("0"),
                )
            ),
            "estimated_full_retrieval_usd": cls._format_cost(
                sum(
                    (Decimal(str(row["estimated_full_retrieval_usd"])) for row in destination_rows),
                    Decimal("0"),
                )
            ),
            "destinations": destination_rows,
            "sources": source_rows,
        }

    def validate(self, show_error=None):
        try:
            if hasattr(self, 'storage_aws_s3'):
                storage = getattr(self, 'storage_aws_s3')
                return storage.validate()
            elif hasattr(self, 'storage_backblaze_b2'):
                storage = getattr(self, 'storage_backblaze_b2')
                return storage.validate()
            elif hasattr(self, 'storage_do_spaces'):
                storage = getattr(self, 'storage_do_spaces')
                return storage.validate()
            elif hasattr(self, 'storage_dropbox'):
                storage = getattr(self, 'storage_dropbox')
                return storage.validate()
            elif hasattr(self, 'storage_exoscale'):
                storage = getattr(self, 'storage_exoscale')
                return storage.validate()
            elif hasattr(self, 'storage_filebase'):
                storage = getattr(self, 'storage_filebase')
                return storage.validate()
            elif hasattr(self, 'storage_google_drive'):
                storage = getattr(self, 'storage_google_drive')
                return storage.validate()
            elif hasattr(self, 'storage_linode'):
                storage = getattr(self, 'storage_linode')
                return storage.validate()
            elif hasattr(self, 'storage_upcloud'):
                storage = getattr(self, 'storage_upcloud')
                return storage.validate()
            elif hasattr(self, 'storage_oracle'):
                storage = getattr(self, 'storage_oracle')
                return storage.validate()
            elif hasattr(self, 'storage_scaleway'):
                storage = getattr(self, 'storage_scaleway')
                return storage.validate()
            elif hasattr(self, 'storage_pcloud'):
                storage = getattr(self, 'storage_pcloud')
                return storage.validate()
            elif hasattr(self, 'storage_onedrive'):
                storage = getattr(self, 'storage_onedrive')
                return storage.validate()
            elif hasattr(self, 'storage_vultr'):
                storage = getattr(self, 'storage_vultr')
                return storage.validate()
            elif hasattr(self, 'storage_wasabi'):
                storage = getattr(self, 'storage_wasabi')
                return storage.validate()
            elif hasattr(self, 'storage_cloudflare'):
                storage = getattr(self, 'storage_cloudflare')
                return storage.validate()
            elif hasattr(self, 'storage_leviia'):
                storage = getattr(self, 'storage_leviia')
                return storage.validate()
            elif hasattr(self, 'storage_tencent'):
                storage = getattr(self, 'storage_tencent')
                return storage.validate()
            elif hasattr(self, 'storage_alibaba'):
                storage = getattr(self, 'storage_alibaba')
                return storage.validate()
            elif hasattr(self, 'storage_azure'):
                storage = getattr(self, 'storage_azure')
                return storage.validate()
            elif hasattr(self, 'storage_google_cloud'):
                storage = getattr(self, 'storage_google_cloud')
                return storage.validate()
            elif hasattr(self, 'storage_idrive'):
                storage = getattr(self, 'storage_idrive')
                return storage.validate()
            elif hasattr(self, 'storage_ionos'):
                storage = getattr(self, 'storage_ionos')
                return storage.validate()
            elif hasattr(self, 'storage_rackcorp'):
                storage = getattr(self, 'storage_rackcorp')
                return storage.validate()
            elif hasattr(self, 'storage_ibm'):
                storage = getattr(self, 'storage_ibm')
                return storage.validate()
            elif hasattr(self, 'storage_local'):
                storage = getattr(self, 'storage_local')
                return storage.validate()
        except Exception as e:
            capture_exception(e)
            if show_error:
                raise ValueError(e.__str__())
            else:
                return False


class CoreStorageLocal(TimeStampedModel):
    """'Local Storage' backend: backups are kept as plain zip files on a disk path of
    this BackupSheep server. `path` is an optional subdirectory under
    settings.LOCAL_STORAGE_ROOT (''/None = the root itself)."""

    storage = models.OneToOneField(
        "CoreStorage", related_name="storage_local", on_delete=models.CASCADE
    )
    path = models.CharField(max_length=1024, null=True, blank=True)
    no_delete = models.BooleanField(null=True)

    class Meta:
        db_table = "core_storage_local"

    @staticmethod
    def storage_root():
        from django.conf import settings

        return os.path.realpath(settings.LOCAL_STORAGE_ROOT)

    @staticmethod
    def _path_parts(subpath):
        """Return a canonical root-relative directory path without touching disk.

        Local Storage configuration is accepted by the Internet-facing API, while
        the mounted backup volume is writable only by ``worker-storage``.  Keep the
        API-side check lexical: no create/open/unlink operation belongs in the web
        process, and no absolute path is ever placed on the broker.
        """

        value = str(subpath or "")
        if "\x00" in value or os.path.isabs(value):
            raise ValueError("Path must be relative to the local storage root.")
        normalized = value.replace("\\", "/")
        parts = []
        for part in normalized.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise ValueError("Path must stay inside the local storage root.")
            parts.append(part)
        return tuple(parts)

    @classmethod
    def validate_configuration(cls, data=None):
        """Validate only persisted configuration; never mutate ``/backups``."""

        path = data.get("path") if isinstance(data, dict) else data
        cls._path_parts(path)
        return True

    def resolve_path(self, subpath=None):
        """Resolve `subpath` (defaults to this storage's `path`) to an absolute
        directory inside the local storage root. Rejects absolute paths and any
        '..' traversal escaping the root."""
        root = self.storage_root()
        subpath = subpath if subpath is not None else self.path
        parts = self._path_parts(subpath)
        target = os.path.realpath(os.path.join(root, *parts))
        if target != root and not target.startswith(root + os.sep):
            raise ValueError("Path must stay inside the local storage root.")
        return target

    def _open_directory(self, *, create):
        """Open the configured directory through no-follow directory fds.

        Walking from the already-open Local Storage root prevents a symlink in a
        configured component from redirecting a validation/upload outside the
        mounted volume.  The returned fd is owned by the caller.
        """

        root = self.storage_root()
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        current_fd = os.open(root, flags)
        try:
            for part in self._path_parts(self.path):
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(part, flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except Exception:
            os.close(current_fd)
            raise

    def prepare_directory(self):
        """Create/open the configured directory from ``worker-storage`` only."""

        directory_fd = self._open_directory(create=True)
        try:
            return self.resolve_path()
        finally:
            os.close(directory_fd)

    def probe_filesystem(self):
        """Perform the destructive write/read/unlink probe on worker-storage."""

        directory_fd = self._open_directory(create=True)
        filename = f".backupsheep-validation-{uuid.uuid4().hex}"
        file_fd = None
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
            flags |= getattr(os, "O_NOFOLLOW", 0)
            file_fd = os.open(filename, flags, 0o600, dir_fd=directory_fd)
            payload = filename.encode("ascii")
            if os.write(file_fd, payload) != len(payload):
                return False
            os.fsync(file_fd)
            os.lseek(file_fd, 0, os.SEEK_SET)
            return os.read(file_fd, len(payload) + 1) == payload
        finally:
            if file_fd is not None:
                os.close(file_fd)
            try:
                os.unlink(filename, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)

    def validate(self, data=None, raise_exp=None):
        """Return durable configuration eligibility without touching the volume.

        New/updated Local Storage rows remain ``PENDING`` until the dedicated
        storage worker completes :meth:`probe_filesystem`.  Backup source workers
        can therefore evaluate a destination without acquiring write access to
        ``/backups``.
        """

        if data is not None:
            return self.validate_configuration(data)
        self.validate_configuration(self.path)
        return bool(
            self.storage_id
            and self.storage.status == self.storage.Status.ACTIVE
        )


class CoreStorageDeletionLease(TimeStampedModel):
    """Internal coordinator lease for one storage-configuration deletion."""

    storage = models.OneToOneField(
        CoreStorage, related_name="deletion_lease", on_delete=models.CASCADE
    )
    owner = models.CharField(max_length=255, blank=True, default="")
    token = models.UUIDField(null=True, blank=True, editable=False)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "core_storage_deletion_lease"
