import json
import os
import uuid

import requests
from django.db import models
from model_utils.models import TimeStampedModel
from sentry_sdk import capture_message, capture_exception

from ..account.models import CoreAccount
from ..connection.models import CoreAWSRegion, CoreWasabiRegion, CoreDoSpacesRegion, CoreFilebaseRegion, \
    CoreExoscaleRegion, CoreOracleRegion, CoreScalewayRegion, CoreTencentRegion, CoreAlibabaRegion, CoreIonosRegion, \
    CoreRackCorpRegion, CoreIBMRegion
from ..member.models import CoreMember
from apps.api.v1.utils.api_helpers import bs_encrypt, bs_decrypt


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
        chunk_size = 157286400
        dest_path = f"/{file_name}.txt"
        encryption_key = self.storage.account.get_encryption_key()
        access_token = bs_decrypt(self.access_token, encryption_key)
        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        dbx = dropbox.Dropbox(
            oauth2_access_token=access_token,
            oauth2_refresh_token=refresh_token,
            app_key=settings.DROPBOX_APP_KEY,
            app_secret=settings.DROPBOX_APP_SECRET,
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

        token_request = requests.post(dropbox_url, data=params)

        if token_request.status_code == 200:
            token_data = token_request.json()
            self.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            self.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
            self.save()


class CoreStoragePCloud(TimeStampedModel):
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
        encryption_key = self.storage.account.get_encryption_key()

        if data:
            access_token = data["access_token"]
        else:
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
        import requests
        from pcloud import PyCloud

        if data:
            hostname = data["hostname"]
        else:
            hostname = self.hostname

        local_txt_file = "_upload_test_files/backupsheep.txt"
        pcloud_path = "/validate/backupsheep.txt"

        # create validate folder if doesn't exists
        requests.post(
            f"https://{hostname}/createfolderifnotexists?path=/validate",
            headers=self.get_client(data=data),
            verify=True,
        )

        pc = PyCloud(
            username=self.userid,
            password=self.get_access_token(),
            endpoint=self.hostname.split('.')[0],
            oauth2=True
        )
        result = pc.uploadfile(files=[local_txt_file], path="/validate")

        if result.get('metadata'):
            metadata = result.get('metadata')[0]
            if metadata.get("path") == pcloud_path:
                pc.deletefile(path=pcloud_path, fileid=metadata.get("fileid"))
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

        encryption_key = self.storage.account.get_encryption_key()

        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": settings.MS_CLIENT_ID,
            "client_secret": settings.MS_CLIENT_SECRET_VALUE,
        }

        token_request = requests.post(settings.MS_OAUTH_TOKEN_URL, data=params)

        if token_request.status_code == 200:
            token_data = token_request.json()
            self.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            self.refresh_token = bs_encrypt(token_data["refresh_token"], encryption_key)
            self.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
            self.scope = token_data["scope"]
            self.save()
        else:
            print(token_request.json())

    def validate(self, data=None, raise_exp=None):
        import requests
        from django.conf import settings

        url = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.user_id}"

        drive_request = requests.request("GET", url, headers=self.get_client(data))

        if drive_request.status_code == 200:
            file_name = "backupsheep.txt"
            local_file_path = "_upload_test_files/backupsheep.txt"
            target_file_path = f"backupsheep/{file_name}"

            onedrive_path = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.drive_id}/root:/{target_file_path}"

            # Upload file
            file_data = open(local_file_path, "rb")
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
        from google.auth.transport.requests import AuthorizedSession
        import google.auth.transport.urllib3

        encryption_key = self.storage.account.get_encryption_key()
        access_token = bs_decrypt(self.access_token, encryption_key)

        credentials = google.oauth2.credentials.Credentials(
            access_token,
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
        )

        client = AuthorizedSession(credentials)
        return client

    def get_refresh_token(self):
        import google.oauth2.credentials
        from django.conf import settings
        from google.auth.transport.requests import AuthorizedSession
        from google.auth.transport.urllib3 import AuthorizedHttp
        import google.auth.transport.urllib3
        import urllib3

        encryption_key = self.storage.account.get_encryption_key()
        access_token = bs_decrypt(self.access_token, encryption_key)
        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        credentials = google.oauth2.credentials.Credentials(
            access_token,
            refresh_token=refresh_token,
            token_uri="https://accounts.google.com/o/oauth2/token",
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
        )

        http = urllib3.PoolManager()
        request = google.auth.transport.urllib3.Request(http)
        credentials.refresh(request)
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
                "name": "backupsheep.txt",
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

                        result = client.delete(
                            f"https://www.googleapis.com/drive/v3/files/{storage_file_id}",
                            headers={"Content-Type": "application/json; charset=UTF-8"},
                        )

                        if result.status_code == 204:
                            return True


class CoreStorageAWSS3(TimeStampedModel):
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

    class Meta:
        db_table = "core_storage_aws_s3"

    def validate(self, data=None, raise_exp=None):
        import boto3
        import time

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            access_key = bs_decrypt(self.access_key, encryption_key)
            secret_key = bs_decrypt(self.secret_key, encryption_key)
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{region.endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{region.endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://s3.filebase.com",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{region.endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}", region_name=endpoint.split('.')[1]
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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

        import boto3
        import time

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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            region_name=region.code, endpoint_url=f"https://{endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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

        import boto3
        import time

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

        s3_client = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region.code,
            endpoint_url=f"https://{endpoint}",
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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

        import boto3
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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name="auto",
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        endpoint = f"s3.leviia.com"
        return endpoint

    def validate(self, data=None, raise_exp=None):

        import boto3
        import time
        from botocore.config import Config

        if data:
            access_key = data["access_key"]
            secret_key = data["secret_key"]
            endpoint = f"s3.leviia.com"
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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name="auto",
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import urllib.request

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

        config = CosConfig(Region=region.code, SecretId=access_key, SecretKey=secret_key, Scheme="https")
        client = CosS3Client(config)

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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

        with urllib.request.urlopen(object_url) as response:
            url_response = response.read()

            if url_response.decode() != file_content:
                if raise_exp:
                    raise ValueError(
                        f"We were unable to validate uploaded file. Check your file {filename} in your bucket")
                else:
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
        import urllib.request

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

        auth = oss2.Auth(access_key, secret_key)

        bucket = oss2.Bucket(auth, f"https://{endpoint}", bucket_name)

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

        file_content = "BackupSheep test upload."

        result = bucket.put_object(filename, file_content)

        if not result.etag:
            return False

        s3_object = bucket.get_object(filename)

        if not s3_object.etag:
            return False

        object_url = bucket.sign_url('GET', filename, 3600 * 24, headers={'content-disposition': 'attachment'},
                                     slash_safe=True)

        with urllib.request.urlopen(object_url) as response:
            url_response = response.read()

            if url_response.decode() != file_content:
                if raise_exp:
                    raise ValueError(
                        f"We were unable to validate uploaded file. Check your file {filename} in your bucket")
                else:
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
        from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient

        if data:
            connection_string = data["connection_string"]
        else:
            encryption_key = self.storage.account.get_encryption_key()
            connection_string = bs_decrypt(self.connection_string, encryption_key)

        return BlobServiceClient.from_connection_string(connection_string)

    def validate(self, data=None, raise_exp=None):
        import time
        import datetime
        from azure.storage.blob import BlobSasPermissions, generate_blob_sas
        from datetime import timedelta
        import urllib.request

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

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

        blob_service_client = self.get_client(data)
        blob_client = blob_service_client.get_blob_client(container=bucket_name, blob=filename)

        file_content = "BackupSheep test upload."

        blob_client.upload_blob(file_content, blob_type="BlockBlob")

        # Create a SAS token that expires in 1 hour
        sas_expiry = datetime.datetime.utcnow() + timedelta(hours=1)
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

        with urllib.request.urlopen(blob_url) as response:
            url_response = response.read()

            if url_response.decode() != file_content:
                if raise_exp:
                    raise ValueError(
                        f"We were unable to validate uploaded file. Check your file {filename} in your bucket")
                else:
                    return False

        if not no_delete:
            blob_client.delete_blob()
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
        import urllib.request

        if data:
            no_delete = data.get("no_delete")
            prefix = data["prefix"]
            bucket_name = data["bucket_name"]
        else:
            no_delete = self.no_delete
            prefix = self.prefix
            bucket_name = self.bucket_name

        storage_client = gc_storage.Client(credentials=self.get_credentials(data))
        bucket = storage_client.bucket(bucket_name)

        if not bucket.exists():
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

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

        # Create file
        blob = bucket.blob(filename)

        # blob.upload_from_filename(filename, if_generation_match=generation_match_precondition)
        file_content = "BackupSheep test upload."

        blob.upload_from_string(file_content)

        blob.reload()

        url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=15),
            method="GET",
        )

        with urllib.request.urlopen(url) as response:
            url_response = response.read()

            if url_response.decode() != file_content:
                if raise_exp:
                    raise ValueError(
                        f"We were unable to validate uploaded file. Check your file {filename} in your bucket"
                    )
                else:
                    return False

        if not no_delete:
            blob.delete()
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

    def validate(self, data=None, raise_exp=None):

        import boto3
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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key,
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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

        import boto3
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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region.code,
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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

        import boto3
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

        s3_client = boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region.code,
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
        import ibm_boto3
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

        s3_client = ibm_boto3.client(
            "s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region.code,
            endpoint_url=f"https://{endpoint}", config=Config(signature_version='s3v4')
        )

        if prefix:
            if (prefix != "") and (prefix.endswith("/") is False):
                prefix += "/"

        filename = f"{prefix}backupsheep_test_{int(time.time())}.txt"

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
    stats_wordpress_count = models.BigIntegerField(null=True)
    # Backups
    stats_website_backup_count = models.BigIntegerField(null=True)
    stats_database_backup_count = models.BigIntegerField(null=True)
    stats_wordpress_backup_count = models.BigIntegerField(null=True)
    # Size
    stats_website_size = models.BigIntegerField(null=True)
    stats_database_size = models.BigIntegerField(null=True)
    stats_wordpress_size = models.BigIntegerField(null=True)
    # Delete this later
    stat_wordpress_size = models.BigIntegerField(null=True)

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
            elif hasattr(self, 'storage_googlecloud'):
                storage = getattr(self, 'storage_googlecloud')
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
            elif hasattr(self, 'storage_bs'):
                storage = getattr(self, 'storage_bs')
                return storage.validate()
        except Exception as e:
            capture_exception(e)
            if show_error:
                raise ValueError(e.__str__())
            else:
                return False
