import json
import os

import boto3
import requests
from botocore.exceptions import ClientError
from django.conf import settings
from django.db import models
import time

from django.utils.text import slugify
from django_celery_beat.models import PeriodicTasks
from google.oauth2 import service_account
from requests.exceptions import SSLError, JSONDecodeError
from requests_toolbelt import SSLAdapter

from rest_framework.exceptions import APIException
from sentry_sdk import capture_exception, capture_message

from apps._tasks.exceptions import (
    NodeConnectionErrorSSH,
    NodeConnectionErrorMYSQL,
    NodeConnectionErrorMARIADB,
    NodeConnectionErrorPOSTGRESQL,
    NodeConnectionErrorWebsite,
    NodeConnectionErrorEligibleObjects,
    NodeConnectionErrorSFTP,
    IntegrationValidationFailed,
    IntegrationValidationError,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt

from ..account.models import CoreAccount
from model_utils.models import TimeStampedModel

from ..member.models import CoreMember
from ..utils.models import UtilBase


class CoreIntegration(UtilBase):
    class Type(models.TextChoices):
        CLOUD = "cloud", "Cloud"
        SAAS = "saas", "SaaS"
        WEBSITE = "website", "Website"
        DATABASE = "database", "Database"

    code = models.CharField(max_length=64, unique=True)
    public_key = models.TextField(null=True)
    description = models.TextField(null=True)
    position = models.IntegerField(null=True)
    url = models.URLField(null=True)
    image = models.CharField(null=True, max_length=2048)
    enabled = models.BooleanField(default=True)
    type = models.CharField(
        max_length=64,
        choices=Type.choices,
        default=Type.CLOUD,
    )

    class Meta:
        db_table = "core_integration"


class CoreWasabiRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_wasabi_region"


class CoreDoSpacesRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_do_spaces_region"


class CoreFilebaseRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_filebase_region"


class CoreExoscaleRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_exoscale_region"


class CoreOracleRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)

    class Meta:
        db_table = "core_oracle_region"


class CoreScalewayRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)

    class Meta:
        db_table = "core_scaleway_region"


class CoreAWSRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)
    rds_endpoint = models.CharField(max_length=255, null=True)
    s3_endpoint = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = "core_aws_region"


class CoreTencentRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)

    class Meta:
        db_table = "core_tencent_region"


class CoreAlibabaRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_alibab_region"


class CoreIonosRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)

    class Meta:
        db_table = "core_ionos_region"


class CoreRackCorpRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    class Meta:
        db_table = "core_rackcorp_region"

class CoreIBMRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    class Meta:
        db_table = "core_ibm_region"


class CoreLightsailRegion(models.Model):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    endpoint = models.CharField(max_length=255)
    rds_endpoint = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = "core_lightsail_region"


class CoreAuthDigitalOcean(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_digitalocean", on_delete=models.CASCADE)
    # all clear
    access_token = models.BinaryField(null=True)
    # all clear
    refresh_token = models.BinaryField(null=True)
    scope = models.CharField(max_length=32, null=True)
    token_type = models.CharField(max_length=32, null=True)
    expiry = models.DateTimeField(null=True)
    token_refresh_failed = models.BooleanField(default=False)
    info_name = models.CharField(max_length=64, null=True)
    info_email = models.CharField(max_length=64, null=True)
    info_uuid = models.CharField(max_length=255, null=True)
    # 2022 - This is new method. oAuth doesn't work well with teams setup
    api_key = models.BinaryField(null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_digitalocean"

    def refresh_auth_token(self):
        from apps._tasks.helper.tasks import send_postmark_email
        from datetime import datetime
        from ..node.models import CoreNode

        encryption_key = self.connection.account.get_encryption_key()

        refresh_token_decrypted = bs_decrypt(self.refresh_token, encryption_key)

        if refresh_token_decrypted:
            token_request_url = (
                f"{settings.DIGITALOCEAN_TOKEN_URL}?"
                f"grant_type=refresh_token"
                f"&refresh_token={refresh_token_decrypted}"
            )

            result = requests.post(token_request_url)
            if result.status_code == 200:
                do_tokens = result.json()
                self.access_token = bs_encrypt(do_tokens["access_token"], encryption_key)
                self.refresh_token = bs_encrypt(do_tokens["refresh_token"], encryption_key)
                self.expiry = datetime.fromtimestamp((int(time.time()) + int(do_tokens["expires_in"])))
                if do_tokens.get("info"):
                    self.info_name = do_tokens["info"].get("name")
                    self.info_email = do_tokens["info"].get("email")
                    self.info_uuid = do_tokens["info"].get("uuid")
                self.save()
                self.connection.status = CoreConnection.Status.ACTIVE
                self.connection.save()
                # activate all paused nodes.
                for node in self.connection.nodes.filter(status=CoreNode.Status.PAUSED_MAX_RETRIES):
                    node.status = CoreNode.Status.ACTIVE
                    node.save()
            elif result.status_code == 401:
                if result.json().get("error") == "invalid_grant":
                    # Configure this to send new email. DigitalOcean doesn't use these tokens anymore
                    pass
                    # self.connection.status = CoreConnection.Status.TOKEN_REFRESH_FAIL
                    # self.connection.save()
                    # member = self.connection.account.get_primary_member()
                    # to_email = member.user.email
                    # send_postmark_email.delay(
                    #     to_email,
                    #     23780797,
                    #     "TOKEN_REFRESH_FAIL",
                    #     {
                    #         "connection_name": self.connection.name,
                    #         "connection_info_name": self.info_name,
                    #         "connection_info_email": self.info_email,
                    #         "connection_status": self.connection.get_status_display(),
                    #         "action_url": "https://backupsheep.com/console/setup/digitalocean/",
                    #         "help_url": "https://support.backupsheep.com",
                    #         "sender_name": "BackupSheep - Notification Bot",
                    #     },
                    # )
            elif result.status_code == 429:
                if result.json()["id"] == "too_many_requests":
                    print(result.json()["message"])
            else:
                print("other error")

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        if self.api_key:
            client = {
                "content-type": "application/json",
                "Authorization": f"Bearer {bs_decrypt(self.api_key, encryption_key)}",
            }
        # Legacy method. We switched to API Access Token in 2022
        else:
            client = {
                "content-type": "application/json",
                "Authorization": f"{self.token_type} {bs_decrypt(self.access_token, encryption_key)}",
            }
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        payload = {"per_page": 200}

        if object_type == "cloud":
            result = requests.get(
                settings.DIGITALOCEAN_API + "/v2/droplets",
                headers=client,
                params=payload,
                verify=True,
            )
            if result.status_code == 200:
                droplets = result.json()["droplets"]
                for droplet in droplets:
                    droplet["_bs_unique_id"] = droplet.get("id", None)
                    droplet["_bs_name"] = droplet.get("name", None)
                    droplet["_bs_region"] = droplet.get("region", {}).get("name", None)
                    droplet["_bs_size"] = droplet.get("size", {}).get("disk", None)
                    eligible_objects.append(droplet)
            else:
                raise APIException(detail=result.json()["message"])
            result.close()
        elif object_type == "volume":
            result = requests.get(
                settings.DIGITALOCEAN_API + "/v2/volumes",
                headers=client,
                params=payload,
                verify=True,
            )
            if result.status_code == 200:
                droplets = result.json()["volumes"]
                for droplet in droplets:
                    droplet["_bs_unique_id"] = droplet.get("id", None)
                    droplet["_bs_name"] = droplet.get("name", None)
                    droplet["_bs_region"] = droplet.get("region", {}).get("name", None)
                    droplet["_bs_size"] = droplet.get("size_gigabytes", None)
                    eligible_objects.append(droplet)
            else:
                raise APIException(detail=result.json()["message"])
            result.close()
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        client = self.get_client()
        result = requests.get(settings.DIGITALOCEAN_API + "/v2/account", headers=client, verify=True)
        if result.status_code == 200:
            return True
        else:
            return None


class CoreAuthHetzner(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_hetzner", on_delete=models.CASCADE)
    api_key = models.BinaryField(null=True)
    token_refresh_failed = models.BooleanField(default=False)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_hetzner"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = {
            "content-type": "application/json",
            "Authorization": f"Bearer {bs_decrypt(self.api_key, encryption_key)}",
        }
        return client

    # Todo: deal with more than 50 items later
    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        payload = {"per_page": 50}

        if object_type == "cloud":
            result = requests.get(
                settings.HETZNER_API + "/v1/servers",
                headers=client,
                params=payload,
                verify=True,
            )
            if result.status_code == 200:
                servers = result.json()["servers"]
                for server in servers:
                    server["_bs_unique_id"] = server.get("id", None)
                    server["_bs_name"] = server.get("name", None)
                    server["_bs_region"] = server.get("datacenter", {}).get("description", None)
                    server["_bs_size"] = server.get("primary_disk_size", None)
                    eligible_objects.append(server)
            else:
                raise APIException(detail=result.json()["error"]["message"])
            result.close()
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        client = self.get_client()
        result = requests.get(settings.HETZNER_API + "/v1/actions", headers=client, verify=True)
        if result.status_code == 200:
            return True
        else:
            return None


class CoreAuthUpCloud(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_upcloud", on_delete=models.CASCADE)
    username = models.BinaryField(null=True)
    password = models.BinaryField(null=True)
    token_refresh_failed = models.BooleanField(default=False)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_upcloud"

    def get_client(self):
        from requests.auth import HTTPBasicAuth

        encryption_key = self.connection.account.get_encryption_key()

        client = HTTPBasicAuth(bs_decrypt(self.username, encryption_key), bs_decrypt(self.password, encryption_key))
        return client

    # Todo: deal with more than 50 items later
    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()

        if object_type == "volume":
            result = requests.get(
                settings.UPCLOUD_API + "/storage/normal",
                auth=client,
                verify=True,
                headers={"content-type": "application/json"},
            )
            if result.status_code == 200:
                servers = result.json()["storages"]["storage"]
                for server in servers:
                    server["_bs_unique_id"] = server.get("uuid", None)
                    server["_bs_name"] = server.get("title", None)
                    server["_bs_region"] = server.get("zone", None)
                    server["_bs_size"] = server.get("size", None)
                    eligible_objects.append(server)
            else:
                raise APIException(detail=result.json()["error"]["message"])
            result.close()
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        client = self.get_client()
        result = requests.get(
            settings.UPCLOUD_API + "/account", auth=client, verify=True, headers={"content-type": "application/json"}
        )
        if result.status_code == 200:
            return True
        else:
            return None


class CoreAuthAWS(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_aws", on_delete=models.CASCADE)
    access_key = models.BinaryField(null=True)
    secret_key = models.BinaryField(null=True)
    region = models.ForeignKey(CoreAWSRegion, related_name="auth_aws", on_delete=models.PROTECT)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_aws"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = boto3.client(
            "ec2",
            region_name=self.region.code,
            aws_access_key_id=bs_decrypt(self.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(self.secret_key, encryption_key),
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        if object_type == "cloud":
            reservations = client.describe_instances().get("Reservations")
            instances = [i for r in reservations for i in r["Instances"]]
            for aws_instance in instances:
                aws_instance["_bs_unique_id"] = aws_instance.get("InstanceId", None)
                aws_instance["_bs_name"] = aws_instance.get("KeyName", None)
                aws_instance["_bs_region"] = aws_instance.get("Placement", {}).get("AvailabilityZone", None)
                aws_instance["_bs_size"] = aws_instance.get("size_gigabytes", None)
                if not aws_instance["_bs_name"]:
                    aws_instance["_bs_name"] = aws_instance.get("InstanceId", None)
                eligible_objects.append(aws_instance)
        elif object_type == "volume":
            volumes = client.describe_volumes().get("Volumes")
            for aws_volume in volumes:
                aws_volume["_bs_unique_id"] = aws_volume.get("VolumeId", None)
                aws_volume["_bs_name"] = aws_volume.get("VolumeId", None)
                aws_volume["_bs_region"] = aws_volume.get("AvailabilityZone", None)
                aws_volume["_bs_size"] = aws_volume.get("Size", None)
                eligible_objects.append(aws_volume)
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.describe_instances()
            return True
        except ClientError as e:
            return False
        except Exception as e:
            return False


class CoreAuthLightsail(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_lightsail", on_delete=models.CASCADE)
    info_name = models.CharField(max_length=64, null=True)
    access_key = models.BinaryField(null=True)
    secret_key = models.BinaryField(null=True)
    region = models.ForeignKey(CoreLightsailRegion, related_name="auth_lightsail", on_delete=models.PROTECT)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_lightsail"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = boto3.client(
            "lightsail",
            region_name=self.region.code,
            aws_access_key_id=bs_decrypt(self.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(self.secret_key, encryption_key),
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        if object_type == "cloud":
            more_objects = True
            next_page_token = ''

            while more_objects is True:
                response = client.get_instances(pageToken=next_page_token)

                for instance in response["instances"]:
                    instance["_bs_unique_id"] = instance.get("name", None)
                    instance["_bs_name"] = instance.get("name", None)
                    instance["_bs_region"] = instance.get("location", {}).get("regionName", {})
                    instance["_bs_size"] = instance.get("hardware", {}).get("disks", [])[0].get("sizeInGb")
                    eligible_objects.append(instance)

                next_page_token = response.get("nextPageToken")

                if not next_page_token:
                    more_objects = False

        elif object_type == "volume":
            more_objects = True
            next_page_token = ''

            while more_objects is True:
                response = client.get_disks(pageToken=next_page_token)

                for disk in response["disks"]:
                    disk["_bs_unique_id"] = disk.get("name", None)
                    disk["_bs_name"] = disk.get("name", None)
                    disk["_bs_region"] = disk.get("location", {}).get("regionName", {})
                    disk["_bs_size"] = disk.get("sizeInGb", None)
                    eligible_objects.append(disk)

                next_page_token = response.get("nextPageToken")

                if not next_page_token:
                    more_objects = False

        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get_instances()
            return True
        except ClientError as e:
            return False
        except Exception as e:
            return False


class CoreAuthAWSRDS(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_aws_rds", on_delete=models.CASCADE)
    access_key = models.BinaryField()
    info_name = models.CharField(max_length=64, null=True)
    secret_key = models.BinaryField()
    region = models.ForeignKey(CoreAWSRegion, related_name="auth_aws_rds", on_delete=models.PROTECT)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_aws_rds"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = boto3.client(
            "rds",
            region_name=self.region.code,
            aws_access_key_id=bs_decrypt(self.access_key, encryption_key),
            aws_secret_access_key=bs_decrypt(self.secret_key, encryption_key),
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        instances = client.describe_db_instances()
        for rds_instance in instances.get("DBInstances"):
            rds_instance["_bs_unique_id"] = rds_instance.get("DBInstanceIdentifier", None)
            rds_instance["_bs_name"] = rds_instance.get("DBInstanceIdentifier", None)
            rds_instance["_bs_region"] = rds_instance.get("AvailabilityZone", None)
            rds_instance["_bs_size"] = rds_instance.get("AllocatedStorage", None)
            eligible_objects.append(rds_instance)
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.describe_db_instances()
            return True
        except ClientError as e:
            return False
        except Exception as e:
            return False


class CoreAuthOVHCA(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_ovh_ca", on_delete=models.CASCADE)
    consumer_key = models.BinaryField(null=True)
    info_customer_code = models.CharField(max_length=1024, null=True)
    info_name = models.CharField(max_length=1024, null=True)
    info_email = models.CharField(max_length=255, null=True)
    info_organization = models.CharField(max_length=1024, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_ovh_ca"

    def get_client(self):
        import ovh

        encryption_key = self.connection.account.get_encryption_key()

        client = ovh.Client(
            endpoint=str("ovh-ca"),
            application_key=settings.OVH_CA_APP_KEY,
            application_secret=settings.OVH_CA_APP_SECRET,
            consumer_key=bs_decrypt(self.consumer_key, encryption_key),
            timeout=86400,
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        projects = client.get("/cloud/project")

        if object_type == "cloud":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                servers = client.get(f"/cloud/project/{project}/instance")

                for cloud_server in servers:
                    cloud_server["project"] = project_details
                    cloud_server["_bs_unique_id"] = cloud_server.get("id", None)
                    cloud_server["_bs_name"] = cloud_server.get("name", None)
                    cloud_server["_bs_region"] = cloud_server.get("region", None)
                    cloud_server["_bs_size"] = cloud_server.get("size", None)
                    eligible_objects.append(cloud_server)
            return eligible_objects
        elif object_type == "volume":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                volumes = client.get(f"/cloud/project/{project}/volume")
                for cloud_volume in volumes:
                    cloud_volume["project"] = project_details
                    cloud_volume["_bs_unique_id"] = cloud_volume.get("id", None)
                    cloud_volume["_bs_name"] = cloud_volume.get("name", None)
                    cloud_volume["_bs_region"] = cloud_volume.get("region", None)
                    cloud_volume["_bs_size"] = cloud_volume.get("size", None)
                    eligible_objects.append(cloud_volume)
            return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get("/cloud/project")
            return True
        except Exception as e:
            return False


class CoreAuthOVHEU(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_ovh_eu", on_delete=models.CASCADE)
    consumer_key = models.BinaryField(null=True)
    info_customer_code = models.CharField(max_length=1024, null=True)
    info_name = models.CharField(max_length=1024, null=True)
    info_email = models.CharField(max_length=255, null=True)
    info_organization = models.CharField(max_length=1024, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_ovh_eu"

    def get_client(self):
        import ovh

        encryption_key = self.connection.account.get_encryption_key()

        client = ovh.Client(
            endpoint=str("ovh-eu"),
            application_key=settings.OVH_EU_APP_KEY,
            application_secret=settings.OVH_EU_APP_SECRET,
            consumer_key=bs_decrypt(self.consumer_key, encryption_key),
            timeout=86400,
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        projects = client.get("/cloud/project")

        if object_type == "cloud":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                servers = client.get(f"/cloud/project/{project}/instance")
                for cloud_server in servers:
                    cloud_server["project"] = project_details
                    cloud_server["_bs_unique_id"] = cloud_server.get("id", None)
                    cloud_server["_bs_name"] = cloud_server.get("name", None)
                    cloud_server["_bs_region"] = cloud_server.get("region", None)
                    cloud_server["_bs_size"] = cloud_server.get("size", None)
                    eligible_objects.append(cloud_server)
            return eligible_objects
        elif object_type == "volume":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                volumes = client.get(f"/cloud/project/{project}/volume")
                for cloud_volume in volumes:
                    cloud_volume["project"] = project_details
                    cloud_volume["_bs_unique_id"] = cloud_volume.get("id", None)
                    cloud_volume["_bs_name"] = cloud_volume.get("name", None)
                    cloud_volume["_bs_region"] = cloud_volume.get("region", None)
                    cloud_volume["_bs_size"] = cloud_volume.get("size", None)
                    eligible_objects.append(cloud_volume)
            return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get("/cloud/project")
            return True
        except Exception as e:
            return False


class CoreAuthOVHUS(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_ovh_us", on_delete=models.CASCADE)
    consumer_key = models.BinaryField(null=True)
    info_customer_code = models.CharField(max_length=1024, null=True)
    info_name = models.CharField(max_length=1024, null=True)
    info_email = models.CharField(max_length=255, null=True)
    info_organization = models.CharField(max_length=1024, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_ovh_us"

    def get_client(self):
        import ovh

        encryption_key = self.connection.account.get_encryption_key()

        client = ovh.Client(
            endpoint=str("ovh-us"),
            application_key=settings.OVH_US_APP_KEY,
            application_secret=settings.OVH_US_APP_SECRET,
            consumer_key=bs_decrypt(self.consumer_key, encryption_key),
            timeout=86400,
        )
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        projects = client.get("/cloud/project")

        if object_type == "cloud":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                servers = client.get(f"/cloud/project/{project}/instance")
                for cloud_server in servers:
                    cloud_server["project"] = project_details
                    cloud_server["_bs_unique_id"] = cloud_server.get("id", None)
                    cloud_server["_bs_name"] = cloud_server.get("name", None)
                    cloud_server["_bs_region"] = cloud_server.get("region", None)
                    cloud_server["_bs_size"] = cloud_server.get("size", None)
                    eligible_objects.append(cloud_server)
            return eligible_objects
        elif object_type == "volume":
            for project in projects:
                project_details = client.get(f"/cloud/project/{project}")
                volumes = client.get(f"/cloud/project/{project}/volume")
                for cloud_volume in volumes:
                    cloud_volume["project"] = project_details
                    cloud_volume["_bs_unique_id"] = cloud_volume.get("id", None)
                    cloud_volume["_bs_name"] = cloud_volume.get("name", None)
                    cloud_volume["_bs_region"] = cloud_volume.get("region", None)
                    cloud_volume["_bs_size"] = cloud_volume.get("size", None)
                    eligible_objects.append(cloud_volume)
            return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            client = self.get_client()
            client.get("/cloud/project")
            return True
        except Exception as e:
            return False


class CoreAuthVultr(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_vultr", on_delete=models.CASCADE)
    api_key = models.BinaryField(null=True)
    info_name = models.CharField(max_length=64, null=True)
    info_email = models.CharField(max_length=64, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_vultr"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

        client = {
            "Authorization": f"Bearer {bs_decrypt(self.api_key, encryption_key)}",
        }
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        client = self.get_client()
        params = {"per_page": 500}

        regions = requests.get(f"{settings.VULTR_API}/v2/regions", params=params, headers=client).json().get("regions")

        if object_type == "cloud":
            result = requests.get(f"{settings.VULTR_API}/v2/instances", params=params, headers=client)
            if result.status_code == 200:
                for instance in result.json()["instances"]:
                    instance["_bs_unique_id"] = instance.get("id", None)
                    if (instance.get("hostname", None) == "vultr.guest") and instance.get("tag", None):
                        instance["_bs_name"] = f"{instance.get('tag', None)}"
                    else:
                        instance["_bs_name"] = f"{instance.get('hostname', None)}"

                    _bs_region = next((x for x in regions if x["id"] == instance.get("region", None)), None)

                    instance["_bs_region"] = f"{_bs_region['city']}, {_bs_region['country']}"
                    instance["_bs_size"] = instance.get("disk", None)
                    eligible_objects.append(instance)
            result.close()
        elif object_type == "volume":
            result = requests.get(f"{settings.VULTR_API}/v2/blocks", params=params, headers=client)
            if result.status_code == 200:
                for block in result.json()["blocks"]:
                    block["_bs_unique_id"] = block.get("id", None)
                    block["_bs_name"] = block.get("label", None)
                    _bs_region = next((x for x in regions if x["id"] == block.get("region", None)), None)
                    block["_bs_region"] = f"{_bs_region['city']}, {_bs_region['country']}"
                    block["_bs_size"] = block.get("size_gb", None)
                    eligible_objects.append(block)
            result.close()
        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        client = self.get_client()
        result = requests.get(f"{settings.VULTR_API}/v2/account", headers=client)
        if result.status_code == 200:
            return True
        else:
            return None


class CoreAuthOracle(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_oracle", on_delete=models.CASCADE)
    user = models.CharField(max_length=255)
    fingerprint = models.CharField(max_length=255)
    tenancy = models.CharField(max_length=255)
    region = models.CharField(max_length=255)
    private_key = models.BinaryField()
    profile = models.CharField(max_length=255)

    class Meta:
        db_table = "core_auth_oracle"

    def get_client(self, data=None):
        import tempfile
        from oci.config import validate_config

        if data:
            user = data["user"]
            fingerprint = data["fingerprint"]
            tenancy = data["tenancy"]
            region = data["region"]
            private_key = data["private_key"]
        else:
            user = self.user
            fingerprint = self.fingerprint
            tenancy = self.tenancy
            region = self.region
            encryption_key = self.connection.account.get_encryption_key()
            private_key = bs_decrypt(self.private_key, encryption_key)

        fd, ssh_key_path = tempfile.mkstemp(dir="/home/ubuntu/backupsheep/_storage")
        with os.fdopen(fd, "w") as tmp:
            tmp.write(private_key)

        config = {
            "user": user,
            "key_file": ssh_key_path,
            "fingerprint": fingerprint,
            "tenancy": tenancy,
            "region": region,
        }
        validate_config(config)
        # identity = oci.identity.IdentityClient(config)
        return config

    def get_eligible_objects(self, object_type="cloud"):
        import oci

        eligible_objects = []
        per_page = 1000
        config = self.get_client()

        if object_type == "cloud":
            pass
        elif object_type == "volume":
            block_storage_client = oci.core.BlockstorageClient(config)

            """
            Get Boot Volumes
            """
            boot_volumes = block_storage_client.list_boot_volumes(limit=per_page, compartment_id=self.tenancy)

            if boot_volumes.status == 200:
                for boot_volume in boot_volumes.data:
                    eligible_object = {
                        "id": boot_volume.id,
                        "_bs_unique_id": boot_volume.id,
                        "_bs_name": boot_volume.display_name,
                        "_bs_region": boot_volume.availability_domain,
                        "_bs_size": boot_volume.size_in_gbs,
                        "_bs_vol_type": "boot",
                    }
                    eligible_objects.append(eligible_object)

            """
            Get Block Volumes
            """
            volumes = block_storage_client.list_volumes(limit=per_page, compartment_id=self.tenancy)

            if volumes.status == 200:
                for volume in volumes.data:
                    eligible_object = {
                        "id": volume.id,
                        "_bs_unique_id": volume.id,
                        "_bs_name": volume.display_name,
                        "_bs_region": volume.availability_domain,
                        "_bs_size": volume.size_in_gbs,
                        "_bs_vol_type": "block",
                    }
                    eligible_objects.append(eligible_object)
            else:
                raise ValueError(f"Unable to get list of volumes. Received status code {boot_volumes.status} from API.")
        return eligible_objects

    def validate(self, data=None, check_errors=None, raise_exp=None):
        import oci

        if data:
            user = data["user"]
        else:
            user = self.user
        try:
            config = self.get_client(data=data)
            identity = oci.identity.IdentityClient(config)
            oracle_user = identity.get_user(config["user"]).data
            return oracle_user.id == user
        except Exception as e:
            if check_errors:
                raise ValueError(f"Validation failed. Please check your integration details. Error: {e.__str__()}")
            else:
                return False


class CoreAuthLinode(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_linode", on_delete=models.CASCADE)
    api_key = models.BinaryField(null=True)
    info_name = models.CharField(max_length=64, null=True)
    info_email = models.CharField(max_length=64, null=True)
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_linode"

    def validate(self, check_errors=None, raise_exp=None):
        return True


class CoreAuthGoogleCloud(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_google_cloud", on_delete=models.CASCADE)
    service_key = models.BinaryField()
    encryption_updated = models.BooleanField(default=False)

    class Meta:
        db_table = "core_auth_google_cloud"

    def refresh_auth_token(self):
        from datetime import datetime

        encryption_key = self.connection.account.get_encryption_key()

        params = {
            "grant_type": "refresh_token",
            "refresh_token": bs_decrypt(self.refresh_token, encryption_key),
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
        }

        token_request = requests.post(settings.GOOGLE_OAUTH_TOKEN_URL, data=params)

        if token_request.status_code == 200:
            token_data = token_request.json()
            self.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            self.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
            self.save()

    def get_client(self, data=None):
        import json
        from google.auth.transport.requests import AuthorizedSession

        if data:
            service_key_json = json.loads(data["service_key"])
        else:
            encryption_key = self.connection.account.get_encryption_key()
            service_key_json = json.loads(bs_decrypt(self.service_key, encryption_key))

        credentials = service_account.Credentials.from_service_account_info(service_key_json)
        scoped_credentials = credentials.with_scopes(["https://www.googleapis.com/auth/cloud-platform"])
        client = AuthorizedSession(scoped_credentials)
        return client

    def get_eligible_objects(self, object_type="cloud"):
        eligible_objects = []
        active_projects = []
        client = self.get_client()
        params = {"per_page": 500}

        if object_type == "cloud":
            result = client.get(f"{settings.GOOGLE_RESOURCE_API}/v1/projects", params={"pageSize": 100})
            if result.status_code == 200:
                projects = result.json().get("projects")
                # Check for active projects
                for project in projects:
                    if project["lifecycleState"] == "ACTIVE":
                        active_projects.append(project)

                if len(active_projects) > 0:
                    for active_project in active_projects:
                        result = client.get(
                            f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones",
                            params=params,
                        )
                        if result.status_code == 200:
                            if result.json().get("items"):
                                zones = result.json().get("items")

                                for zone in zones:
                                    result = client.get(
                                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones/{zone['name']}/instances",
                                        params=params,
                                    )
                                    if result.status_code == 200:
                                        if result.json().get("items"):
                                            instances = result.json().get("items")
                                            for instance in instances:
                                                instance["_bs_unique_id"] = instance.get("id", None)
                                                instance["_bs_name"] = f"{instance.get('name', None)}"
                                                instance["_bs_region"] = zone["name"]
                                                instance["_bs_size"] = instance.get("disks", None)[0].get("diskSizeGb")
                                                instance["_bs_project_id"] = active_project["projectId"]
                                                instance["_bs_zone"] = zone["name"]
                                                eligible_objects.append(instance)

                                    result.close()
                        else:
                            if result.json().get("error"):
                                error = result.json().get("error")
                                # permission_error = all([char in error["message"].lower() for char in ["required", "permission", "for"]])
                                # if not permission_error:
                                raise ValueError(error["message"])
                            else:
                                raise ValueError(
                                    f"Unable to get list of instances. Received status code {result.status_code} from API."
                                )
            else:
                if result.json().get("error"):
                    error = result.json().get("error")
                    raise ValueError(error["message"])
                else:
                    raise ValueError(
                        f"Unable to get list of instances. Received status code {result.status_code} from API."
                    )
        elif object_type == "volume":
            result = client.get(f"{settings.GOOGLE_RESOURCE_API}/v1/projects", params={"pageSize": 100})
            if result.status_code == 200:
                projects = result.json().get("projects")
                # Check for active projects
                for project in projects:
                    if project["lifecycleState"] == "ACTIVE":
                        active_projects.append(project)

                if len(active_projects) > 0:
                    for active_project in active_projects:
                        result = client.get(
                            f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones",
                            params=params,
                        )
                        if result.status_code == 200:
                            if result.json().get("items"):
                                zones = result.json().get("items")

                                for zone in zones:
                                    result = client.get(
                                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1/projects/{active_project['projectId']}/zones/{zone['name']}/disks",
                                        params=params,
                                    )
                                    if result.status_code == 200:
                                        if result.json().get("items"):
                                            disks = result.json().get("items")
                                            for disk in disks:
                                                disk["_bs_unique_id"] = disk.get("id", None)
                                                disk["_bs_name"] = f"{disk.get('name', None)}"
                                                disk["_bs_region"] = zone["name"]
                                                disk["_bs_size"] = disk["sizeGb"]
                                                disk["_bs_project_id"] = active_project["projectId"]
                                                disk["_bs_zone"] = zone["name"]
                                                eligible_objects.append(disk)

                                    result.close()
                        else:
                            if result.json().get("error"):
                                error = result.json().get("error")
                                # permission_error = all([char in error["message"].lower() for char in ["required", "permission", "for"]])
                                # if not permission_error:
                                raise ValueError(error["message"])
                            else:
                                raise ValueError(
                                    f"Unable to get list of instances. Received status code {result.status_code} from API."
                                )
            else:
                if result.json().get("error"):
                    error = result.json().get("error")
                    raise ValueError(error["message"])
                else:
                    raise ValueError(
                        f"Unable to get list of instances. Received status code {result.status_code} from API."
                    )
        return eligible_objects

    def validate(self, data=None, check_errors=None, raise_exp=None):
        try:
            client = self.get_client(data=data)
            result = client.get(f"{settings.GOOGLE_RESOURCE_API}/v1/projects", params={"pageSize": 100})
            if result.status_code == 200:
                return True
        except Exception as e:
            if check_errors:
                raise ValueError(f"Validation failed. Please check your integration details. Error: {e.__str__()}")
            else:
                return False
        # url = f"https://openidconnect.googleapis.com/v1/userinfo"
        #
        # profile_request = requests.get(url, headers=self.get_client())
        #
        # return profile_request.status_code == 200


class CoreAuthWebsite(TimeStampedModel):
    class Protocol(models.IntegerChoices):
        FTP = 1, "FTP"
        SFTP = 2, "SFTP"
        FTPS = 3, "FTPS"

    connection = models.OneToOneField("CoreConnection", related_name="auth_website", on_delete=models.CASCADE)
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    use_private_key = models.BooleanField(null=True)
    # all cleaned
    private_key = models.BinaryField(null=True)
    # all clear
    username = models.BinaryField(null=True)
    # all clear
    password = models.BinaryField(null=True)
    protocol = models.IntegerField(choices=Protocol.choices, null=True)
    info_name = models.CharField(max_length=64, null=True)
    use_public_key = models.BooleanField(null=True)
    ftps_use_explicit_ssl = models.BooleanField(null=True)
    encryption_updated = models.BooleanField(default=False)
    # https://xtresoft.atlassian.net/browse/BS-12
    flag_use_sha1_key_verification = models.BooleanField(default=False, null=True)

    class Meta:
        db_table = "core_auth_website"

    def check_connection(self, data=None, check_errors=None):
        import ftputil
        from apps.api.v1.utils.api_helpers import bs_decrypt, FtpSession, FtpTlsSession
        import paramiko
        import tempfile
        import os

        if data:
            username = data.get("username")
            password = data.get("password")
            port = data.get("port")
            host = data.get("host")
            protocol = data.get("protocol")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            port = self.port
            host = self.host
            protocol = self.protocol

        if protocol == self.Protocol.FTP:
            try:
                path = None
                with ftputil.FTPHost(
                    host,
                    username,
                    password,
                    port=port,
                    session_factory=FtpSession,
                ) as hosting_host:

                    hosting_host.listdir(path or ".")
                    hosting_host.close()
            except Exception as e:
                raise NodeConnectionErrorWebsite(e.__str__())
        elif protocol == self.Protocol.FTPS:
            try:
                path = None

                with ftputil.FTPHost(
                    host,
                    username,
                    password,
                    port=port,
                    session_factory=FtpTlsSession,
                ) as hosting_host:
                    hosting_host.listdir(path or ".")
                    hosting_host.close()
            except Exception as e:
                raise NodeConnectionErrorWebsite(e.__str__())
        elif protocol == self.Protocol.SFTP:
            try:
                # All we want is to check if connection can be made.
                sftp, ssh, ssh_key_path = self.get_sftp_client(data)

                # Now close connections and remove key file.
                sftp.close()
                ssh.close()
                if ssh_key_path:
                    os.remove(ssh_key_path)
            except Exception as e:
                raise NodeConnectionErrorWebsite(e.__str__())

    def get_sftp_client(self, data=None):
        import paramiko
        import tempfile
        import os

        if data:
            username = data.get("username")
            password = data.get("password")
            private_key = data.get("private_key")
            port = data.get("port")
            host = data.get("host")
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
            flag_use_sha1_key_verification = data.get("flag_use_sha1_key_verification")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            private_key = bs_decrypt(self.private_key, encryption_key)
            port = self.port
            host = self.host
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            flag_use_sha1_key_verification = self.flag_use_sha1_key_verification

        ssh_key_path = None

        disabled_algorithms = None
        if flag_use_sha1_key_verification:
            disabled_algorithms = {"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}

        if use_public_key:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            pkey = paramiko.RSAKey.from_private_key_file(settings.SSH_KEY_PATH)
            ssh.connect(
                host,
                auth_timeout=180,
                banner_timeout=180,
                timeout=180,
                port=int(port),
                username=username,
                pkey=pkey,
                disabled_algorithms=disabled_algorithms,
            )
            sftp = ssh.open_sftp()
        elif use_private_key:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            fd, ssh_key_path = tempfile.mkstemp(dir="/home/ubuntu/backupsheep/_storage")
            with os.fdopen(fd, "w") as tmp:
                tmp.write(private_key)
            if password:
                pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path, password=password)
            else:
                pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path)
            ssh.connect(
                host,
                auth_timeout=180,
                banner_timeout=180,
                timeout=180,
                port=int(port),
                username=username,
                pkey=pkey,
                disabled_algorithms=disabled_algorithms,
            )
            sftp = ssh.open_sftp()
        else:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                host,
                auth_timeout=180,
                banner_timeout=180,
                timeout=180,
                port=int(port),
                username=username,
                password=password,
                disabled_algorithms=disabled_algorithms,
            )
            sftp = ssh.open_sftp()
        if not sftp:
            raise NodeConnectionErrorSFTP()
        return sftp, ssh, ssh_key_path

    def get_eligible_objects(self, path=None):
        if not path:
            path = "."

        eligible_objects = []
        self.check_connection()
        try:
            import os
            import ftputil
            from apps.api.v1.utils.api_helpers import (
                bs_decrypt,
                FtpSession,
                FtpTlsSession,
                isFile,
                isdir,
            )

            encryption_key = self.connection.account.get_encryption_key()

            if self.protocol == self.Protocol.FTP:
                with ftputil.FTPHost(
                    self.host,
                    bs_decrypt(self.username, encryption_key),
                    bs_decrypt(self.password, encryption_key),
                    port=int(self.port),
                    session_factory=FtpSession,
                ) as hosting_host:

                    names = hosting_host.listdir(path or ".")

                    for name in names:
                        try:
                            full_path = (
                                (path if (path != "." and path != "/") else "") + ("/" if path != "." else "") + name
                            )

                            hosting_host.path.getsize(full_path)

                            if hosting_host.path.isdir(full_path):
                                obj_type = "directory"
                            elif hosting_host.path.isfile(full_path):
                                obj_type = "file"

                            eligible_objects.append(
                                {
                                    "directory": path,
                                    "path": (path if (path != "." and path != "/") else "")
                                    + ("/" if path != "." else "")
                                    + name,
                                    "type": obj_type,
                                    "name": name,
                                }
                            )
                        except Exception as e:
                            # Ignore this for now. But later add checks here.
                            capture_exception(e)
                    hosting_host.close()
                    # Sort by type and then by object type(file or dir)
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["type"])
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])

            elif self.protocol == self.Protocol.FTPS:
                with ftputil.FTPHost(
                    self.host,
                    bs_decrypt(self.username, encryption_key),
                    bs_decrypt(self.password, encryption_key),
                    port=int(self.port),
                    session_factory=FtpTlsSession,
                ) as hosting_host:

                    names = hosting_host.listdir(path or ".")

                    for name in names:
                        try:
                            full_path = (
                                (path if (path != "." and path != "/") else "") + ("/" if path != "." else "") + name
                            )

                            hosting_host.path.getsize(full_path)

                            if hosting_host.path.isdir(full_path):
                                obj_type = "directory"
                            elif hosting_host.path.isfile(full_path):
                                obj_type = "file"

                            eligible_objects.append(
                                {
                                    "directory": path,
                                    "path": (path if (path != "." and path != "/") else "")
                                    + ("/" if path != "." else "")
                                    + name,
                                    "type": obj_type,
                                    "name": name,
                                }
                            )
                        except Exception as e:
                            # Ignore this for now. But later add checks here.
                            capture_exception(e)
                    hosting_host.close()
                    # Sort by type and then by object type(file or dir)
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["type"])
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])

            elif self.protocol == self.Protocol.SFTP:
                sftp, ssh, ssh_key_path = self.get_sftp_client()
                # Some files and dir won't have correct permission so we will ignore them.
                try:
                    names = sftp.listdir(path or ".")
                except (IOError, OSError):
                    names = []

                for name in names:
                    full_path = (path if path != "." else "") + ("/" if path != "." else "") + name

                    if isFile(full_path, sftp):
                        obj_type = "file"
                        eligible_objects.append(
                            {
                                "directory": path,
                                "path": (path if (path != "." and path != "/") else "")
                                + ("/" if path != "." else "")
                                + name,
                                "type": obj_type,
                                "name": name,
                            }
                        )
                    elif isdir(full_path, sftp):
                        obj_type = "directory"
                        eligible_objects.append(
                            {
                                "directory": path,
                                "path": (path if (path != "." and path != "/") else "")
                                + ("/" if path != "." else "")
                                + name,
                                "type": obj_type,
                                "name": name,
                            }
                        )

                # Sort by type and then by object type(file or dir)
                eligible_objects = sorted(eligible_objects, key=lambda k: k["type"])
                eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])

                # Now close connections and remove key file.
                sftp.close()
                ssh.close()
                if ssh_key_path:
                    os.remove(ssh_key_path)

        except Exception as e:
            raise NodeConnectionErrorEligibleObjects()

        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            self.check_connection(data=None, check_errors=check_errors)
            return True
        except Exception as e:
            if check_errors:
                raise IntegrationValidationError(e.__str__())
            else:
                return False


class CoreAuthDatabase(TimeStampedModel):
    class DatabaseType(models.IntegerChoices):
        MYSQL = 1, "MySQL"
        MARIADB = 2, "MariaDB"
        POSTGRESQL = 3, "PostgreSQL"

    class DatabaseVersion(models.TextChoices):
        MYSQL_8_0 = "mysql_8_0", "MySQL 8.0"
        MYSQL_5_7 = "mysql_5_7", "MySQL 5.7"
        MYSQL_5_6 = "mysql_5_6", "MySQL 5.6"
        MYSQL_5_5 = "mysql_5_5", "MySQL 5.5"

        MARIADB_10_10 = "mariadb_10_10", "MariaDB 10.10"
        MARIADB_10_9 = "mariadb_10_9", "MariaDB 10.9"
        MARIADB_10_8 = "mariadb_10_8", "MariaDB 10.8"
        MARIADB_10_7 = "mariadb_10_7", "MariaDB 10.7"
        MARIADB_10_6 = "mariadb_10_6", "MariaDB 10.6"
        MARIADB_10_5 = "mariadb_10_5", "MariaDB 10.5"
        MARIADB_10_4 = "mariadb_10_4", "MariaDB 10.4"
        MARIADB_10_3 = "mariadb_10_3", "MariaDB 10.3"
        MARIADB_10_2 = "mariadb_10_2", "MariaDB 10.2"
        MARIADB_10_1 = "mariadb_10_1", "MariaDB 10.1"
        POSTGRESQL_15 = "postgres_15", "PostgreSQL 15"
        POSTGRESQL_14 = "postgres_14", "PostgreSQL 14"
        POSTGRESQL_13 = "postgres_13", "PostgreSQL 13"
        POSTGRESQL_12 = "postgres_12", "PostgreSQL 12"
        POSTGRESQL_11 = "postgres_11", "PostgreSQL 11"
        POSTGRESQL_10 = "postgres_10", "PostgreSQL 10"
        POSTGRESQL_9 = "postgres_9", "PostgreSQL 9"

    connection = models.OneToOneField("CoreConnection", related_name="auth_database", on_delete=models.CASCADE)
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    database_name = models.CharField(max_length=255, null=True)
    all_databases = models.BooleanField(default=False)
    # all clear
    username = models.BinaryField(null=True)
    # all clear
    password = models.BinaryField(null=True)
    type = models.IntegerField(choices=DatabaseType.choices)
    version = models.CharField(choices=DatabaseVersion.choices, max_length=32)
    include_stored_procedure = models.BooleanField(null=True)
    use_ssl = models.BooleanField(default=False)
    info_name = models.CharField(max_length=64, null=True)
    # all clear
    ssh_username = models.BinaryField(null=True)
    # all clear
    ssh_password = models.BinaryField(null=True)
    ssh_port = models.IntegerField(null=True)
    ssh_host = models.CharField(max_length=255, null=True)
    use_public_key = models.BooleanField(null=True)
    use_private_key = models.BooleanField(null=True)
    # all clear
    private_key = models.BinaryField(null=True)
    encryption_updated = models.BooleanField(default=False)
    # https://xtresoft.atlassian.net/browse/BS-12
    flag_use_sha1_key_verification = models.BooleanField(default=False, null=True)

    class Meta:
        db_table = "core_auth_database"

    def check_connection(self, data=None, check_errors=None):
        import mysql.connector
        import psycopg2

        if data:
            host = data.get("host")
            port = data.get("port")
            database_name = data.get("database_name")
            username = data.get("username")
            password = data.get("password")
            all_databases = data.get("all_databases")
            use_ssl = data.get("use_ssl", False)

            type = self.DatabaseType(data.get("type"))
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            host = self.host
            port = self.port
            database_name = self.database_name
            all_databases = self.all_databases
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            type = self.type
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            use_ssl = self.use_ssl

        if use_public_key or use_private_key:
            ssh, ssh_key_path = self.get_ssh_client(data=data)

            option_ssl_mode = ""
            if use_ssl:
                option_ssl_mode = "--ssl-mode=PREFERRED"

            if type == self.DatabaseType.MYSQL:
                execstr = (
                    f"mysql"
                    f" {option_ssl_mode}"
                    f" --disable-column-names"
                    f" -h'{host}'"
                    f" -u'{username}'"
                    f" -p'{password}'"
                    f" --port='{port}'"
                    f' -e"STATUS;"'
                )
                stdin, stdout, stderr = ssh.exec_command(execstr)

                """
                Check output. 
                """
                output_lines = stdout.readlines()

                """
                Check for any errors. 
                """
                error_lines = stderr.readlines()

                output = " ".join(map(str, output_lines or "")).strip("\n").strip()
                error = " ".join(map(str, error_lines or "")).strip("\n").strip()
                combined = f"{output}\n{error}"

                if "server:" in combined.lower() or "server version:" in combined.lower():
                    pass
                else:
                    combined = combined.replace(
                        "[Warning] Using a password on the command line interface can be insecure", ""
                    )
                    raise IntegrationValidationError(combined)

            elif type == self.DatabaseType.MARIADB:
                execstr = (
                    f"mysql"
                    f" {option_ssl_mode}"
                    f" --disable-column-names"
                    f" -h'{host}'"
                    f" -u'{username}'"
                    f" -p'{password}'"
                    f" --port='{port}'"
                    f' -e"STATUS;"'
                )
                stdin, stdout, stderr = ssh.exec_command(execstr)
                """
                Check output. 
                """
                output_lines = stdout.readlines()

                """
                Check for any errors. 
                """
                error_lines = stderr.readlines()

                output = " ".join(map(str, output_lines or "")).strip("\n").strip()
                error = " ".join(map(str, error_lines or "")).strip("\n").strip()
                combined = f"{output}\n{error}"

                if "server:" in combined.lower() or "server version:" in combined.lower():
                    pass
                else:
                    combined = combined.replace(
                        "[Warning] Using a password on the command line interface can be insecure", ""
                    )
                    raise IntegrationValidationError(combined)

            elif type == self.DatabaseType.POSTGRESQL:
                if all_databases:
                    dbname = f"dbname='postgres'"
                else:
                    dbname = f"dbname='{database_name}'"
                # execstr = (
                #     f'psql'
                #     f' "host={host}'
                #     f" user='{username}'"
                #     f" password='{password}'"
                #     f" port='{port}'"
                #     f" {dbname}"
                #     f' sslmode=prefer" -lqt | cut -d \| -f 1'
                # )

                # PostgreSQL 14.5 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0, 64-bit
                execstr = (
                    f"psql"
                    f' "host={host}'
                    f" user='{username}'"
                    f" password='{password}'"
                    f" port={port}"
                    f" {dbname}"
                    f' sslmode=prefer" -c "SELECT version();"'
                )

                stdin, stdout, stderr = ssh.exec_command(execstr)
                """
                Check output. 
                """
                output_lines = stdout.readlines()

                """
                Check for any errors. 
                """
                error_lines = stderr.readlines()

                output = " ".join(map(str, output_lines or "")).strip("\n").strip()
                error = " ".join(map(str, error_lines or "")).strip("\n").strip()
                combined = f"{output}\n{error}"

                if "postgresql" in combined.lower() and "compiled by" in combined.lower():
                    output_list = output.lower().strip().split(" ")

                    if len(output_list) > 0:
                        find_index = lambda l, e: l.index(e) if e in l else None

                        if find_index(output_list, "postgresql"):

                            db_server_version = output_list[find_index(output_list, "postgresql") + 1]

                            # Now get pg_dump version
                            execstr = f"pg_dump --version"

                            stdin, stdout, stderr = ssh.exec_command(execstr)
                            output_lines = stdout.readlines()
                            output_lines = " ".join(map(str, output_lines or "")).strip("\n").strip()
                            ssh_pg_dump_version = output_lines.strip().split(" ")[2]

                            if float(db_server_version) > float(ssh_pg_dump_version):
                                raise IntegrationValidationError(
                                    f"The pg_dump version ({ssh_pg_dump_version})"
                                    f" on SSH server must be equal or higher"
                                    f" than your PostgreSQL version ({db_server_version})"
                                )
                else:
                    raise IntegrationValidationError(combined)
            """
            Delete temp SSH Key
            """
            ssh.close()
            if ssh_key_path:
                os.remove(ssh_key_path)
        else:
            if type == self.DatabaseType.MYSQL:
                try:
                    db_con = mysql.connector.connect(
                        host=host,
                        port=int(port),
                        user=username,
                        passwd=password,
                        db=database_name,
                        connect_timeout=60,
                        ssl_disabled=(not use_ssl),
                    )
                    cursor = db_con.cursor()
                    cursor.execute("SHOW TABLES")
                    cursor.fetchall()
                    cursor.close()
                    db_con.close()
                except Exception as e:
                    raise IntegrationValidationError(e.__str__())
            elif type == self.DatabaseType.MARIADB:
                try:
                    db_con = mysql.connector.connect(
                        host=host,
                        port=int(port),
                        user=username,
                        passwd=password,
                        db=database_name,
                        connect_timeout=60,
                        ssl_disabled=(not use_ssl),
                    )
                    cursor = db_con.cursor()
                    cursor.execute("SHOW TABLES")
                    cursor.fetchall()
                    cursor.close()
                    db_con.close()
                except Exception as e:
                    raise IntegrationValidationError(e.__str__())
            elif type == self.DatabaseType.POSTGRESQL:
                try:
                    db_con = psycopg2.connect(
                        dbname=database_name,
                        user=username,
                        password=password,
                        host=host,
                        port=port,
                    )
                    cursor = db_con.cursor()
                    cursor.execute("select relname from pg_class where relkind='r' and relname !~ '^(pg_|sql_)';")
                    cursor.fetchall()
                    cursor.close()
                    db_con.close()
                except Exception as e:
                    raise IntegrationValidationError(e.__str__())

    """
    Find DB Version & automatically set correct version
    """

    def find_db_type_and_version(self, data=None):
        import mysql.connector
        import psycopg2

        if data:
            host = data.get("host")
            port = data.get("port")
            database_name = data.get("database_name")
            username = data.get("username")
            password = data.get("password")
            use_ssl = data.get("use_ssl", False)

            type = self.DatabaseType(data.get("type"))
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            host = self.host
            port = self.port
            database_name = self.database_name
            username = bs_decrypt(self.username, encryption_key)
            password = bs_decrypt(self.password, encryption_key)
            type = self.type
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            use_ssl = self.use_ssl

        if use_public_key or use_private_key:
            ssh, ssh_key_path = self.get_ssh_client(data=data)

            option_ssl_mode = ""
            if use_ssl:
                option_ssl_mode = "--ssl-mode=PREFERRED"

            if type == self.DatabaseType.MYSQL:
                execstr = (
                    f"mysql"
                    f" {option_ssl_mode}"
                    f" --disable-column-names"
                    f" -h'{host}'"
                    f" -u'{username}'"
                    f" -p'{password}'"
                    f" --port='{port}'"
                    f' -e"SELECT version();"'
                )
                stdin, stdout, stderr = ssh.exec_command(execstr)
                output_lines = stdout.readlines()
                db_type_version = None
                if output_lines:
                    result = " ".join(map(str, output_lines)).strip("\n").strip()
                    version = int(result.split(".")[0])
                    if version >= 10:
                        db_type = "mariadb"
                    else:
                        db_type = "mysql"
                    db_version = result.split(".")[0] + "_" + result.split(".")[1]
                    db_type_version = f"{db_type}_{db_version}"
                return db_type_version
            elif type == self.DatabaseType.MARIADB:
                execstr = (
                    f"mysql"
                    f" {option_ssl_mode}"
                    f" --disable-column-names"
                    f" -h'{host}'"
                    f" -u'{username}'"
                    f" -p'{password}'"
                    f" --port='{port}'"
                    f' -e"SELECT version();"'
                )
                stdin, stdout, stderr = ssh.exec_command(execstr)
                output_lines = stdout.readlines()
                db_type_version = None
                if output_lines:
                    result = " ".join(map(str, output_lines)).strip("\n").strip()
                    version = int(result.split(".")[0])
                    if version >= 10:
                        db_type = "mariadb"
                    else:
                        db_type = "mysql"
                    db_version = result.split(".")[0] + "_" + result.split(".")[1]
                    db_type_version = f"{db_type}_{db_version}"
                return db_type_version
            elif type == self.DatabaseType.POSTGRESQL:
                execstr = (
                    f"psql"
                    f' "host={host}'
                    f" user='{username}'"
                    f" password='{password}'"
                    f" port={port}"
                    f' sslmode=prefer" -c "SELECT version();"'
                )
                stdin, stdout, stderr = ssh.exec_command(execstr)
                output_lines = stdout.readlines()
                db_type_version = None
                if output_lines:
                    result = " ".join(map(str, output_lines)).strip("\n").strip()
                    if "postgresql" in result.lower():
                        db_type = slugify(result.replace(".", "_")).split("-")[1].replace("postgresql", "postgres")
                        db_version = slugify(result.replace(".", "_")).split("-")[2]
                        db_type_version = f"{db_type}_{db_version}"
                return db_type_version
            """
            Delete temp SSH Key
            """
            ssh.close()
            if ssh_key_path:
                os.remove(ssh_key_path)
        else:
            if type == self.DatabaseType.MYSQL:
                db_con = mysql.connector.connect(
                    host=host,
                    port=int(port),
                    user=username,
                    passwd=password,
                    db=database_name,
                    connect_timeout=60,
                    ssl_disabled=(not use_ssl),
                )
                cursor = db_con.cursor()
                cursor.execute("select version();")
                result = cursor.fetchone()[0]
                cursor.close()
                db_con.close()
                if "mariadb" in result.lower() or "mysql" in result.lower():
                    return slugify(f"{result.split('-')[1]}_{result.split('-')[0]}".replace(".", "_")).replace("-", "_")
                else:
                    return None
            elif type == self.DatabaseType.MARIADB:
                db_con = mysql.connector.connect(
                    host=host,
                    port=int(port),
                    user=username,
                    passwd=password,
                    db=database_name,
                    connect_timeout=60,
                    ssl_disabled=(not use_ssl),
                )
                cursor = db_con.cursor()
                cursor.execute("select version();")
                result = cursor.fetchone()[0]
                cursor.close()
                db_con.close()
                if "mariadb" in result.lower() or "mysql" in result.lower():
                    return slugify(f"{result.split('-')[1]}_{result.split('-')[0]}".replace(".", "_")).replace("-", "_")
                else:
                    return None
            elif type == self.DatabaseType.POSTGRESQL:
                db_con = psycopg2.connect(
                    dbname=database_name,
                    user=username,
                    password=password,
                    host=host,
                    port=port,
                )
                cursor = db_con.cursor()
                cursor.execute("select version();")
                result = cursor.fetchone()[0]
                cursor.close()
                db_con.close()

                if "postgres" in result.lower():
                    db_type_version = result.split("on")[0].replace("postgresql", "postgres")
                    return (
                        slugify(f"{db_type_version.split(' ')[0]}_{db_type_version.split(' ')[1]}".replace(".", "_"))
                        .replace("-", "_")
                        .replace("postgresql", "postgres")
                    )
                else:
                    return None

    """
    Fix and update DB Version based on find_db_type_and_version
    """

    def update_db_type_and_version(self):
        available_db_versions = CoreAuthDatabase.DatabaseVersion.values
        available_db_types = CoreAuthDatabase.DatabaseType.choices
        db_version = self.find_db_type_and_version()
        if db_version:
            for available_db_versions in available_db_versions:
                if available_db_versions in db_version:
                    self.version = available_db_versions
                    self.save()
            for available_db_type in available_db_types:
                if available_db_type[1].lower() in db_version:
                    self.type = available_db_type[0]
                    self.save()
        return {"type": self.get_type_display(), "version": self.get_version_display()}

    def get_ssh_client(self, data=None):
        import paramiko
        import tempfile
        import os

        if data:
            ssh_username = data.get("ssh_username")
            ssh_password = data.get("ssh_password")
            ssh_port = data.get("ssh_port")
            ssh_host = data.get("ssh_host")
            private_key = data.get("private_key")
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
            flag_use_sha1_key_verification = data.get("flag_use_sha1_key_verification")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            ssh_username = bs_decrypt(self.ssh_username, encryption_key)
            ssh_password = bs_decrypt(self.ssh_password, encryption_key)
            ssh_port = self.ssh_port
            ssh_host = self.ssh_host
            private_key = bs_decrypt(self.private_key, encryption_key)
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            flag_use_sha1_key_verification = self.flag_use_sha1_key_verification

        ssh = None
        ssh_key_path = None

        disabled_algorithms = None
        if flag_use_sha1_key_verification:
            disabled_algorithms = {"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]}

        if use_public_key:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            pkey = paramiko.RSAKey.from_private_key_file(settings.SSH_KEY_PATH)
            ssh.connect(
                ssh_host,
                auth_timeout=180,
                banner_timeout=180,
                timeout=180,
                port=int(ssh_port),
                username=ssh_username,
                pkey=pkey,
                disabled_algorithms=disabled_algorithms,
            )
            sftp = ssh.open_sftp()
            sftp.listdir(".")
            sftp.close()
        elif use_private_key:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            fd, ssh_key_path = tempfile.mkstemp(dir="/home/ubuntu/backupsheep/_storage")
            with os.fdopen(fd, "w") as tmp:
                tmp.write(private_key)

            pkey = paramiko.RSAKey.from_private_key_file(ssh_key_path, password=ssh_password)
            ssh.connect(
                ssh_host,
                auth_timeout=180,
                banner_timeout=180,
                timeout=180,
                look_for_keys=False,
                port=int(ssh_port),
                username=ssh_username,
                pkey=pkey,
                disabled_algorithms=disabled_algorithms,
            )

            sftp = ssh.open_sftp()
            sftp.listdir(".")
            sftp.close()
        if not ssh:
            raise NodeConnectionErrorSSH()
        return ssh, ssh_key_path

    def get_ssh_process(self, data=None):
        import paramiko
        import tempfile
        import os
        import subprocess

        if data:
            ssh_username = data.get("ssh_username")
            ssh_password = data.get("ssh_password")
            ssh_port = data.get("ssh_port")
            ssh_host = data.get("ssh_host")
            private_key = data.get("private_key")
            use_public_key = data.get("use_public_key")
            use_private_key = data.get("use_private_key")
            flag_use_sha1_key_verification = data.get("flag_use_sha1_key_verification")
        else:
            encryption_key = self.connection.account.get_encryption_key()
            ssh_username = bs_decrypt(self.ssh_username, encryption_key)
            ssh_password = bs_decrypt(self.ssh_password, encryption_key)
            ssh_port = self.ssh_port
            ssh_host = self.ssh_host
            private_key = bs_decrypt(self.private_key, encryption_key)
            use_public_key = self.use_public_key
            use_private_key = self.use_private_key
            flag_use_sha1_key_verification = self.flag_use_sha1_key_verification

        ssh = None
        ssh_key_path = None

        if use_public_key:
            p = subprocess.Popen(
                f"ssh {ssh_username}@{ssh_host} -p {int(ssh_port)} -i {settings.SSH_KEY_PATH}",
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p.stdin.write("ls\n")
            print(p.stdout.read())
        elif use_private_key:
            fd, ssh_key_path = tempfile.mkstemp(dir="/home/ubuntu/backupsheep/_storage")
            with os.fdopen(fd, "w") as tmp:
                tmp.write(private_key)

            p = subprocess.Popen(
                f"ssh {ssh_username}@{ssh_host} -p {int(ssh_port)} -i {ssh_key_path}",
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            p.stdin.write("ls\n")
            print(p.stdout.read())
        if not ssh:
            raise NodeConnectionErrorSSH()
        return ssh, ssh_key_path

    def get_eligible_objects(self):
        import mysql.connector
        import psycopg2

        encryption_key = self.connection.account.get_encryption_key()

        eligible_objects = []
        self.check_connection(data=None, check_errors=True)

        try:
            option_ssl_mode = ""
            if self.use_ssl:
                option_ssl_mode = "--ssl-mode=PREFERRED"

            if self.type == self.DatabaseType.MYSQL:
                if self.use_public_key or self.use_private_key:

                    ssh, ssh_key_path = self.get_ssh_client()

                    if self.database_name:
                        execstr = (
                            f"mysql"
                            f" {option_ssl_mode}"
                            f" --disable-column-names"
                            f" -h'{self.host}'"
                            f" -u'{bs_decrypt(self.username, encryption_key)}'"
                            f" -p'{bs_decrypt(self.password, encryption_key)}'"
                            f" --port='{self.port}'"
                            f' -e"use {self.database_name}; show tables;"'
                        )
                    else:
                        execstr = (
                            f"mysql"
                            f" {option_ssl_mode}"
                            f" --disable-column-names"
                            f" -h'{self.host}'"
                            f" -u'{bs_decrypt(self.username, encryption_key)}'"
                            f" -p'{bs_decrypt(self.password, encryption_key)}'"
                            f' --port="{self.port}"'
                            f' -e"show databases;"'
                        )

                    stdin, stdout, stderr = ssh.exec_command(execstr)
                    #
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     if "warning" not in error.lower() and "info" not in error.lower():
                    #         raise NodeConnectionErrorMYSQL(error)

                    for line in stdout:
                        database_name = line.strip("\n").strip()

                        if database_name:
                            eligible_objects.append({"name": database_name})
                    """
                    Delete temp SSH Key
                    """
                    ssh.close()
                    if ssh_key_path:
                        os.remove(ssh_key_path)
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])
                else:
                    db_con = mysql.connector.connect(
                        host=self.host,
                        port=int(self.port),
                        user=bs_decrypt(self.username, encryption_key),
                        passwd=bs_decrypt(self.password, encryption_key),
                        db=self.database_name,
                        connect_timeout=60,
                        ssl_disabled=(not self.use_ssl),
                    )
                    cursor = db_con.cursor()
                    cursor.execute("SHOW TABLES")
                    result = cursor.fetchall()
                    for item in result:
                        eligible_objects.append({"name": item[0]})
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])
                    cursor.close()
                    db_con.close()
            elif self.type == self.DatabaseType.MARIADB:
                if self.use_public_key or self.use_private_key:
                    ssh, ssh_key_path = self.get_ssh_client()

                    if self.database_name:
                        execstr = (
                            f"mysql"
                            f" {option_ssl_mode}"
                            f" --disable-column-names"
                            f" -h'{self.host}'"
                            f" -u'{bs_decrypt(self.username, encryption_key)}'"
                            f" -p'{bs_decrypt(self.password, encryption_key)}'"
                            f" --port='{self.port}'"
                            f' -e"use {self.database_name}; show tables;"'
                        )

                    else:
                        execstr = (
                            f"mysql"
                            f" {option_ssl_mode}"
                            f" --disable-column-names"
                            f" -h'{self.host}'"
                            f" -u'{bs_decrypt(self.username, encryption_key)}'"
                            f" -p'{bs_decrypt(self.password, encryption_key)}'"
                            f' --port="{self.port}" -e"show databases;"'
                        )

                    stdin, stdout, stderr = ssh.exec_command(execstr)
                    #
                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     if "warning" not in error.lower() and "info" not in error.lower():
                    #         raise NodeConnectionErrorMARIADB(error)

                    for line in stdout:
                        database_name = line.strip("\n").strip()
                        if database_name:
                            eligible_objects.append({"name": database_name})
                    """
                    Delete temp SSH Key
                    """
                    ssh.close()
                    if ssh_key_path:
                        os.remove(ssh_key_path)

                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])
                else:
                    db_con = mysql.connector.connect(
                        host=self.host,
                        port=int(self.port),
                        user=bs_decrypt(self.username, encryption_key),
                        passwd=bs_decrypt(self.password, encryption_key),
                        db=self.database_name,
                        connect_timeout=60,
                        ssl_disabled=(not self.use_ssl),
                    )
                    cursor = db_con.cursor()
                    cursor.execute("SHOW TABLES")
                    result = cursor.fetchall()
                    for item in result:
                        eligible_objects.append({"name": item[0]})
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])
                    cursor.close()
                    db_con.close()
            elif self.type == self.DatabaseType.POSTGRESQL:
                if self.use_public_key or self.use_private_key:
                    ssh, ssh_key_path = self.get_ssh_client()

                    if self.database_name:
                        execstr = (
                            'psql "host=%s'
                            " user='%s'"
                            " dbname='%s'"
                            " password='%s'"
                            " port=%s"
                            ' sslmode=prefer" -c "\dt" -qAtX | cut -d \| -f 2'
                            % (
                                self.host,
                                bs_decrypt(self.username, encryption_key),
                                self.database_name,
                                bs_decrypt(self.password, encryption_key),
                                self.port,
                            )
                        )
                    else:
                        execstr = (
                            'psql "host=%s'
                            " user='%s'"
                            " password='%s'"
                            " port=%s"
                            ' sslmode=prefer" -lqt | cut -d \| -f 1'
                            % (
                                self.host,
                                bs_decrypt(self.username, encryption_key),
                                bs_decrypt(self.password, encryption_key),
                                self.port,
                            )
                        )

                    stdin, stdout, stderr = ssh.exec_command(execstr)

                    # for line in stderr:
                    #     error = line.strip("\n").strip()
                    #     if "warning" not in error.lower():
                    #         raise NodeConnectionErrorPOSTGRESQL(error)

                    for line in stdout:
                        database_name = line.strip("\n").strip()
                        if database_name:
                            eligible_objects.append({"name": database_name})
                    """
                    Delete temp SSH Key
                    """
                    ssh.close()
                    if ssh_key_path:
                        os.remove(ssh_key_path)
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])
                else:
                    db_con = psycopg2.connect(
                        dbname=self.database_name,
                        user=bs_decrypt(self.username, encryption_key),
                        password=bs_decrypt(self.password, encryption_key),
                        host=self.host,
                        port=self.port,
                    )

                    cursor = db_con.cursor()
                    cursor.execute("select relname from pg_class where relkind='r' and relname !~ '^(pg_|sql_)';")
                    result = cursor.fetchall()

                    for item in result:
                        eligible_objects.append({"name": item[0]})
                    eligible_objects = sorted(eligible_objects, key=lambda k: k["name"])
                    cursor.close()
                    db_con.close()
        except Exception as e:
            raise NodeConnectionErrorEligibleObjects(e.__str__())

        return eligible_objects

    def validate(self, check_errors=None, raise_exp=None):
        try:
            self.check_connection(data=None, check_errors=check_errors)
            return True
        except Exception as e:
            if check_errors and raise_exp:
                raise IntegrationValidationError(e.__str__())
            else:
                return False


class CoreAuthWordPress(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_wordpress", on_delete=models.CASCADE)
    url = models.URLField()
    key = models.CharField(max_length=255)
    http_user = models.CharField(max_length=255, null=True, blank=True)
    http_pass = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = "core_auth_wordpress"

    def get_client(self):
        user_agent = (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14"
            " (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A"
        )
        try:
            from fake_useragent import UserAgent

            ua = UserAgent(use_cache_server=False)
            user_agent = ua.random
        except Exception as e:
            pass

        client = {
            "User-Agent": user_agent,
            "content-type": "application/json",
        }
        return client

    def get_auth(self, data=None):
        if data:
            http_user = data.get("http_user")
            http_pass = data.get("http_pass")
        else:
            http_user = self.http_user
            http_pass = self.http_pass
        auth = None
        if http_user and http_pass:
            auth = (http_user, http_pass)
        return auth

    def validate(self, data=None, check_errors=None, raise_exp=None):
        from bs4 import BeautifulSoup
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3 import Retry
        import ssl
        import time

        if data:
            url = data["url"]
            key = data["key"]
        else:
            url = self.url
            key = self.key

        client = self.get_client()

        # adapter = SSLAdapter(ssl.PROTOCOL_TLSv1_2)
        # s = requests.Session()
        # s.mount('https://', adapter)
        try:
            session = requests.Session()
            session.auth = self.get_auth(data)
            retry_strategy = Retry(
                total=3,
                backoff_factor=5,
                status_forcelist=[429, 500, 502, 503, 504],
                method_whitelist=["HEAD", "GET", "OPTIONS"],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            url = f"{url}/?rest_route=/backupsheep/updraftplus/validate&key={key}&t={time.time()}"
            result = session.get(url, timeout=60, verify=False, headers=client)
        except Exception as e:
            if check_errors:
                if "handshake failure" in e.__str__():
                    raise ValueError(
                        "SSL handshake failed. "
                        f"Please use our website and database integration for this website. Validation URL: {url}"
                    )
                elif "retries exceeded with url" in e.__str__():
                    raise ValueError(
                        f"Unable to connect to your WordPress website due to timeout. If you are using Cloudflare,"
                        f" Stackpath or any security plugin in your WordPress then please allow backup server IPs."
                        f"  Validation URL: {url}"
                    )
                else:
                    raise ValueError(
                        f"Unable to connect to your website. If you are using Cloudflare, "
                        f"Stackpath or any security plugin in your WordPress then please allow backup "
                        f"server IPs or you can"
                        f" use our website and database integration for this website. Validation URL: {url}"
                    )
            else:
                return False
        if result.status_code == 200:
            try:
                if result.json().get("plugins", {}).get("backupsheep") and result.json().get("plugins", {}).get(
                    "updraftplus"
                ):
                    return True
                elif not result.json().get("validate_backupsheep_key"):
                    raise ValueError(
                        "Invalid WordPress Key. Please get correct WordPress Key from your integration "
                        f"and add it to BackupSheep Wordpress plugin. Validation URL: {url}"
                    )
                elif not result.json().get("plugins", {}).get("backupsheep") and not result.json().get(
                    "plugins", {}
                ).get("updraftplus"):
                    raise ValueError(f"Your BackupSheep & UpdraftPlus plugins are not active. Validation URL: {url}")
                elif not result.json().get("plugins", {}).get("backupsheep") and not result.json().get(
                    "plugins", {}
                ).get("updraftplus"):
                    raise ValueError(f"Your BackupSheep & UpdraftPlus plugins are not active. Validation URL: {url}")
                elif not result.json().get("plugins", {}).get("backupsheep"):
                    raise ValueError(f"Your BackupSheep plugin is not active. Validation URL: {url}")
                elif not result.json().get("plugins", {}).get("updraftplus"):
                    raise ValueError(f"Your UpdraftPlus plugin is not active. Validation URL: {url}")
            except JSONDecodeError:
                if check_errors:
                    raise ValueError(
                        f"Invalid JSON response. If you are using Cloudflare then add backup server IPs"
                        f"to web application firewall. Also check your .htaccess file on your web server."
                        f" Validation URL: {url}"
                    )
                else:
                    return False
            except Exception as e:
                if check_errors:
                    raise ValueError(e.__str__())
                else:
                    return False
        elif result.status_code == 404:
            if result.json().get("rest_no_route") == "rest_no_route":
                raise ValueError("Please install BackupSheep and UpdraftPlus plugin. Validation URL: {url}")
        else:
            if check_errors:
                soup = BeautifulSoup(result.text)
                raise ValueError(soup.get_text())
            else:
                return None


class CoreAuthBasecamp(TimeStampedModel):
    connection = models.OneToOneField("CoreConnection", related_name="auth_basecamp", on_delete=models.CASCADE)
    access_token = models.BinaryField(null=True)
    refresh_token = models.BinaryField(null=True)
    token_type = models.CharField(max_length=255, default="Bearer")
    expiry = models.DateTimeField(null=True)
    identity_id = models.CharField(max_length=255)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_auth_basecamp"

    def get_client(self):
        encryption_key = self.connection.account.get_encryption_key()

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

        encryption_key = self.connection.account.get_encryption_key()

        refresh_token = bs_decrypt(self.refresh_token, encryption_key)

        params = {
            "type": "refresh",
            "refresh_token": refresh_token,
            "client_id": settings.BASECAMP_CLIENT_ID,
            "client_secret": settings.BASECAMP_CLIENT_SECRET,
            # "redirect_uri": f"{settings.APP_URL + settings.BASECAMP_REDIRECT_URL}",
        }

        token_request = requests.post(settings.BASECAMP_TOKEN_ENDPOINT, data=params)

        if token_request.status_code == 200:
            token_data = token_request.json()
            self.access_token = bs_encrypt(token_data["access_token"], encryption_key)
            self.expiry = datetime.fromtimestamp((int(time.time()) + int(token_data["expires_in"])))
            self.save()

    def validate(self, data=None, check_errors=None, raise_exp=None):
        url = "https://launchpad.37signals.com/authorization.json"

        headers = self.get_client()

        response = requests.request("GET", url, headers=headers, data={})

        if response.status_code == 200:
            return True
        else:
            return False

    def get_eligible_objects(self):
        eligible_objects = []

        url = "https://launchpad.37signals.com/authorization.json"

        headers = self.get_client()

        response = requests.request("GET", url, headers=headers, data={})

        if response.status_code == 200:
            data = response.json()

            for account in data.get("accounts"):
                url = f"{account['href']}/projects.json"
                headers = self.get_client()
                project_response = requests.request("GET", url, headers=headers, data={})

                if project_response.status_code == 200:
                    projects = project_response.json()
                    for project in projects:
                        eligible_objects.append(
                            {
                                "id": project["id"],
                                "name": project["name"],
                                "description": project["description"],
                                "account_id": account["id"],
                                "account_name": account["name"],
                                "account_product": account["product"],
                            }
                        )
        return eligible_objects

class CoreConnectionStatus(models.Model):
    code = models.CharField(max_length=64, unique=True)
    private = models.BooleanField(default=False)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_connection_status"


class CoreConnectionLocation(UtilBase):
    code = models.CharField(max_length=64, unique=True)
    ip_address = models.GenericIPAddressField(null=True)
    ip_address_v6 = models.GenericIPAddressField(null=True)
    location = models.CharField(max_length=64, null=True)
    image_url = models.TextField(null=True)
    api_endpoint = models.CharField(max_length=255, null=True)
    api_url = models.URLField(null=True)
    queue = models.CharField(max_length=64, null=True)
    position = models.IntegerField(null=True)
    integrations = models.ManyToManyField(
        CoreIntegration,
        related_name="locations",
        through="CoreConnectionLocationIntegration",
    )
    task_list = models.JSONField(null=True)

    class Meta:
        db_table = "core_connection_location"
        verbose_name = "Location"
        verbose_name_plural = "Locations"
        ordering = ["position"]

    def compile_url(self, path):
        if "node-web-" in settings.SERVER_CODE:
            url = f"{self.api_url}{path}"
        elif settings.SERVER_CODE == "local":
            url = f"{settings.APP_URL}{path}"
        else:
            url = f"{self.api_url}{path}"
        return url


class CoreConnectionLocationIntegration(TimeStampedModel):
    def __str__(self):
        return "%s --  %s " % (self.integration.name, self.location.name)

    location = models.ForeignKey(CoreConnectionLocation, on_delete=models.PROTECT)
    integration = models.ForeignKey(CoreIntegration, on_delete=models.PROTECT)

    class Meta:
        db_table = "core_connection_location_mtm_integrations"
        verbose_name = "Integration Location"
        verbose_name_plural = "Integration Locations"


class CoreConnection(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        PENDING = 2, "Pending"
        SUSPENDED = 3, "Suspended"
        PAUSED = 4, "Paused"
        DELETE_REQUESTED = 5, "Delete Requested"
        TOKEN_REFRESH_FAIL = 6, "Token Refresh Failed"

    class Notification(models.IntegerChoices):
        NOT_SENT = 1, "Not Sent"
        SENT = 2, "Sent"

    account = models.ForeignKey(CoreAccount, related_name="connections", on_delete=models.CASCADE)
    old_status = models.ForeignKey(
        CoreConnectionStatus,
        related_name="connections",
        on_delete=models.CASCADE,
        null=True,
    )
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    notification = models.IntegerField(choices=Notification.choices, default=Notification.NOT_SENT)
    integration = models.ForeignKey(CoreIntegration, related_name="connections", on_delete=models.PROTECT)
    location = models.ForeignKey(
        CoreConnectionLocation,
        related_name="connections",
        on_delete=models.PROTECT,
        null=True,
    )
    name = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    added_by = models.ForeignKey(
        CoreMember,
        related_name="added_connections",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_connection"

    def update_scheduled_backup_locations(self, location):
        pass

        # from apps.console.node.models import CoreSchedule
        #
        # for schedule in CoreSchedule.objects.filter(node__connection_id=self.id):
        #     if schedule.celery_periodic_task:
        #         if schedule.celery_periodic_task.queue:
        #             schedule.celery_periodic_task.queue = (
        #                 schedule.celery_periodic_task.queue.replace(
        #                     schedule.node.connection.location.queue, location.queue
        #                 )
        #             )
        #             schedule.celery_periodic_task.save()
        #             PeriodicTasks.changed(schedule.celery_periodic_task)

    # Todo: Also terminate current running backups.
    def delete_requested(self):
        self.status = CoreConnection.Status.DELETE_REQUESTED
        self.save()
        for node in self.nodes.all():
            node.delete_requested()

    def validate(self, check_errors=None, raise_exp=None):
        if hasattr(self, f"auth_{self.integration.code}"):
            auth_object = getattr(self, f"auth_{self.integration.code}")
            return auth_object.validate(check_errors=check_errors, raise_exp=raise_exp)

    def backup_ready_to_initiate(self):
        launch_ok = self.status == self.Status.ACTIVE
        return launch_ok

    def total_nodes(self):
        return self.nodes.filter().count()

    def type(self):
        return  self.integration.type

    @property
    def incremental_backup_available(self):
        if self.integration.code == "website":
            return self.auth_website.use_public_key or self.auth_website.use_private_key
