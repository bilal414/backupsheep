import datetime
import json
import humanfriendly
import pytz
import requests
from celery import chord
from django.conf import settings
from django.db import models
from django.db.models import UniqueConstraint
from django.utils.text import slugify
from django.utils.timezone import get_current_timezone
from django_celery_beat.models import PeriodicTask, CrontabSchedule
from model_utils.models import TimeStampedModel
from ovh import InvalidCredential, ResourceConflictError
from sentry_sdk import capture_exception, capture_message

from apps.console.storage.models import CoreStorage
from apps._tasks.exceptions import (
    NodeBackupFailedError,
    NodeBackupStatusCheckTimeOutError,
    NodeBackupStatusCheckCallError,
    NodeConnectionError,
)
import humanize

from apps._tasks.integration.backup.dfferential import snapshot_dfferential
from apps.api.v1.utils.api_helpers import get_error, mkdir_p
from ..backup.models import CoreDatabaseBackupStoragePoints
from ..connection.models import CoreConnection
from ..member.models import CoreMember


from ..utils.models import UtilBackup, UtilCloud
from botocore.exceptions import ClientError


class CoreServerStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_server_status"


class CoreServerType(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_server_type"


class CoreDigitalOcean(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="digitalocean", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_digitalocean"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_digitalocean.get_client()
        if self.node.type == CoreNode.Type.CLOUD:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                r_json = result.json()
                if r_json.get("droplet"):
                    server = r_json.get("droplet")
                    if server.get("status") == "active" and not server.get("locked"):
                        node_ok = True
        elif self.node.type == CoreNode.Type.VOLUME:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_digitalocean.get_client()

            if self.node.type == CoreNode.Type.CLOUD:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    droplet = result.json()["droplet"]
                    if droplet["status"] == "active" or droplet["status"] == "new":
                        droplet_data = {"type": "snapshot", "name": backup.uuid_str}
                        result = requests.post(
                            f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}/actions",
                            headers=client,
                            data=json.dumps(droplet_data),
                            verify=True,
                        )
                        if result.status_code == 201:
                            action = result.json()["action"]
                            backup.action_id = action.get("id")
                            backup.save()
                        else:
                            raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                        f"API call returned with status {result.status_code}")
                    else:
                        raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                    f"Droplet status is {droplet['status']}")
                elif result.status_code == 502:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Invalid response from DigitalOcean API. We will try again shortly.",
                    )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                elif result.status_code == 401:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Unable to connect to your DigitalOcean account. Please reconnect your account to refresh authentication token.",
                    )
                else:
                    raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                f"API call returned with status {result.status_code}")

            elif self.node.type == CoreNode.Type.VOLUME:
                volume_data = {"name": backup.uuid_str}

                result = requests.post(
                    f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}/snapshots",
                    headers=client,
                    data=json.dumps(volume_data),
                    verify=True,
                )

                if result.status_code == 201:
                    snapshot = result.json()["snapshot"]
                    backup.unique_id = snapshot["id"]
                    backup.size_gigabytes = snapshot["min_disk_size"]
                    backup.save()
                elif result.status_code == 502:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Invalid response from DigitalOcean API. We will try again shortly.",
                    )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                elif result.status_code == 401:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Unable to connect to your DigitalOcean account. Please reconnect your account to refresh authentication token.",
                    )
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )


class CoreContabo(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="contabo", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_contabo"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_digitalocean.get_client()
        if self.node.type == CoreNode.Type.CLOUD:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                r_json = result.json()
                if r_json.get("droplet"):
                    server = r_json.get("droplet")
                    if server.get("status") == "active" and not server.get("locked"):
                        node_ok = True
        elif self.node.type == CoreNode.Type.VOLUME:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_digitalocean.get_client()

            if self.node.type == CoreNode.Type.CLOUD:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    droplet = result.json()["droplet"]
                    if droplet["status"] == "active" or droplet["status"] == "new":
                        droplet_data = {"type": "snapshot", "name": backup.uuid_str}
                        result = requests.post(
                            f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}/actions",
                            headers=client,
                            data=json.dumps(droplet_data),
                            verify=True,
                        )
                        if result.status_code == 201:
                            action = result.json()["action"]
                            backup.action_id = action.get("id")
                            backup.save()
                        else:
                            raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                        f"API call returned with status {result.status_code}")
                    else:
                        raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                    f"Droplet status is {droplet['status']}")
                elif result.status_code == 502:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Invalid response from DigitalOcean API. We will try again shortly.",
                    )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                elif result.status_code == 401:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Unable to connect to your DigitalOcean account. "
                        "Please reconnect your account to refresh authentication token.",
                    )
                else:
                    raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                f"API call returned with status {result.status_code}")

            elif self.node.type == CoreNode.Type.VOLUME:
                volume_data = {"name": backup.uuid_str}

                result = requests.post(
                    f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}/snapshots",
                    headers=client,
                    data=json.dumps(volume_data),
                    verify=True,
                )

                if result.status_code == 201:
                    snapshot = result.json()["snapshot"]
                    backup.unique_id = snapshot["id"]
                    backup.size_gigabytes = snapshot["min_disk_size"]
                    backup.save()
                elif result.status_code == 502:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Invalid response from DigitalOcean API. We will try again shortly.",
                    )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                elif result.status_code == 401:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Unable to connect to your DigitalOcean account. "
                        "Please reconnect your account to refresh authentication token.",
                    )
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )


class CoreHetzner(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="hetzner", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_hetzner"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_hetzner.get_client()
        result = requests.get(
            f"{settings.HETZNER_API}/v1/servers/{self.unique_id}",
            headers=client,
            verify=True,
        )
        if result.status_code == 200:
            r_json = result.json()
            if r_json.get("server"):
                server = r_json.get("server")
                if server.get("status") == "running" and not server.get("locked"):
                    node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_hetzner.get_client()

            if self.node.type == CoreNode.Type.CLOUD:
                server_data = {"description": backup.uuid_str, "type": "snapshot"}
                result = requests.post(
                    f"{settings.HETZNER_API}/v1/servers/{self.unique_id}/actions/create_image",
                    data=json.dumps(server_data),
                    headers=client,
                    verify=True,
                )
                if result.status_code == 201:
                    image = result.json()["image"]
                    action = result.json()["action"]
                    if action["status"] == "running":
                        backup.action_id = action["id"]
                        backup.unique_id = image["id"]
                        backup.metadata = result.json()
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str, backup.attempt_no, backup.type, f"Status code was: {action['status']}",
                        )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        f"API status code was: {result.status_code}",
                    )

            elif self.node.type == CoreNode.Type.VOLUME:
                # Hetzner Cloud Doesn't offer Volume backup
                pass
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )


class CoreUpCloud(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="upcloud", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_upcloud"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_upcloud.get_client()
        result = requests.get(
            f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
            auth=client,
            verify=True,
            headers={"content-type": "application/json"}
        )
        if result.status_code == 200:
            r_json = result.json()
            if r_json.get("storage"):
                storage = r_json.get("storage")
                if storage.get("state") == "online":
                    node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_upcloud.get_client()

            if self.node.type == CoreNode.Type.VOLUME:
                server_data = {"storage": {"title": backup.uuid_str}}
                result = requests.post(
                    f"{settings.UPCLOUD_API}/storage/{self.unique_id}/backup",
                    data=json.dumps(server_data),
                    auth=client,
                    verify=True,
                    headers={"content-type": "application/json"}
                )
                if result.status_code == 201:
                    storage = result.json()["storage"]
                    backup.unique_id = storage["uuid"]
                    backup.size_gigabytes = storage["size"]
                    backup.metadata = result.json()
                    backup.save()
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "API rate limit exceeded. We will try again shortly.",
                    )
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        f"API call returned with status {result.status_code}"
                    )
            elif self.node.type == CoreNode.Type.CLOUD:
                # UpCloud Doesn't offer Server backup
                pass
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )


class CoreOVHCA(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="ovh_ca", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_ca"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_ovh_ca.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            ovh_response = client.get(f"/cloud/project/{self.project_id}/instance/{self.unique_id}")
            if ovh_response.get("status") == "ACTIVE":
                node_ok = True
        elif self.node.type == CoreNode.Type.VOLUME:
            ovh_response = client.get(f"/cloud/project/{self.project_id}/volume/{self.unique_id}")
            if ovh_response.get("status") == "available" or ovh_response.get("status") == "in-use":
                node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        client = self.node.connection.auth_ovh_ca.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/instance/{self.unique_id}/snapshot",
                    snapshotName=backup.uuid_str,
                )
                # This unique_id will be updated in validate() method with actual ID from OVH
                backup.unique_id = backup.uuid_str
                backup.save()
            except InvalidCredential:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/volume/{self.unique_id}/snapshot",
                    name=backup.uuid_str,
                )
                backup.unique_id = backup.uuid_str
                backup.save()
            except InvalidCredential:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )


class CoreOVHEU(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="ovh_eu", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_eu"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_ovh_eu.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            ovh_response = client.get(f"/cloud/project/{self.project_id}/instance/{self.unique_id}")
            if ovh_response.get("status") == "ACTIVE":
                node_ok = True
        elif self.node.type == CoreNode.Type.VOLUME:
            ovh_response = client.get(f"/cloud/project/{self.project_id}/volume/{self.unique_id}")
            if ovh_response.get("status") == "available" or ovh_response.get("status") == "in-use":
                node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        client = self.node.connection.auth_ovh_eu.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/instance/{self.unique_id}/snapshot",
                    snapshotName=backup.uuid_str,
                )
                # This unique_id will be updated in validate() method with actual ID from OVH
                backup.unique_id = backup.uuid_str
                backup.save()
            except InvalidCredential:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/volume/{self.unique_id}/snapshot",
                    name=backup.uuid_str,
                )
                backup.unique_id = backup.uuid_str
                backup.save()
            except InvalidCredential:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )


class CoreOVHUS(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="ovh_us", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_us"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_ovh_us.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            ovh_response = client.get(f"/cloud/project/{self.project_id}/instance/{self.unique_id}")
            if ovh_response.get("status") == "ACTIVE":
                node_ok = True
        elif self.node.type == CoreNode.Type.VOLUME:
            ovh_response = client.get(f"/cloud/project/{self.project_id}/volume/{self.unique_id}")
            if ovh_response.get("status") == "available" or ovh_response.get("status") == "in-use":
                node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        client = self.node.connection.auth_ovh_us.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/instance/{self.unique_id}/snapshot",
                    snapshotName=backup.uuid_str,
                )
                # This unique_id will be updated in validate() method with actual ID from OVH
                backup.unique_id = backup.uuid_str
                backup.save()
            except InvalidCredential:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/volume/{self.unique_id}/snapshot",
                    name=backup.uuid_str,
                )
                backup.unique_id = backup.uuid_str
                backup.save()
            except InvalidCredential:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node,
                    backup.uuid_str,
                    backup.attempt_no,
                    backup.type,
                    message=get_error(e)
                )


class CoreAWS(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="aws", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    no_reboot = models.BooleanField(default=True)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws"

    def validate(self):
        node_ok = False
        try:
            client = self.node.connection.auth_aws.get_client()

            if self.node.type == CoreNode.Type.CLOUD:
                response = client.describe_instances(
                    InstanceIds=[self.unique_id],
                )
                if response.get("Reservations"):
                    instance = response.get("Reservations")[0]["Instances"][0]
                    if instance.get("State", {}).get("Name") == "running" or instance.get("State", {}).get(
                            "Name") == "stopped":
                        node_ok = True
            elif self.node.type == CoreNode.Type.VOLUME:
                response = client.describe_volumes(
                    VolumeIds=[self.unique_id],
                )
                volume = response.get("Volumes")[0]
                if volume.get("State") == "available" or volume.get("State") == "in-use":
                    node_ok = True
            return node_ok
        except ClientError as e:
            return False
        except Exception as e:
            return False

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_aws.get_client()

            if self.node.type == CoreNode.Type.CLOUD:
                response = client.create_image(
                    Description=backup.uuid_str,
                    InstanceId=self.unique_id,
                    Name=backup.uuid_str,
                    NoReboot=self.no_reboot,
                )

                if not response.get("ImageId"):
                    raise NodeBackupFailedError(self.node,
                                                backup.uuid_str,
                                                backup.attempt_no,
                                                backup.type, f"ImageID not present")

                image_id = response.get("ImageId")

                backup.unique_id = image_id
                backup.save()

            elif self.node.type == CoreNode.Type.VOLUME:
                response = client.create_snapshot(
                    Description=backup.uuid_str,
                    VolumeId=self.unique_id,
                )

                if not response.get("SnapshotId"):
                    raise NodeBackupFailedError(self.node,
                                                backup.uuid_str,
                                                backup.attempt_no,
                                                backup.type, f"SnapshotId not present.")

                snapshot_id = response.get("SnapshotId")
                backup.unique_id = snapshot_id
                backup.save()
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )


class CoreLightsail(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="lightsail", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_lightsail"

    def validate(self):
        node_ok = False
        try:
            client = self.node.connection.auth_lightsail.get_client()

            if self.node.type == CoreNode.Type.CLOUD:
                response = client.get_instance(
                    instanceName=self.unique_id
                )
                if response.get("instance"):
                    instance = response.get("instance")
                    if instance.get("state", {}).get("name") == "running" or instance.get("state", {}).get(
                            "name") == "stopped":
                        node_ok = True
            elif self.node.type == CoreNode.Type.VOLUME:
                response = client.get_disk(
                    diskName=self.unique_id
                )
                disk = response.get("disk")
                if disk.get("state") == "available" or disk.get("state") == "in-use":
                    node_ok = True
            return node_ok
        except ClientError as e:
            return False
        except Exception as e:
            return False

    def create_snapshot(self, backup):
        try:
            client = self.node.connection.auth_lightsail.get_client()

            if self.node.type == CoreNode.Type.CLOUD:
                response = client.create_instance_snapshot(
                    instanceSnapshotName=backup.uuid_str, instanceName=self.unique_id
                )
                if response.get("operations"):
                    operation = response["operations"][0]

                    if operation["status"] != "Failed":
                        backup.unique_id = backup.uuid_str
                        backup.save()
            elif self.node.type == CoreNode.Type.VOLUME:
                response = client.create_disk_snapshot(
                    diskName=backup.uuid_str,
                    diskSnapshotName=self.unique_id,
                )
                if response.get("operations"):
                    operation = response["operations"][0]

                    if operation["status"] != "Failed":
                        backup.unique_id = backup.uuid_str
                        backup.save()
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )


class CoreAWSRDS(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="aws_rds", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws_rds"

    def validate(self):
        node_ok = False
        try:
            client = self.node.connection.auth_aws_rds.get_client()

            response = client.describe_db_instances(
                DBInstanceIdentifier=self.unique_id
            )
            if response.get("DBInstances"):
                db_instance = response.get("DBInstances")[0]
                if db_instance.get("DBInstanceStatus") == "available" or db_instance.get("DBInstanceStatus") == "stopped":
                    node_ok = True
            return node_ok
        except ClientError as e:
            return False
        except Exception as e:
            return False

    def create_snapshot(self, backup):
        client = self.node.connection.auth_aws_rds.get_client()
        snapshot = client.create_db_snapshot(
            DBSnapshotIdentifier=backup.uuid_str, DBInstanceIdentifier=self.unique_id
        )
        backup.unique_id = snapshot["DBSnapshot"]["DBSnapshotIdentifier"]
        backup.size_gigabytes = snapshot["DBSnapshot"]["AllocatedStorage"]
        backup.save()


class CoreVultr(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="vultr", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_vultr"

    def validate(self):
        node_ok = False
        client = self.node.connection.auth_vultr.get_client()
        if self.node.type == CoreNode.Type.CLOUD:
            result = requests.get(
                f"{settings.VULTR_API}/v2/instances/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                instance = result.json()["instance"]
                if instance["status"] == "active":
                    node_ok = True
        elif self.node.type == CoreNode.Type.VOLUME:
            result = requests.get(
                f"{settings.VULTR_API}/v2/blocks/{self.unique_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                block = result.json()["block"]
                if block["status"] == "active":
                    node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        client = self.node.connection.auth_vultr.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                result = requests.post(
                    f"{settings.VULTR_API}/v2/snapshots",
                    headers=client,
                    data=json.dumps(
                        {"instance_id": self.unique_id, "description": self.node.name}
                    ),
                    verify=True,
                )
                if result.status_code == 201:
                    snapshot = result.json()["snapshot"]
                    backup.unique_id = snapshot["id"]
                    backup.metadata = snapshot
                    backup.save()
                elif result.status_code == 502:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Invalid response from Vultr API. We will try again shortly.",
                    )
                elif result.status_code == 429:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Vultr 12 snapshot limit exceeded. Vultr limits each account to have maximum of 12 snapshots.",
                    )
                elif result.status_code == 401:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str, backup.attempt_no, backup.type,
                        "Unable to connect to your Vultr account. Please reconnect your account to refresh authentication token.",
                    )
                else:
                    raise NodeBackupFailedError(self.node, backup.uuid_str, backup.attempt_no, backup.type,
                                                f"API call returned with status {result.status_code}")
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            pass


class CoreOracle(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="oracle", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_oracle"

    def validate(self):
        import oci
        from oci.core.models import BootVolumeBackup, VolumeBackup

        node_ok = False

        if self.node.type == CoreNode.Type.VOLUME:
            config = self.node.connection.auth_oracle.get_client()
            block_storage_client = oci.core.BlockstorageClient(config)

            if self.metadata.get("_bs_vol_type") == "boot":
                request = block_storage_client.get_boot_volume(self.unique_id)
                if request.status == 200:
                    if (
                        request.data.id == self.unique_id
                        and request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_AVAILABLE
                    ):
                        node_ok = True
            elif self.metadata.get("_bs_vol_type") == "block":
                request = block_storage_client.get_volume(self.unique_id)
                if request.status == 200:
                    if (
                        request.data.id == self.unique_id
                        and request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_AVAILABLE
                    ):
                        node_ok = True
        return node_ok

    def create_snapshot(self, backup):
        import oci
        from oci.core.models import CreateBootVolumeBackupDetails, CreateVolumeBackupDetails

        if self.node.type == CoreNode.Type.VOLUME:
            try:
                config = self.node.connection.auth_oracle.get_client()
                block_storage_client = oci.core.BlockstorageClient(config)

                if self.metadata.get("_bs_vol_type") == "boot":
                    boot_volume_backup_details = CreateBootVolumeBackupDetails(
                        boot_volume_id=self.unique_id,
                        display_name=backup.uuid_str,
                        freeform_tags={"BACKUPSHEEP__UUID": backup.uuid_str},
                        type=CreateBootVolumeBackupDetails.TYPE_FULL,
                    )

                    request = block_storage_client.create_boot_volume_backup(
                        create_boot_volume_backup_details=boot_volume_backup_details, opc_retry_token=backup.uuid_str
                    )
                    if request.status == 200:
                        backup.unique_id = request.data.id
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            f"API call returned with status {request.status}",
                        )
                elif self.metadata.get("_bs_vol_type") == "block":
                    volume_backup_details = CreateVolumeBackupDetails(
                        volume_id=self.unique_id,
                        display_name=backup.uuid_str,
                        freeform_tags={"BACKUPSHEEP__UUID": backup.uuid_str},
                        type=CreateVolumeBackupDetails.TYPE_FULL,
                    )

                    request = block_storage_client.create_volume_backup(
                        create_volume_backup_details=volume_backup_details, opc_retry_token=backup.uuid_str
                    )

                    if request.status == 200:
                        backup.unique_id = request.data.id
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            f"API call returned with status {request.status}",
                        )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )


class CoreLinode(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="linode", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    linode_id = models.CharField(max_length=255, null=True)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_linode"


class CoreGoogleCloud(UtilCloud):
    node = models.OneToOneField(
        "CoreNode", related_name="google_cloud", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    unique_id = models.CharField(max_length=255)
    project_id = models.CharField(max_length=255)
    zone = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_google_cloud"

    def validate(self):
        node_ok = False

        if self.node.type == CoreNode.Type.CLOUD:
            client = self.node.connection.auth_google_cloud.get_client()

            result = requests.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.node.google_cloud.project_id}"
                f"/zones/{self.node.google_cloud.zone}"
                f"/instances/{self.node.google_cloud.unique_id}", headers=client
            )
            if result.status_code == 200:
                instance = result.json()

                if (
                    instance.get("status") == "RUNNING"
                    or instance.get("status") == "TERMINATED"
                    or instance.get("status") == "SUSPENDED"
                ):
                    node_ok = True

        elif self.node.type == CoreNode.Type.VOLUME:
            client = self.node.connection.auth_google_cloud.get_client()

            result = requests.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.node.google_cloud.project_id}"
                f"/zones/{self.node.google_cloud.zone}"
                f"/disks/{self.node.google_cloud.unique_id}", headers=client
            )
            if result.status_code == 200:
                instance = result.json()

                if instance.get("status") == "READY":
                    node_ok = True
        return node_ok

    def create_snapshot(self, backup):

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                client = self.node.connection.auth_google_cloud.get_client()

                result = requests.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/zones/{self.node.google_cloud.zone}"
                    f"/instances/{self.node.google_cloud.unique_id}",
                    headers=client
                )
                if result.status_code == 200:
                    instance = result.json()

                    result = requests.post(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.node.google_cloud.project_id}"
                        f"/global/machineImages",
                        headers=client,
                        data=json.dumps(
                            {"name": backup.uuid_str,
                             "sourceInstance": f"projects/{self.node.google_cloud.project_id}"
                                               f"/zones/{self.node.google_cloud.zone}"
                                               f"/instances/{instance['name']}"}
                        ),
                    )
                    if result.status_code == 200:
                        image = result.json()
                        backup.unique_id = image["id"]
                        backup.size_gigabytes = int(image.get("totalStorageBytes", 0))/(1000**3)
                        backup.metadata = image
                        backup.save()
                    else:
                        raise NodeBackupFailedError(
                            self.node,
                            backup.uuid_str,
                            backup.attempt_no,
                            backup.type,
                            f"Unable to create instance image. API call returned with status {result.status_code}",
                        )
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        f"Unable to get instance details. API call returned with status {result.status_code}",
                    )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                client = self.node.connection.auth_google_cloud.get_client()
                result = requests.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/zones/{self.node.google_cloud.zone}"
                    f"/disks/{self.node.google_cloud.unique_id}",
                    headers=client
                )
                if result.status_code == 200:
                    disk = result.json()
                    result = requests.post(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.node.google_cloud.project_id}"
                        f"/zones/{self.node.google_cloud.zone}"
                        f"/disks/{disk['name']}/createSnapshot",
                        headers=client,
                        data=json.dumps(
                            {"name": backup.uuid_str,
                             "sourceInstance": f"projects/{self.node.google_cloud.project_id}"
                                               f"/zones/{self.node.google_cloud.zone}"
                                               f"/disks/{disk['name']}"}
                        ),
                    )
                    if result.status_code == 200:
                        snapshot = result.json()
                        backup.unique_id = snapshot["id"]
                        backup.size_gigabytes = int(snapshot.get("storageBytes", 0)) / (1000 ** 3)
                        backup.metadata = snapshot
                        backup.save()
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        f"Unable to create instance image. API call returned with status {result.status_code}",
                    )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )


class CoreWebsite(TimeStampedModel):
    class BackupType(models.IntegerChoices):
        FULL = 1, "Full v1"
        INCREMENTAL = 2, "Incremental"
        DIFFERENTIAL = 3, "Differential"
        FULL_V2 = 4, "Full v2"

    node = models.OneToOneField(
        "CoreNode", related_name="website", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    paths = models.JSONField(null=True)
    excludes = models.JSONField(null=True)
    includes_regex = models.JSONField(null=True)
    includes_glob = models.JSONField(null=True)
    excludes_regex = models.JSONField(null=True)
    excludes_glob = models.JSONField(null=True)
    parallel = models.IntegerField(null=True, default=3)
    verbose = models.BooleanField(default=False, null=True)
    all_paths = models.BooleanField(null=True)
    notes = models.TextField(null=True, blank=True)
    backup_type = models.IntegerField(choices=BackupType.choices, default=BackupType.FULL)
    tar_temp_backup_dir = models.TextField(null=True, blank=True)
    tar_exclude_vcs_ignores = models.BooleanField(default=False, null=True)
    tar_exclude_vcs = models.BooleanField(default=False, null=True)
    tar_exclude_backups = models.BooleanField(default=False, null=True)
    tar_exclude_caches = models.BooleanField(default=False, null=True)

    class Meta:
        db_table = "core_website"

    def create_snapshot(self, backup):
        from apps._tasks.integration.backup.website import snapshot_website
        from apps._tasks.integration.backup.incremental import snapshot_incremental
        from apps._tasks.integration.backup.full_v2 import snapshot_full_v2
        from apps._tasks.integration.storage.tasks import storage_upload
        from ..backup.models import CoreWebsiteBackupStoragePoints
        from apps._tasks.helper.tasks import delete_from_disk

        backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
        backup.save()

        """
        Run Website Backup
        """
        if self.backup_type == self.BackupType.INCREMENTAL and (
            self.node.connection.auth_website.use_private_key or self.node.connection.auth_website.use_public_key
        ):
            snapshot_incremental(backup)
        elif self.backup_type == self.BackupType.DIFFERENTIAL and (
            self.node.connection.auth_website.use_private_key or self.node.connection.auth_website.use_public_key
        ):
            snapshot_dfferential(backup)
        elif self.backup_type == self.BackupType.FULL_V2 and (
                self.node.connection.auth_website.use_private_key or self.node.connection.auth_website.use_public_key
        ):
            snapshot_full_v2(backup)
        else:
            snapshot_website(backup)

        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()

        try:
            """
            Upload Website Backup
            """
            storage_upload_task_list = []
            for stored_website_backup in backup.stored_website_backups.filter(
                    status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_READY
            ):
                queue = f"storage_upload__{self.node.connection.integration.code}__{self.node.get_integration_alt_code()}__{self.node.connection.location.queue}"
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_website_backup.id
                    ).set(queue=queue)
                )

            queue = f"delete_from_disk__{backup.website.node.connection.location.queue}"
            final_call_back_task = delete_from_disk.si(backup.uuid_str, "zip").set(
                queue=queue
            )
            chord(storage_upload_task_list, final_call_back_task).apply_async()
        except Exception as e:
            capture_exception(e)
        return backup


class CoreDatabase(TimeStampedModel):
    node = models.OneToOneField(
        "CoreNode", related_name="database", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    tables = models.JSONField(null=True)
    all_tables = models.BooleanField(null=True)
    databases = models.JSONField(null=True)
    all_databases = models.BooleanField(null=True)
    option_single_transaction = models.BooleanField(null=True, default=True)
    option_skip_opt = models.BooleanField(null=True, default=False)
    option_compress = models.BooleanField(null=True, default=True)
    # todo: remove this field.
    option_gtid_purged_off = models.BooleanField(null=True, default=True)
    #todo: remove this field.
    option_postgres_format_custom = models.BooleanField(null=True, default=False)
    notes = models.TextField(null=True, blank=True)
    option_postgres = models.TextField(null=True, blank=True)
    option_mysql = models.TextField(null=True, blank=True)
    option_mariadb = models.TextField(null=True, blank=True)
    option_mongodb = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "core_database"

    def create_snapshot(self, backup):
        from ..connection.models import CoreAuthDatabase
        from apps._tasks.integration.storage.tasks import storage_upload
        from apps._tasks.helper.tasks import delete_from_disk
        from apps._tasks.integration.backup.mariadb import snapshot_mariadb
        from apps._tasks.integration.backup.mysql import snapshot_mysql
        from apps._tasks.integration.backup.postgresql import snapshot_postgresql

        """
        Run Database Backup
        """
        backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
        backup.save()

        if (
                self.node.connection.auth_database.type
                == CoreAuthDatabase.DatabaseType.MYSQL
        ):
            snapshot_mysql(backup)
        if (
                self.node.connection.auth_database.type
                == CoreAuthDatabase.DatabaseType.MARIADB
        ):
            snapshot_mariadb(backup)
        if (
                self.node.connection.auth_database.type
                == CoreAuthDatabase.DatabaseType.POSTGRESQL
        ):
            snapshot_postgresql(backup)

        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()

        try:
            """
            Upload Database Backup
            """
            storage_upload_task_list = []
            for stored_database_backup in backup.stored_database_backups.filter(
                    status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_READY
            ):
                queue = f"storage_upload__{self.node.connection.integration.code}__{self.node.get_integration_alt_code()}__{self.node.connection.location.queue}"
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_database_backup.id
                    ).set(queue=queue)
                )

            queue = (
                f"delete_from_disk__{backup.database.node.connection.location.queue}"
            )
            final_call_back_task = delete_from_disk.si(backup.uuid_str, "zip").set(
                queue=queue
            )
            chord(storage_upload_task_list, final_call_back_task).apply_async()
        except Exception as e:
            raise NodeBackupFailedError(
                self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
            )
        return backup


class CoreWordPress(TimeStampedModel):
    class Include(models.IntegerChoices):
        FULL = 1, "Full (Database + Files)"
        DATABASE = 2, "Only Database"
        FILES = 3, "Only Files"

    include = models.IntegerField(choices=Include.choices, default=Include.FULL)
    node = models.OneToOneField(
        "CoreNode", related_name="wordpress", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "core_wordpress"

    def create_snapshot(self, backup):
        from apps._tasks.integration.backup.wordpress import snapshot_wordpress
        from apps._tasks.integration.storage.tasks import storage_upload
        from ..backup.models import CoreWordPressBackupStoragePoints
        from apps._tasks.helper.tasks import delete_from_disk

        backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
        backup.save()

        """
        Run WordPress Backup
        """
        snapshot_wordpress(backup)

        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()

        try:
            """
            Upload Wordpress Backup
            """
            storage_upload_task_list = []
            for stored_wordpress_backup in backup.stored_wordpress_backups.filter(
                    status=CoreWordPressBackupStoragePoints.Status.UPLOAD_READY
            ):
                queue = f"storage_upload__{self.node.get_type_display().lower()}__{self.node.get_integration_alt_code()}__{self.node.connection.location.queue}"
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_wordpress_backup.id
                    ).set(queue=queue)
                )

            queue = f"delete_from_disk__{backup.wordpress.node.connection.location.queue}"
            final_call_back_task = delete_from_disk.si(backup.uuid_str, "zip").set(
                queue=queue
            )
            chord(storage_upload_task_list, final_call_back_task).apply_async()
        except Exception as e:
            capture_exception(e)
        return backup


class CoreBasecamp(TimeStampedModel):
    node = models.OneToOneField(
        "CoreNode", related_name="basecamp", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)
    projects = models.JSONField(null=True)
    all_projects = models.BooleanField(default=False)

    class Meta:
        db_table = "core_basecamp"

    def create_snapshot(self, backup):
        from apps._tasks.integration.backup.basecamp import snapshot_basecamp
        from apps._tasks.integration.storage.tasks import storage_upload
        from ..backup.models import CoreBasecampBackupStoragePoints
        from apps._tasks.helper.tasks import delete_from_disk

        backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
        backup.save()

        """
        Run Basecamp Backup
        """
        snapshot_basecamp(backup)

        backup.status = UtilBackup.Status.DOWNLOAD_COMPLETE
        backup.save()

        try:
            """
            Upload Basecamp Backup
            """
            storage_upload_task_list = []
            for stored_basecamp_backup in backup.stored_basecamp_backups.filter(
                    status=CoreBasecampBackupStoragePoints.Status.UPLOAD_READY
            ):
                queue = f"storage_upload__{self.node.get_type_display().lower()}__{self.node.get_integration_alt_code()}__{self.node.connection.location.queue}"
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_basecamp_backup.id
                    ).set(queue=queue)
                )

            queue = f"delete_from_disk__{backup.basecamp.node.connection.location.queue}"
            final_call_back_task = delete_from_disk.si(backup.uuid_str, "zip").set(
                queue=queue
            )
            chord(storage_upload_task_list, final_call_back_task).apply_async()
        except Exception as e:
            capture_exception(e)
        return backup


class CoreIntercom(TimeStampedModel):
    node = models.OneToOneField(
        "CoreNode", related_name="intercom", on_delete=models.CASCADE
    )
    name = models.CharField(max_length=255)
    notes = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "core_intercom"

    def create_snapshot(self, backup):
        pass


class CoreSchedule(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        PAUSED = 2, "Paused"
        DELETE_REQUESTED = 3, "Delete Requested"

    class Type(models.TextChoices):
        CRON = "cron", "Cron"
        RATE = "rate", "Rate"
        ONETIME = "at", "One-time"

    class RateUnit(models.TextChoices):
        MINUTES = "minutes", "Minutes"
        HOURS = "hours", "Hours"
        DAYS = "days", "Days"

    node = models.ForeignKey(
        "CoreNode", related_name="schedules", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreServerScheduleStatus, related_name="schedules", on_delete=models.PROTECT
    # )
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    type = models.CharField(choices=Type.choices, default="cron", max_length=64)
    rate_unit = models.CharField(choices=RateUnit.choices, null=True, max_length=64)
    rate_value = models.IntegerField(null=True)
    at_datetime = models.DateTimeField(null=True)
    celery_periodic_task = models.ForeignKey(
        PeriodicTask,
        related_name="schedules",
        null=True,
        on_delete=models.SET_NULL,
        editable=False,
    )
    storage_points = models.ManyToManyField(CoreStorage, related_name="schedules")
    name = models.CharField(max_length=255)
    keep_last = models.PositiveIntegerField(null=True)
    type_legacy = models.CharField(max_length=32, default="crontab")
    hour = models.CharField(max_length=255, null=True, blank=True)
    minute = models.CharField(max_length=255, null=True, blank=True)
    day_of_week = models.CharField(max_length=255, null=True, blank=True)
    day_of_month = models.CharField(max_length=255, null=True, blank=True)
    month_of_year = models.CharField(max_length=255, null=True, blank=True)
    year = models.CharField(max_length=255, default="*", null=True, blank=True)
    delete_remote_backups = models.BooleanField(default=False)
    compressed_backups_only = models.BooleanField(default=False, null=True)
    delete_remote_backups_time = models.IntegerField(null=True)
    encrypt_backup = models.BooleanField(default=False, null=True)
    timezone = models.CharField(max_length=64)
    notes = models.TextField(null=True, blank=True)
    aws_schedule_arn = models.TextField(null=True, blank=True)
    added_by = models.ForeignKey(
        CoreMember,
        related_name="added_schedules",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_schedule"

    @property
    def uuid_str(self):
        return slugify(f"bs-s{self.id}-n{self.node.id}-a{self.node.connection.account.id}")

    @property
    def task_name(self):
        name = (
            f"scheduled_backup"
            f"__{self.node.connection.location.queue}"
        )
        return name

    @property
    def queue_name(self):
        name = (
            f"scheduled_backup"
            f"__{self.node.get_type_display().lower()}"
            f"__{self.node.get_integration_alt_code()}"
            f"__{self.node.connection.location.queue}"
        )
        return name

    @property
    def storage_ids(self):
        return list(self.storage_points.filter().values_list("id", flat=True))

    def crontab_display(self):
        return f"{self.minute} {self.hour} {self.day_of_month} {self.month_of_year} {self.day_of_week}"

    def delete_requested(self):
        self.status = CoreSchedule.Status.DELETE_REQUESTED
        # if self.celery_periodic_task:
        #     self.celery_periodic_task.enabled = False
        #     self.celery_periodic_task.save()
        self.save()

    def aws_schedule_expression(self):
        if self.type == CoreSchedule.Type.CRON:
            return (
                f"{self.type}({self.minute} {self.hour} {self.day_of_month} {self.month_of_year} {self.day_of_week} {self.year})"
            )
        elif self.type == CoreSchedule.Type.RATE:
            return f"{self.type}({self.rate_value} {self.rate_unit})"
        elif self.type == CoreSchedule.Type.ONETIME:
            return f"{self.type}({self.at_datetime})"

    def aws_schedule_create(self):
        import boto3
        from rest_framework.authtoken.models import Token

        aws_scheduler = boto3.client(
            "scheduler",
            aws_access_key_id=settings.AWS_SCHEDULER_ACCESS_KEY,
            aws_secret_access_key=settings.AWS_SCHEDULER_SECRET_KEY,
            region_name="us-east-1"
        )

        host = settings.AWS_SCHEDULER_API_HOST

        path = f"/api/v1/schedules/{self.id}/trigger/"

        # AWS Labmda will use token to make call
        member = self.node.connection.account.get_primary_member()
        api_token, _ = Token.objects.get_or_create(user=member.user)
        token = api_token.key

        schedule_settings = {
            "RoleArn": settings.AWS_SCHEDULER_ROLE_ARN,
            "Arn": settings.AWS_SCHEDULER_FUNCTION_ARN,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 24 * 3600, "MaximumRetryAttempts": 100},
            "Input": json.dumps(
                {"host": host, "path": path, "token": token}
            ),
        }

        flex_window = {"Mode": "OFF"}

        state = "ENABLED"

        aws_schedule = {
            "Name": self.uuid_str,
            "State": state,
            "ScheduleExpression": self.aws_schedule_expression(),
            "ScheduleExpressionTimezone": self.timezone,
            "Target": schedule_settings,
            "FlexibleTimeWindow": flex_window,
        }

        aws_response = aws_scheduler.create_schedule(**aws_schedule)
        self.aws_schedule_arn = aws_response.get("ScheduleArn")
        self.save()

    def aws_schedule_update(self):
        import boto3
        from rest_framework.authtoken.models import Token

        aws_scheduler = boto3.client(
            "scheduler",
            aws_access_key_id=settings.AWS_SCHEDULER_ACCESS_KEY,
            aws_secret_access_key=settings.AWS_SCHEDULER_SECRET_KEY,
            region_name="us-east-1"
        )

        host = settings.AWS_SCHEDULER_API_HOST

        path = f"/api/v1/schedules/{self.id}/trigger/"

        # AWS Labmda will use token to make call
        member = self.node.connection.account.get_primary_member()
        api_token, _ = Token.objects.get_or_create(user=member.user)
        token = api_token.key

        schedule_settings = {
            "RoleArn": settings.AWS_SCHEDULER_ROLE_ARN,
            "Arn": settings.AWS_SCHEDULER_FUNCTION_ARN,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 24 * 3600, "MaximumRetryAttempts": 100},
            "Input": json.dumps(
                {"host": host, "path": path, "token": token}
            ),
        }

        flex_window = {"Mode": "OFF"}

        if self.status == self.Status.ACTIVE:
            state = "ENABLED"
        else:
            state = "DISABLED"

        aws_schedule = {
            "Name": self.uuid_str,
            "State": state,
            "ScheduleExpression": self.aws_schedule_expression(),
            "ScheduleExpressionTimezone": self.timezone,
            "Target": schedule_settings,
            "FlexibleTimeWindow": flex_window,
        }

        aws_scheduler.get_schedule(Name=self.uuid_str)
        aws_response = aws_scheduler.update_schedule(**aws_schedule)
        self.aws_schedule_arn = aws_response.get("ScheduleArn")
        self.save()

    def aws_schedule_delete(self):
        import boto3

        aws_scheduler = boto3.client(
            "scheduler",
            aws_access_key_id=settings.AWS_SCHEDULER_ACCESS_KEY,
            aws_secret_access_key=settings.AWS_SCHEDULER_SECRET_KEY,
            region_name="us-east-1"
        )

        aws_scheduler.delete_schedule(Name=self.uuid_str)
        self.aws_schedule_arn = None
        self.save()

    def aws_schedule_expression_tmp(self):
        # https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html#cron-based

        if self.day_of_month == "*" and self.day_of_week == "*":
            day_of_month = "*"
            day_of_week = "?"
        elif self.day_of_month != "*" and self.day_of_week == "*":
            day_of_month = self.day_of_month
            day_of_week = "?"
        elif self.day_of_month == "*" and self.day_of_week != "*":
            day_of_month = "?"
            day_of_week = self.day_of_week
        elif self.day_of_month != "*" and self.day_of_week != "*":
            day_of_month = self.day_of_month
            day_of_week = "?"
        else:
            day_of_month = self.day_of_month
            day_of_week = self.day_of_week

        # 0 doesn't work in AWS. 7 is Sunday.
        day_of_week = day_of_week.replace("0", "1")

        if "*/" in day_of_month:
            day_of_month = "1"

        if "*/" in self.hour:
            self.hour = "0"

        year = "*"

        return f"{self.minute} {self.hour} {day_of_month} {self.month_of_year} {day_of_week} {year}"

    def aws_schedule_sync_tmp(self):
        import boto3
        from rest_framework.authtoken.models import Token

        aws_scheduler = boto3.client(
            "scheduler",
            aws_access_key_id=settings.AWS_SCHEDULER_ACCESS_KEY,
            aws_secret_access_key=settings.AWS_SCHEDULER_SECRET_KEY,
            region_name="us-east-1"
        )

        if "localhost" in settings.APP_DOMAIN:
            host = "backupsheep.net"
        else:
            host = settings.AWS_SCHEDULER_API_HOST

        path = f"/api/v1/schedules/{self.id}/trigger/"

        # AWS Labmda will use token to make call
        member = self.node.connection.account.get_primary_member()
        api_token, _ = Token.objects.get_or_create(user=member.user)
        token = api_token.key

        schedule_settings = {
            "RoleArn": settings.AWS_SCHEDULER_ROLE_ARN,
            "Arn": settings.AWS_SCHEDULER_FUNCTION_ARN,
            "RetryPolicy": {"MaximumEventAgeInSeconds": 24 * 3600, "MaximumRetryAttempts": 100},
            "Input": json.dumps(
                {"host": host, "path": path, "token": token}
            ),
        }

        flex_window = {"Mode": "OFF"}

        if self.status == self.Status.ACTIVE:
            state = "ENABLED"
        else:
            state = "DISABLED"

        aws_schedule = {
            "Name": self.uuid_str,
            "State": state,
            "ScheduleExpression": f"cron({self.aws_schedule_expression_tmp()})",
            "ScheduleExpressionTimezone": self.timezone,
            "Target": schedule_settings,
            "FlexibleTimeWindow": flex_window,
        }

        try:
            """
            Update Schedule
            """
            aws_scheduler.get_schedule(Name=self.uuid_str)

            aws_response = aws_scheduler.update_schedule(**aws_schedule)

            self.aws_schedule_arn = aws_response.get("ScheduleArn")
            self.save()
            print(f"Updated...{self.aws_schedule_arn}")
        except ClientError as err:
            if err.response['Error']['Code'] == 'ResourceNotFoundException':
                """
                Create Schedule
                """
                aws_response = aws_scheduler.create_schedule(**aws_schedule)
                self.aws_schedule_arn = aws_response.get("ScheduleArn")
                self.save()
                print(f"Created...{self.aws_schedule_arn}")


    def setup_periodic_task(self):
        pass
        # if self.type == "crontab":
        #     crontab_schedule, created = CrontabSchedule.objects.get_or_create(
        #         minute=self.minute,
        #         hour=self.hour,
        #         day_of_week=self.day_of_week,
        #         day_of_month=self.day_of_month,
        #         month_of_year=self.month_of_year,
        #         timezone=self.timezone,
        #     )
        #     name = f"schedule__{self.id}__{str(uuid.uuid4())}"
        #     queue = f"queue_periodic__{self.id}__{self.node.get_type_display().lower()}__{self.node.connection.integration.code}__{self.node.connection.location.queue}"
        #     task = f"backup_{self.node.connection.integration.code}"
        #
        #     if (
        #             self.node.type == CoreNode.Type.WEBSITE
        #             or self.node.type == CoreNode.Type.DATABASE
        #             or self.node.type == CoreNode.Type.SAAS
        #     ):
        #         data = [self.node.id, self.id, None]
        #     else:
        #         data = [self.node.id, self.id]
        #
        #     periodic_task = PeriodicTask.objects.create(
        #         crontab=crontab_schedule,
        #         name=name,
        #         queue=queue,
        #         task=task,
        #         args=json.dumps(data),
        #     )
        #     self.celery_periodic_task = periodic_task
        #     self.save()


class CoreScheduleRun(TimeStampedModel):
    schedule = models.ForeignKey(CoreSchedule, related_name="runs", on_delete=models.CASCADE)
    request_id = models.CharField(max_length=1024)

    class Meta:
        db_table = "core_schedule_run"
        constraints = [
            UniqueConstraint(
                fields=["schedule", "request_id"], name="unique_schedule_trigger_request"
            ),
        ]


class CoreNode(TimeStampedModel):
    class Status(models.IntegerChoices):
        ACTIVE = 1, "Active"
        BACKUP_READY = 2, "Ready for Backup"
        BACKUP_IN_PROGRESS = 3, "Backup In-Progress"
        BACKUP_RETRYING = 4, "Retrying Backup"
        SUSPENDED = 5, "Suspended"
        PAUSED = 6, "Paused"
        PAUSED_MAX_RETRIES = 8, "Paused (Max Retries)"
        DELETE_REQUESTED = 7, "Delete Requested"
        DELETE_COMPLETED = 9, "Delete Completed"

    class Type(models.IntegerChoices):
        CLOUD = 1, "Cloud"
        VOLUME = 2, "Volume"
        WEBSITE = 3, "Website"
        DATABASE = 4, "Database"
        SAAS = 5, "SaaS"

    connection = models.ForeignKey(
        CoreConnection, related_name="nodes", on_delete=models.CASCADE
    )
    status = models.IntegerField(choices=Status.choices, default=Status.ACTIVE)
    type = models.IntegerField(choices=Type.choices)
    name = models.CharField(max_length=255)
    flag_next_run_wait = models.IntegerField(null=True)
    flag_delete_node = models.BooleanField(default=False)
    notify_on_success = models.BooleanField(default=True, null=True)
    notify_on_fail = models.BooleanField(default=True, null=True)
    email_data = models.JSONField(null=True)
    timezone = models.CharField(max_length=64, default="UTC")
    added_by = models.ForeignKey(
        CoreMember,
        related_name="added_nodes",
        on_delete=models.CASCADE,
        null=True,
    )

    class Meta:
        db_table = "core_node"
        permissions = (
            ("create_ondemand_backup", "can create on-demand backup"),
            ("create_schedule", "can create schedule for backup"),
        )

    def validate(self):
        if hasattr(self, self.connection.integration.code):
            node_integration_object = getattr(self, self.connection.integration.code)
            return node_integration_object.validate()

    """
    Disabled this on Oct-2021. Don't think this is used anymore because node status is checked in backup_ready_to_initiate()
    """

    # def save(self, *args, **kwargs):
    #     if self.id:
    #         if self.status == self.Status.ACTIVE:
    #             # re-enable schedules, otherwise they will keep running
    #             for schedule in self.schedules.filter(
    #                     status=CoreSchedule.Status.PAUSED
    #             ):
    #                 schedule.status = CoreSchedule.Status.ACTIVE
    #                 schedule.save()
    #         elif (
    #                 self.status == self.Status.PAUSED
    #                 or self.status == self.Status.SUSPENDED
    #         ):
    #             # disable schedules, otherwise they will keep running
    #             for schedule in self.schedules.filter(
    #                     status=CoreSchedule.Status.ACTIVE
    #             ):
    #                 schedule.status = CoreSchedule.Status.PAUSED
    #                 schedule.save()
    #     return super(CoreNode, self).save(*args, **kwargs)

    def backup_task_name(self):
        return f"backup_{self.connection.integration.code}"

    def get_integration_alt_code(self):
        if self.connection.integration.code == "database":
            return self.connection.auth_database.get_type_display().lower()
        elif self.connection.integration.code == "website":
            return self.connection.auth_website.get_protocol_display().lower()
        else:
            return self.connection.integration.code.lower()

    def get_integration_alt_name(self):
        if self.connection.integration.code == "database":
            return self.connection.auth_database.get_type_display()
        elif self.connection.integration.code == "website":
            return self.connection.auth_website.get_protocol_display()
        else:
            return self.connection.integration.name

    def get_backup_from_celery_task_id(self, celery_task_id):
        node_type_object = getattr(self, self.connection.integration.code)
        if node_type_object.backups.filter(celery_task_id=celery_task_id).exists() and celery_task_id:
            return node_type_object.backups.get(celery_task_id=celery_task_id)

    @property
    def get_node_url(self):
        node_type_object = getattr(self, self.connection.integration.code)
        return f"/console/{self.get_type_display().lower()}s/{self.connection.integration.code}/{node_type_object.id}"

    @property
    def name_slug(self):
        trimmed = (self.name[:24]) if len(self.name) > 24 else self.name
        return slugify(f"{trimmed}-n{self.id}")

    @property
    def uuid_str(self):
        return slugify(f"bs-n{self.id}")

    @property
    def incremental_backup_available(self):
        if self.connection.integration.code == "website":
            return self.connection.auth_website.use_public_key or self.connection.auth_website.use_private_key

    def backup_ready_to_initiate(self, celery_task_id=None):
        if self.get_backup_from_celery_task_id(celery_task_id):
            return True
        elif self.status == self.Status.ACTIVE:
            return True
        elif self.status == self.Status.BACKUP_RETRYING or\
                self.status == self.Status.BACKUP_READY or\
                self.status == self.Status.PAUSED_MAX_RETRIES or\
                self.status == self.Status.BACKUP_IN_PROGRESS:
            node_type_object = getattr(self, self.connection.integration.code)

            if node_type_object.backups.filter().count() > 0:
                last_backup = node_type_object.backups.filter().order_by("-created").first()
                if last_backup.status == UtilBackup.Status.COMPLETE:
                    return True
                else:
                    t_difference = datetime.datetime.now(tz=pytz.UTC) - last_backup.created
                    hours_since_last_backup = int(t_difference.total_seconds() / 3600)
                    if hours_since_last_backup >= 1:
                        return True
            else:
                return True

    def billing_good_standing(self):
        try:
            return self.connection.account.billing.good_standing()
        except Exception as e:
            return False

    def last_backup_date(self):
        node_type_object = getattr(self, self.connection.integration.code)
        if node_type_object.backups.filter(status=UtilBackup.Status.COMPLETE).count() > 0:
            backup = node_type_object.backups.filter(status=UtilBackup.Status.COMPLETE).order_by('-created').first()
            timezone = str(get_current_timezone())
            timezone = pytz.timezone(timezone)
            date_time = backup.created.astimezone(timezone).strftime("%b %d %Y - %I:%M%p")
            return date_time
        else:
            return None

    def list_backups(self, list_all_backups=None):
        from django.db.models import Q
        node_type_object = getattr(self, self.connection.integration.code)
        if list_all_backups is True:
            return node_type_object.backups.filter()
        else:
            query = (
                    ~Q(status=UtilBackup.Status.DELETE_FAILED)
                    & ~Q(status=UtilBackup.Status.DELETE_REQUESTED)
                    & ~Q(status=UtilBackup.Status.DELETE_COMPLETED)
                    & ~Q(status=UtilBackup.Status.DELETE_FAILED_NOT_FOUND)
                    & ~Q(status=UtilBackup.Status.DELETE_MAX_RETRY_FAILED)
            )
        return node_type_object.backups.filter(query)

    def total_backups(self):
        node_type_object = getattr(self, self.connection.integration.code)
        return node_type_object.backups.filter(status=UtilBackup.Status.COMPLETE).count()

    def total_storage(self):
        from django.db.models import Sum

        if self.connection.integration.code == "website" or self.connection.integration.code == "database":
            node_type_object = getattr(self, self.connection.integration.code)
            node_stats = node_type_object.backups.filter(status=UtilBackup.Status.COMPLETE).aggregate(Sum("size"))
            return humanfriendly.format_size(node_stats["size__sum"] or 0)
        elif self.connection.integration.type == "saas":
            node_type_object = getattr(self, self.connection.integration.code)
            node_stats = node_type_object.backups.filter(status=UtilBackup.Status.COMPLETE).aggregate(Sum("size"))
            return humanfriendly.format_size(node_stats["size__sum"] or 0)
        else:
            node_type_object = getattr(self, self.connection.integration.code)
            node_stats = node_type_object.backups.filter(status=UtilBackup.Status.COMPLETE).aggregate(
                Sum("size_gigabytes"))
            return humanfriendly.format_size(1000 ** 3 * (node_stats["size_gigabytes__sum"] or 0))

    def total_schedules(self):
        return self.schedules.filter(status=CoreSchedule.Status.ACTIVE).count()

    # def validate(self):
    #     validate_ok = (
    #             self.connection.status == CoreConnection.Status.ACTIVE
    #             and self.connection.validate()
    #     )
    #     return validate_ok

    def backup_initiate(
            self, celery_task_id, backup_type, attempt_no, schedule_id, storage_ids, notes
    ):
        node_type_object = getattr(self, self.connection.integration.code)
        backup, created = node_type_object.backups.get_or_create(celery_task_id=celery_task_id)
        backup.status = UtilBackup.Status.IN_PROGRESS
        backup.type = backup_type
        backup.attempt_no = attempt_no
        backup.schedule_id = schedule_id
        backup.notes = notes

        # Only setup UUID if it's new backup. No need to generate same UUID on retry
        if created:
            if schedule_id:
                schedule = CoreSchedule.objects.get(id=schedule_id)
                schedule_slug = f"{backup.get_type_display()}-{schedule.name}"
            else:
                schedule_slug = f"{backup.get_type_display()}"
            n_and_s = f"{self.name} - {schedule_slug}"
            n_and_s_trimmed = (n_and_s[:24]) if len(n_and_s) > 24 else n_and_s
            backup.uuid = slugify(f"bs-{n_and_s_trimmed}-n{self.id}-b{backup.id}").replace("_", "-")
        backup.save()

        # Cloud servers and volumes don't have storage points for now
        if self.type == self.Type.DATABASE or self.type == self.Type.WEBSITE or self.type == self.Type.SAAS:
            storage_points = CoreStorage.objects.filter(
                id__in=storage_ids,
                account=self.connection.account,
                status=CoreStorage.Status.ACTIVE,
            )
            for storage_point in storage_points:
                """
                Validate all storage points
                """
                if storage_point.validate():
                    backup.storage_points.add(storage_point)
                else:
                    self.connection.account.create_backup_log(
                        message=f"Storage validation failed for {storage_point.name} ({storage_point.type.name}) "
                                f"during backup ({backup.uuid_str}) of your node ({self.name}). ",
                        node=self,
                        backup=backup
                    )

            """
            If all user storage points fail validation then add BackupSheep default storage
            """
            if backup.storage_points.count() == 0:
                storage = CoreStorage.objects.filter(
                    storage_bs__isnull=False,
                    account=self.connection.account,
                    status=CoreStorage.Status.ACTIVE,
                ).first()
                backup.storage_points.add(storage)

                self.connection.account.create_backup_log(
                    message=f"Using BackupSheep Storage for node ({self.name}) backup ({backup.uuid_str}) because "
                            f"validation failed for all your selected storage points.",
                    node=self,
                    backup=backup
                )
        self.save()
        return backup

    def backup_complete_reset(self, celery_task_id=None):
        self.status = CoreNode.Status.ACTIVE
        self.save()

        if celery_task_id:
            backup = self.get_backup_from_celery_task_id(celery_task_id)
            if backup:
                backup.status = UtilBackup.Status.COMPLETE
                backup.save()

    def backup_timeout_reset(self, celery_task_id=None):
        self.status = CoreNode.Status.ACTIVE
        self.save()

        if celery_task_id:
            backup = self.get_backup_from_celery_task_id(celery_task_id)
            if backup:
                backup.status = UtilBackup.Status.TIMEOUT
                backup.save()

    def backup_retrying_reset(self, celery_task_id):
        backup = self.get_backup_from_celery_task_id(celery_task_id)
        if backup:
            backup.status = UtilBackup.Status.RETRYING
            backup.save()

    def backup_max_retries_reached(self, celery_task_id):
        # 2022-June - don't do max paused retry. This creates more problem.
        # self.status = self.Status.PAUSED_MAX_RETRIES
        # self.save()

        # pause schedules, otherwise they will keep running
        # 2022-May - don't need to disable all schedules. Just pause the node.
        # for schedule in self.schedules.filter(status=CoreSchedule.Status.ACTIVE):
        #     schedule.status = CoreSchedule.Status.PAUSED
        #     schedule.save()

        backup = self.get_backup_from_celery_task_id(celery_task_id)
        if backup:
            backup.status = UtilBackup.Status.MAX_RETRY_FAILED
            backup.save()

    def restart_reset(self):
        # node_type_object = getattr(self, self.connection.integration.code)
        # node_type_object.backups.filter()
        self.status = self.Status.ACTIVE
        self.save()

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    def notify_backup_fail(self, error, backup_type):
        from apps._tasks.helper.tasks import send_postmark_email
        from datetime import datetime

        if str(backup_type) == "1":
            backup_type = "On-Demand"
        elif str(backup_type) == "2":
            backup_type = "Scheduled"

        try:
            if self.notify_on_fail and self.connection.account.notify_on_fail:
                member = self.connection.account.get_primary_member()
                to_email = member.user.email

                timezone = pytz.timezone(member.timezone or "UTC")
                now = datetime.now()

                date_time = now.astimezone(timezone).strftime("%b %d %Y - %I:%M%p %Z")

                if error.__class__.__name__ == "ConnectionNotReadyForBackupError" and error.attempt_no == 1:
                    if self.type == self.Type.CLOUD:
                        action_url = f"https://backupsheep.com/console/setup/{self.get_integration_alt_code().lower()}/"
                    elif self.type == self.Type.VOLUME:
                        action_url = f"https://backupsheep.com/console/setup/{self.get_integration_alt_code().lower()}/"
                    elif self.type == self.Type.DATABASE:
                        action_url = (
                            f"https://backupsheep.com/console/setup/database/"
                        )
                    elif self.type == self.Type.WEBSITE:
                        action_url = (
                            f"https://backupsheep.com/console/setup/website/"
                        )
                    else:
                        action_url = f"https://backupsheep.com/console/"

                    data = {
                            "node_type": self.get_type_display().lower(),
                            "node_status": self.get_status_display(),
                            "node_name": self.name,
                            "backup_time": date_time,
                            "connection_name": self.connection.name,
                            "connection_status": self.connection.get_status_display(),
                            "action_url": action_url,
                            "backup_type": backup_type,
                            "endpoint_name": self.connection.location.name,
                            "endpoint_ip": self.connection.location.ip_address,
                            "endpoint_ipv6": self.connection.location.ip_address_v6,
                            "error_details": error.__str__(),
                            "message": error.__class__.__name__,
                            "help_url": "https://support.backupsheep.com",
                            "sender_name": "BackupSheep - Notification Bot",
                    }

                    self.connection.account.create_log(data=data)

                    send_postmark_email.delay(
                        to_email,
                        error.email_template_id,
                        data,
                    )
                elif error.__class__.__name__ == "NodeNotReadyForBackupError" and error.attempt_no == 1:
                    action_url = f"https://backupsheep.com/console/nodes/{self.id}/"

                    data = {
                            "node_type": self.get_type_display().lower(),
                            "node_status": self.get_status_display(),
                            "node_name": self.name,
                            "backup_time": date_time,
                            "connection_name": self.connection.name,
                            "connection_status": self.connection.get_status_display(),
                            "action_url": action_url,
                            "backup_type": backup_type,
                            "endpoint_name": self.connection.location.name,
                            "endpoint_ip": self.connection.location.ip_address,
                            "endpoint_ipv6": self.connection.location.ip_address_v6,
                            "error_details": error.__str__(),
                            "message": error.__class__.__name__,
                            "help_url": "https://support.backupsheep.com",
                            "sender_name": "BackupSheep - Notification Bot",
                    }

                    self.connection.account.create_log(data=data)

                    send_postmark_email.delay(
                        to_email,
                        error.email_template_id,
                        data
                    )
                elif error.__class__.__name__ == "NodeBackupFailedError" and error.attempt_no == 1:
                    # node_type_object = getattr(self, self.connection.integration.code)
                    action_url = f"https://backupsheep.com/console/nodes/{self.id}/"

                    if "SoftTimeLimitExceeded" in error.__str__():
                        error_details = "Backup execution timeout. Backup must complete within 12 hours or else it will be terminated."
                    elif "backupsheep" in error.__str__():
                        error_details = "n/a"
                    elif "_storage/" in error.__str__():
                        error_details = error.__str__().replace("_storage/", "")
                    else:
                        error_details = error.__str__()

                    data = {
                            "node_type": self.get_type_display().lower(),
                            "node_status": self.get_status_display(),
                            "node_name": self.name,
                            "backup_time": date_time,
                            "connection_name": self.connection.name,
                            "connection_status": self.connection.get_status_display(),
                            "action_url": action_url,
                            "backup_type": backup_type,
                            "endpoint_name": self.connection.location.name,
                            "endpoint_ip": self.connection.location.ip_address,
                            "endpoint_ipv6": self.connection.location.ip_address_v6,
                            "error_details": error_details,
                            "message": error.__class__.__name__,
                            "help_url": "https://support.backupsheep.com",
                            "sender_name": "BackupSheep - Notification Bot",
                        }

                    self.connection.account.create_log(data=data)

                    send_postmark_email.delay(
                        to_email,
                        error.email_template_id,
                        data
                    )
                elif error.__class__.__name__ == "SoftTimeLimitExceeded":
                    action_url = f"https://backupsheep.com/console/nodes/{self.id}/"
                    error_details = "Backup execution timeout. Backup must complete within 6" \
                                    " hours or else it will be terminated."
                    data = {
                        "node_type": self.get_type_display().lower(),
                        "node_status": self.get_status_display(),
                        "node_name": self.name,
                        "backup_time": date_time,
                        "connection_name": self.connection.name,
                        "connection_status": self.connection.get_status_display(),
                        "action_url": action_url,
                        "backup_type": backup_type,
                        "endpoint_name": self.connection.location.name,
                        "endpoint_ip": self.connection.location.ip_address,
                        "endpoint_ipv6": self.connection.location.ip_address_v6,
                        "error_details": error_details,
                        "message": error.__class__.__name__,
                        "help_url": "https://support.backupsheep.com",
                        "sender_name": "BackupSheep - Notification Bot",
                    }

                    self.connection.account.create_log(data=data)

                    send_postmark_email.delay(
                        to_email,
                        "error_during_backup",
                        data
                    )
                elif error.__class__.__name__ == "NodeBackupTimeoutError":
                    action_url = f"https://backupsheep.com/console/nodes/{self.id}/"
                    error_details = error.__str__()
                    data = {
                        "node_type": self.get_type_display().lower(),
                        "node_status": self.get_status_display(),
                        "node_name": self.name,
                        "backup_time": date_time,
                        "connection_name": self.connection.name,
                        "connection_status": self.connection.get_status_display(),
                        "action_url": action_url,
                        "backup_type": backup_type,
                        "endpoint_name": self.connection.location.name,
                        "endpoint_ip": self.connection.location.ip_address,
                        "endpoint_ipv6": self.connection.location.ip_address_v6,
                        "error_details": error_details,
                        "message": error.__class__.__name__,
                        "help_url": "https://support.backupsheep.com",
                        "sender_name": "BackupSheep - Notification Bot",
                    }

                    self.connection.account.create_log(data=data)

                    send_postmark_email.delay(
                        to_email,
                        "error_during_backup",
                        data
                    )
                elif (error.__class__.__name__ == "ConnectionValidationFailedError" or
                      error.__class__.__name__ == "IntegrationValidationError"):
                    if self.type == self.Type.CLOUD:
                        action_url = f"https://backupsheep.com/console/integration/{self.get_integration_alt_code().lower()}/?i_name={self.connection.name}"
                    elif self.type == self.Type.VOLUME:
                        action_url = f"https://backupsheep.com/console/integration/{self.get_integration_alt_code().lower()}/?i_name={self.connection.name}"
                    elif self.type == self.Type.DATABASE:
                        action_url = f"https://backupsheep.com/console/integration/database/?i_name={self.connection.name}"
                    elif self.type == self.Type.WEBSITE:
                        action_url = f"https://backupsheep.com/console/integration/website/?i_name={self.connection.name}"
                    else:
                        action_url = f"https://backupsheep.com/console/"

                    data = {
                            "node_type": self.get_type_display().lower(),
                            "node_status": self.get_status_display(),
                            "node_name": self.name,
                            "backup_time": date_time,
                            "connection_name": self.connection.name,
                            "connection_status": self.connection.get_status_display(),
                            "action_url": action_url,
                            "backup_type": backup_type,
                            "endpoint_name": self.connection.location.name,
                            "endpoint_location": self.connection.location.location,
                            "endpoint_ip": self.connection.location.ip_address,
                            "endpoint_ipv6": self.connection.location.ip_address_v6,
                            "error_details": error.__str__(),
                            "message": error.__class__.__name__,
                            "help_url": "https://support.backupsheep.com",
                            "sender_name": "BackupSheep - Notification Bot",
                    }

                    self.connection.account.create_log(data=data)

                    send_postmark_email.delay(
                        to_email,
                        "unable_to_start_backup",
                        data,
                    )
        except Exception as e:
            capture_exception(e)

    def notify_upload_fail(self, error, backup, storage):
        from apps._tasks.helper.tasks import send_postmark_email
        from datetime import datetime

        if backup.type == 1:
            backup_type = "On-Demand"
        elif backup.type == 2:
            backup_type = "Scheduled"
        else:
            backup_type = "n/a"

        try:
            if self.notify_on_fail and self.connection.account.notify_on_fail:
                membership = self.connection.account.memberships.get(primary=True)
                to_email = membership.member.user.email

                timezone = pytz.timezone(membership.member.timezone or "UTC")
                now = datetime.now()

                date_time = now.astimezone(timezone).strftime("%b %d %Y - %I:%M%p %Z")

                action_url = f"https://backupsheep.com/console/nodes/{self.id}/"

                data = {
                    "node_type": self.get_type_display().lower(),
                    "node_status": self.get_status_display(),
                    "node_name": self.name,
                    "backup_time": date_time,
                    "storage_type": storage.type.name,
                    "storage_name": storage.name,
                    "connection_name": self.connection.name,
                    "connection_status": self.connection.get_status_display(),
                    "action_url": action_url,
                    "backup_type": backup_type,
                    "endpoint_name": self.connection.location.name,
                    "endpoint_location": self.connection.location.location,
                    "endpoint_ip": self.connection.location.ip_address,
                    "endpoint_ipv6": self.connection.location.ip_address_v6,
                    "error_details": error.__str__(),
                    "message": "upload_fail",
                    "help_url": "https://support.backupsheep.com",
                    "sender_name": "BackupSheep - Notification Bot",
                }

                self.connection.account.create_log(data=data)

                send_postmark_email.delay(
                    to_email,
                    "unable_to_upload_backup",
                    data,
                )
        except Exception as e:
            capture_exception(e)

    def notify_backup_success(self, backup):
        from apps._tasks.helper.tasks import send_postmark_email

        try:
            if self.notify_on_success and self.connection.account.notify_on_success:
                member = self.connection.account.get_primary_member()
                to_email = member.user.email

                timezone = pytz.timezone(member.timezone or "UTC")
                date_time = backup.modified.astimezone(timezone).strftime(
                    "%b %d %Y - %I:%M%p %Z"
                )

                time_delta = backup.created - backup.modified

                if backup.type == 1:
                    backup_type = "On-Demand"
                elif backup.type == 2:
                    backup_type = "Scheduled"
                else:
                    backup_type = "n/a"

                node_type_object = getattr(self, self.connection.integration.code)

                action_url = f"https://backupsheep.com/console/nodes/{self.id}/"

                # if self.type == self.Type.CLOUD:
                #     action_url = f"https://backupsheep.com/console/clouds/{self.get_integration_alt_code().lower()}/{node_type_object.id}/"
                # elif self.type == self.Type.VOLUME:
                #     action_url = f"https://backupsheep.com/console/volumes/{self.get_integration_alt_code().lower()}/{node_type_object.id}/"
                # elif self.type == self.Type.DATABASE:
                #     action_url = f"https://backupsheep.com/console/databases/{self.get_integration_alt_code().lower()}/{node_type_object.id}/"
                # elif self.type == self.Type.WEBSITE:
                #     action_url = f"https://backupsheep.com/console/websites/files_n_folders/{node_type_object.id}/"
                # else:
                #     action_url = f"https://backupsheep.com/console/"

                data = {
                    "message": f"Backup successful for node {self.name}."
                               f" Backup Name: {backup.uuid_str}."
                               f" Node url: {action_url}",
                    "node_type": self.get_type_display().lower(),
                    "node_status": self.get_status_display(),
                    "node_name": self.name,
                    "backup_time": date_time,
                    "backup_size": backup.size_display(),
                    "connection_name": self.connection.name,
                    "connection_status": self.connection.get_status_display(),
                    "action_url": action_url,
                    "backup_name": backup.uuid_str,
                    "backup_type": backup_type,
                    "backup_duration": humanize.precisedelta(time_delta),
                    "endpoint_name": self.connection.location.name,
                    "endpoint_ip": self.connection.location.ip_address,
                    "endpoint_ipv6": self.connection.location.ip_address_v6,
                    "help_url": "https://support.backupsheep.com",
                    "sender_name": "BackupSheep - Notification Bot",
                }

                self.connection.account.create_log(data=data)

                send_postmark_email.delay(
                    to_email,
                    "backup_is_complete",
                    data,
                )
        except Exception as e:
            capture_exception(e)

# class CoreStorageUsage(TimeStampedModel):
#     account = models.ForeignKey(CoreAccount, related_name='storage_usage', on_delete=models.PROTECT)
#
#     size = models.BigIntegerField(null=True)
#
#     created = models.BigIntegerField()
#
#     class Meta:
#         db_table = 'core_storage_usage'
#
#     def save(self, *args, **kwargs):
#         """ On save, update timestamps """
#         if not self.id:
#             self.created = int(time.time())
#         self.modified = int(time.time())
#
#         return super(CoreStorageUsage, self).save(*args, **kwargs)
