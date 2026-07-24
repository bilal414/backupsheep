import datetime
import json
import humanfriendly
import pytz
import requests
from celery import chord
from django.conf import settings
from django.db import models, transaction
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
                        elif result.status_code == 422:
                            raise NodeBackupFailedError(
                                self.node,
                                backup.uuid_str, backup.attempt_no, backup.type,
                                "Droplet is locked by another action. We will try again shortly.",
                            )
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

    def restore_snapshot(self, backup, restore):
        client = self.node.connection.auth_digitalocean.get_client()
        params = restore.params or {}

        if self.node.type == CoreNode.Type.CLOUD:
            size = params.get("size")
            if not size:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/droplets/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    size = result.json()["droplet"]["size_slug"]
                else:
                    raise Exception(
                        f"Unable to determine source droplet size. API call returned with status {result.status_code}"
                    )
            droplet_data = {
                "name": restore.name,
                "size": size,
                "image": int(backup.unique_id),
            }
            if params.get("region"):
                droplet_data["region"] = params.get("region")
            if params.get("ssh_keys"):
                droplet_data["ssh_keys"] = params.get("ssh_keys")
            result = requests.post(
                f"{settings.DIGITALOCEAN_API}/v2/droplets",
                headers=client,
                json=droplet_data,
                verify=True,
            )
            if result.status_code == 202:
                droplet = result.json()["droplet"]
                restore.resource_id = droplet["id"]
                restore.save()
            else:
                raise Exception(
                    f"API call returned with status {result.status_code}: {get_error(result.text)}"
                )

        elif self.node.type == CoreNode.Type.VOLUME:
            region = params.get("region")
            if not region:
                result = requests.get(
                    f"{settings.DIGITALOCEAN_API}/v2/volumes/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    region = result.json()["volume"]["region"]["slug"]
                else:
                    raise Exception(
                        f"Unable to determine source volume region. API call returned with status {result.status_code}"
                    )
            volume_data = {
                "name": restore.name,
                "region": region,
                "snapshot_id": backup.unique_id,
            }
            result = requests.post(
                f"{settings.DIGITALOCEAN_API}/v2/volumes",
                headers=client,
                json=volume_data,
                verify=True,
            )
            if result.status_code == 201:
                volume = result.json()["volume"]
                restore.resource_id = volume["id"]
                restore.save()
            else:
                raise Exception(
                    f"API call returned with status {result.status_code}: {get_error(result.text)}"
                )

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_digitalocean.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/droplets/{restore.resource_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                droplet = result.json()["droplet"]
                if droplet.get("status") == "active":
                    return CoreCloudRestore.Status.COMPLETE
            return CoreCloudRestore.Status.IN_PROGRESS

        elif self.node.type == CoreNode.Type.VOLUME:
            result = requests.get(
                f"{settings.DIGITALOCEAN_API}/v2/volumes/{restore.resource_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200 and result.json().get("volume", {}).get("id"):
                return CoreCloudRestore.Status.COMPLETE
            return CoreCloudRestore.Status.IN_PROGRESS


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

    def restore_snapshot(self, backup, restore):
        try:
            client = self.node.connection.auth_hetzner.get_client()
            params = restore.params or {}

            server_data = {
                "name": restore.name,
                "image": int(backup.unique_id),
            }

            server_type = params.get("server_type")
            if not server_type:
                # Fall back to the source server's server type
                result = requests.get(
                    f"{settings.HETZNER_API}/v1/servers/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    server_type = result.json()["server"]["server_type"]["name"]
                else:
                    raise Exception(
                        f"Unable to determine server type from source server. "
                        f"API status code was: {result.status_code}"
                    )
            server_data["server_type"] = server_type

            if params.get("location"):
                server_data["location"] = params.get("location")
            if params.get("ssh_keys"):
                server_data["ssh_keys"] = params.get("ssh_keys")
            if params.get("labels"):
                server_data["labels"] = params.get("labels")

            result = requests.post(
                f"{settings.HETZNER_API}/v1/servers",
                data=json.dumps(server_data),
                headers=client,
                verify=True,
            )
            if result.status_code == 201:
                server = result.json()["server"]
                action = result.json()["action"]
                restore.resource_id = server["id"]
                params["action_id"] = action["id"]
                restore.params = params
                restore.save()
            elif result.status_code == 429:
                raise Exception("API rate limit exceeded. We will try again shortly.")
            else:
                raise Exception(f"API status code was: {result.status_code}")
        except Exception as e:
            raise Exception(f"Hetzner restore failed: {get_error(e)}")

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_hetzner.get_client()
        result = requests.get(
            f"{settings.HETZNER_API}/v1/servers/{restore.resource_id}",
            headers=client,
            verify=True,
        )
        if result.status_code == 200:
            server = result.json()["server"]
            if server.get("status") == "running":
                return CoreCloudRestore.Status.COMPLETE
        # Hetzner servers have no definitive error state; anything else
        # (initializing, non-200 response) is treated as still in progress
        return CoreCloudRestore.Status.IN_PROGRESS


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

    def restore_snapshot(self, backup, restore):
        client = self.node.connection.auth_upcloud.get_client()

        if self.node.type == CoreNode.Type.VOLUME:
            params = restore.params or {}
            zone = params.get("zone")
            tier = params.get("tier")
            if not zone:
                # Fall back to the zone of the backup storage
                result = requests.get(
                    f"{settings.UPCLOUD_API}/storage/{backup.unique_id}",
                    auth=client,
                    verify=True,
                    headers={"content-type": "application/json"}
                )
                if result.status_code == 200:
                    zone = result.json()["storage"]["zone"]
                else:
                    raise Exception(
                        f"Unable to fetch backup storage details. "
                        f"API call returned with status {result.status_code}"
                    )
            # Restore clones the backup storage into a NEW normal storage (non-destructive)
            storage_data = {"storage": {"zone": zone, "title": restore.name}}
            if tier:
                storage_data["storage"]["tier"] = tier
            result = requests.post(
                f"{settings.UPCLOUD_API}/storage/{backup.unique_id}/clone",
                data=json.dumps(storage_data),
                auth=client,
                verify=True,
                headers={"content-type": "application/json"}
            )
            if result.status_code == 201:
                storage = result.json()["storage"]
                restore.resource_id = storage["uuid"]
                params["zone"] = storage.get("zone", zone)
                restore.params = params
                restore.save()
            else:
                try:
                    error_message = result.json()["error"]["error_message"]
                except Exception:
                    error_message = f"API call returned with status {result.status_code}"
                raise Exception(f"Unable to clone backup storage: {error_message}")
        else:
            raise Exception("Snapshot restore is only supported for UpCloud volumes")

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_upcloud.get_client()
        result = requests.get(
            f"{settings.UPCLOUD_API}/storage/{restore.resource_id}",
            auth=client,
            verify=True,
            headers={"content-type": "application/json"}
        )
        if result.status_code == 200:
            state = result.json()["storage"]["state"]
            if state == "online":
                return CoreCloudRestore.Status.COMPLETE
            elif state == "error":
                return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


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
                # This unique_id will be updated in poll_status() with actual ID from OVH
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

    def restore_snapshot(self, backup, restore):
        import math

        from apps._tasks.exceptions import RestoreCreateError

        client = self.node.connection.auth_ovh_ca.get_client()
        params = restore.params or {}

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                flavor_id = params.get("flavor_id")
                region = params.get("region")
                # Fall back to the source instance when options are not supplied;
                # the snapshot can only be restored in the region it was taken in
                if not flavor_id or not region:
                    ovh_instance = client.get(
                        f"/cloud/project/{self.project_id}/instance/{self.unique_id}"
                    )
                    flavor_id = flavor_id or ovh_instance.get("flavorId")
                    region = region or ovh_instance.get("region")
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/instance",
                    flavorId=flavor_id,
                    name=restore.name,
                    region=region,
                    imageId=backup.unique_id,
                )
                restore.resource_id = ovh_response["id"]
                restore.save()
            except InvalidCredential:
                raise RestoreCreateError(
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise RestoreCreateError(message=get_error(e))
            except Exception as e:
                raise RestoreCreateError(message=get_error(e))
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                region = params.get("region")
                size = params.get("size")
                volume_type = params.get("type")
                # Fall back to the source volume when options are not supplied
                if not region or not size or not volume_type:
                    ovh_volume = client.get(
                        f"/cloud/project/{self.project_id}/volume/{self.unique_id}"
                    )
                    region = region or ovh_volume.get("region")
                    size = size or ovh_volume.get("size")
                    volume_type = volume_type or ovh_volume.get("type")
                # The new volume must be at least the size of the snapshot
                if backup.size_gigabytes:
                    size = max(int(size), math.ceil(backup.size_gigabytes))
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/volume",
                    region=region,
                    size=size,
                    type=volume_type,
                    snapshotId=backup.unique_id,
                    name=restore.name,
                )
                restore.resource_id = ovh_response["id"]
                restore.save()
            except InvalidCredential:
                raise RestoreCreateError(
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise RestoreCreateError(message=get_error(e))
            except Exception as e:
                raise RestoreCreateError(message=get_error(e))

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_ovh_ca.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            ovh_instance = client.get(
                f"/cloud/project/{self.project_id}/instance/{restore.resource_id}"
            )
            status = ovh_instance.get("status")
            if status == "ACTIVE":
                return CoreCloudRestore.Status.COMPLETE
            elif status == "ERROR":
                return CoreCloudRestore.Status.FAILED
        elif self.node.type == CoreNode.Type.VOLUME:
            ovh_volume = client.get(
                f"/cloud/project/{self.project_id}/volume/{restore.resource_id}"
            )
            status = ovh_volume.get("status")
            if status == "available":
                return CoreCloudRestore.Status.COMPLETE
            elif status == "error":
                return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


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
                # This unique_id will be updated in poll_status() with actual ID from OVH
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

    def restore_snapshot(self, backup, restore):
        import math

        from apps._tasks.exceptions import RestoreCreateError

        client = self.node.connection.auth_ovh_eu.get_client()
        params = restore.params or {}

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                flavor_id = params.get("flavor_id")
                region = params.get("region")
                # Fall back to the source instance when options are not supplied;
                # the snapshot can only be restored in the region it was taken in
                if not flavor_id or not region:
                    ovh_instance = client.get(
                        f"/cloud/project/{self.project_id}/instance/{self.unique_id}"
                    )
                    flavor_id = flavor_id or ovh_instance.get("flavorId")
                    region = region or ovh_instance.get("region")
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/instance",
                    flavorId=flavor_id,
                    name=restore.name,
                    region=region,
                    imageId=backup.unique_id,
                )
                restore.resource_id = ovh_response["id"]
                restore.save()
            except InvalidCredential:
                raise RestoreCreateError(
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise RestoreCreateError(message=get_error(e))
            except Exception as e:
                raise RestoreCreateError(message=get_error(e))
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                region = params.get("region")
                size = params.get("size")
                volume_type = params.get("type")
                # Fall back to the source volume when options are not supplied
                if not region or not size or not volume_type:
                    ovh_volume = client.get(
                        f"/cloud/project/{self.project_id}/volume/{self.unique_id}"
                    )
                    region = region or ovh_volume.get("region")
                    size = size or ovh_volume.get("size")
                    volume_type = volume_type or ovh_volume.get("type")
                # The new volume must be at least the size of the snapshot
                if backup.size_gigabytes:
                    size = max(int(size), math.ceil(backup.size_gigabytes))
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/volume",
                    region=region,
                    size=size,
                    type=volume_type,
                    snapshotId=backup.unique_id,
                    name=restore.name,
                )
                restore.resource_id = ovh_response["id"]
                restore.save()
            except InvalidCredential:
                raise RestoreCreateError(
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise RestoreCreateError(message=get_error(e))
            except Exception as e:
                raise RestoreCreateError(message=get_error(e))

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_ovh_eu.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            ovh_instance = client.get(
                f"/cloud/project/{self.project_id}/instance/{restore.resource_id}"
            )
            status = ovh_instance.get("status")
            if status == "ACTIVE":
                return CoreCloudRestore.Status.COMPLETE
            elif status == "ERROR":
                return CoreCloudRestore.Status.FAILED
        elif self.node.type == CoreNode.Type.VOLUME:
            ovh_volume = client.get(
                f"/cloud/project/{self.project_id}/volume/{restore.resource_id}"
            )
            status = ovh_volume.get("status")
            if status == "available":
                return CoreCloudRestore.Status.COMPLETE
            elif status == "error":
                return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


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
                # This unique_id will be updated in poll_status() with actual ID from OVH
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

    def restore_snapshot(self, backup, restore):
        import math

        from apps._tasks.exceptions import RestoreCreateError

        client = self.node.connection.auth_ovh_us.get_client()
        params = restore.params or {}

        if self.node.type == CoreNode.Type.CLOUD:
            try:
                flavor_id = params.get("flavor_id")
                region = params.get("region")
                # Fall back to the source instance when options are not supplied;
                # the snapshot can only be restored in the region it was taken in
                if not flavor_id or not region:
                    ovh_instance = client.get(
                        f"/cloud/project/{self.project_id}/instance/{self.unique_id}"
                    )
                    flavor_id = flavor_id or ovh_instance.get("flavorId")
                    region = region or ovh_instance.get("region")
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/instance",
                    flavorId=flavor_id,
                    name=restore.name,
                    region=region,
                    imageId=backup.unique_id,
                )
                restore.resource_id = ovh_response["id"]
                restore.save()
            except InvalidCredential:
                raise RestoreCreateError(
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise RestoreCreateError(message=get_error(e))
            except Exception as e:
                raise RestoreCreateError(message=get_error(e))
        elif self.node.type == CoreNode.Type.VOLUME:
            try:
                region = params.get("region")
                size = params.get("size")
                volume_type = params.get("type")
                # Fall back to the source volume when options are not supplied
                if not region or not size or not volume_type:
                    ovh_volume = client.get(
                        f"/cloud/project/{self.project_id}/volume/{self.unique_id}"
                    )
                    region = region or ovh_volume.get("region")
                    size = size or ovh_volume.get("size")
                    volume_type = volume_type or ovh_volume.get("type")
                # The new volume must be at least the size of the snapshot
                if backup.size_gigabytes:
                    size = max(int(size), math.ceil(backup.size_gigabytes))
                ovh_response = client.post(
                    f"/cloud/project/{self.project_id}/volume",
                    region=region,
                    size=size,
                    type=volume_type,
                    snapshotId=backup.unique_id,
                    name=restore.name,
                )
                restore.resource_id = ovh_response["id"]
                restore.save()
            except InvalidCredential:
                raise RestoreCreateError(
                    message="We are unable to connect to your OVH account. "
                            "Please reconnect your account to refresh authentication token.",
                )
            except ResourceConflictError as e:
                raise RestoreCreateError(message=get_error(e))
            except Exception as e:
                raise RestoreCreateError(message=get_error(e))

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_ovh_us.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            ovh_instance = client.get(
                f"/cloud/project/{self.project_id}/instance/{restore.resource_id}"
            )
            status = ovh_instance.get("status")
            if status == "ACTIVE":
                return CoreCloudRestore.Status.COMPLETE
            elif status == "ERROR":
                return CoreCloudRestore.Status.FAILED
        elif self.node.type == CoreNode.Type.VOLUME:
            ovh_volume = client.get(
                f"/cloud/project/{self.project_id}/volume/{restore.resource_id}"
            )
            status = ovh_volume.get("status")
            if status == "available":
                return CoreCloudRestore.Status.COMPLETE
            elif status == "error":
                return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


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

    def restore_snapshot(self, backup, restore):
        client = self.node.connection.auth_aws.get_client()
        params = restore.params or {}

        if self.node.type == CoreNode.Type.CLOUD:
            instance_type = params.get("instance_type")
            if not instance_type:
                response = client.describe_instances(
                    InstanceIds=[self.unique_id],
                )
                if response.get("Reservations"):
                    instance = response.get("Reservations")[0]["Instances"][0]
                    instance_type = instance.get("InstanceType")
            if not instance_type:
                raise Exception(
                    "Unable to determine instance type. Please provide instance_type in params."
                )
            instance_data = {
                "ImageId": backup.unique_id,
                "MinCount": 1,
                "MaxCount": 1,
                "InstanceType": instance_type,
                "TagSpecifications": [
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": restore.name}],
                    }
                ],
            }
            if params.get("key_name"):
                instance_data["KeyName"] = params.get("key_name")
            if params.get("subnet_id"):
                instance_data["SubnetId"] = params.get("subnet_id")
            if params.get("security_group_ids"):
                instance_data["SecurityGroupIds"] = params.get("security_group_ids")
            response = client.run_instances(**instance_data)
            if not response.get("Instances"):
                raise Exception("InstanceId not present in run_instances response.")
            restore.resource_id = response.get("Instances")[0]["InstanceId"]
            restore.save()

        elif self.node.type == CoreNode.Type.VOLUME:
            availability_zone = params.get("availability_zone")
            if not availability_zone:
                response = client.describe_volumes(
                    VolumeIds=[self.unique_id],
                )
                if response.get("Volumes"):
                    availability_zone = response.get("Volumes")[0].get("AvailabilityZone")
            if not availability_zone:
                raise Exception(
                    "Unable to determine availability zone. Please provide availability_zone in params."
                )
            response = client.create_volume(
                AvailabilityZone=availability_zone,
                SnapshotId=backup.unique_id,
            )
            if not response.get("VolumeId"):
                raise Exception("VolumeId not present in create_volume response.")
            restore.resource_id = response.get("VolumeId")
            restore.save()

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_aws.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            response = client.describe_instances(
                InstanceIds=[restore.resource_id],
            )
            if response.get("Reservations"):
                instance = response.get("Reservations")[0]["Instances"][0]
                state = instance.get("State", {}).get("Name")
                if state == "running":
                    return CoreCloudRestore.Status.COMPLETE
                elif state == "terminated" or state == "shutting-down":
                    return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS

        elif self.node.type == CoreNode.Type.VOLUME:
            response = client.describe_volumes(
                VolumeIds=[restore.resource_id],
            )
            if response.get("Volumes"):
                state = response.get("Volumes")[0].get("State")
                if state == "available":
                    return CoreCloudRestore.Status.COMPLETE
                elif state == "error":
                    return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS


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
                    diskName=self.unique_id,
                    diskSnapshotName=backup.uuid_str,
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

    def restore_snapshot(self, backup, restore):
        try:
            client = self.node.connection.auth_lightsail.get_client()
            params = restore.params or {}

            if self.node.type == CoreNode.Type.CLOUD:
                availability_zone = params.get("availability_zone")
                if not availability_zone:
                    response = client.get_instance_snapshot(
                        instanceSnapshotName=backup.unique_id
                    )
                    availability_zone = response.get("instanceSnapshot", {}).get("location", {}).get(
                        "availabilityZone")

                bundle_id = params.get("bundle_id")
                if not bundle_id:
                    response = client.get_instance(
                        instanceName=self.unique_id
                    )
                    bundle_id = response.get("instance", {}).get("bundleId")

                client.create_instances_from_snapshot(
                    instanceNames=[restore.name],
                    instanceSnapshotName=backup.unique_id,
                    availabilityZone=availability_zone,
                    bundleId=bundle_id,
                )
                restore.resource_id = restore.name
                restore.save()
            elif self.node.type == CoreNode.Type.VOLUME:
                availability_zone = params.get("availability_zone")
                if not availability_zone:
                    response = client.get_disk_snapshot(
                        diskSnapshotName=backup.unique_id
                    )
                    availability_zone = response.get("diskSnapshot", {}).get("location", {}).get("availabilityZone")

                client.create_disk_from_snapshot(
                    diskName=restore.name,
                    diskSnapshotName=backup.unique_id,
                    availabilityZone=availability_zone,
                    sizeInGb=int(backup.size_gigabytes),
                )
                restore.resource_id = restore.name
                restore.save()
        except Exception as e:
            raise Exception(get_error(e))

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_lightsail.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            response = client.get_instance(
                instanceName=restore.resource_id
            )
            instance = response.get("instance", {})
            state = instance.get("state", {}).get("name")
            if state == "running":
                return CoreCloudRestore.Status.COMPLETE
            return CoreCloudRestore.Status.IN_PROGRESS
        elif self.node.type == CoreNode.Type.VOLUME:
            response = client.get_disk(
                diskName=restore.resource_id
            )
            disk = response.get("disk", {})
            state = disk.get("state")
            if state == "available":
                return CoreCloudRestore.Status.COMPLETE
            elif state == "error":
                return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS


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

    def restore_snapshot(self, backup, restore):
        import re

        client = self.node.connection.auth_aws_rds.get_client()

        # RDS identifiers must be 1-63 chars, start with a letter, contain
        # only letters/digits/hyphens with no consecutive or trailing hyphens
        identifier = re.sub(r"[^a-zA-Z0-9-]", "-", restore.name)
        identifier = re.sub(r"-+", "-", identifier)
        identifier = re.sub(r"^[^a-zA-Z]+", "", identifier)
        identifier = identifier[:63].rstrip("-")
        if not identifier:
            raise Exception(
                f"Unable to build a valid RDS instance identifier from '{restore.name}'. "
                "The name must contain at least one letter."
            )

        request = {
            "DBInstanceIdentifier": identifier,
            "DBSnapshotIdentifier": backup.unique_id,
        }
        params = restore.params or {}
        if params.get("db_instance_class"):
            request["DBInstanceClass"] = params["db_instance_class"]
        if params.get("db_subnet_group_name"):
            request["DBSubnetGroupName"] = params["db_subnet_group_name"]
        if params.get("multi_az") is not None:
            request["MultiAZ"] = params["multi_az"]
        if params.get("publicly_accessible") is not None:
            request["PubliclyAccessible"] = params["publicly_accessible"]
        if params.get("storage_type"):
            request["StorageType"] = params["storage_type"]

        try:
            client.restore_db_instance_from_db_snapshot(**request)
        except ClientError as e:
            raise Exception(
                f"Unable to restore RDS snapshot {backup.unique_id}: {get_error(e)}"
            )

        restore.resource_id = identifier
        restore.save()

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_aws_rds.get_client()
        try:
            response = client.describe_db_instances(
                DBInstanceIdentifier=restore.resource_id
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "DBInstanceNotFound":
                # the new instance can take a moment to appear after restore starts
                return CoreCloudRestore.Status.IN_PROGRESS
            raise

        db_instance = response.get("DBInstances")[0]
        status = db_instance.get("DBInstanceStatus")

        if status == "available":
            return CoreCloudRestore.Status.COMPLETE
        elif status in ("failed", "incompatible-restore", "incompatible-network", "incompatible-parameters"):
            return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


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
                    json={"instance_id": self.unique_id, "description": self.node.name},
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
                        "API rate limit exceeded. We will try again shortly.",
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
            try:
                # Block storage snapshots are created under /v2/blocks/snapshots and
                # the API returns the snapshot object at top level (no wrapper key).
                result = requests.post(
                    f"{settings.VULTR_API}/v2/blocks/snapshots",
                    headers=client,
                    json={"block_id": self.unique_id, "description": backup.uuid_str},
                    verify=True,
                )
                if result.status_code == 201:
                    snapshot = result.json()
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
                        "API rate limit exceeded. We will try again shortly.",
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

    def restore_snapshot(self, backup, restore):
        client = self.node.connection.auth_vultr.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            params = restore.params or {}
            region = params.get("region")
            plan = params.get("plan")

            if not region or not plan:
                result = requests.get(
                    f"{settings.VULTR_API}/v2/instances/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    instance = result.json()["instance"]
                    region = region or instance["region"]
                    plan = plan or instance["plan"]
                else:
                    raise Exception(
                        f"Unable to get instance details. API call returned with status {result.status_code}"
                    )

            result = requests.post(
                f"{settings.VULTR_API}/v2/instances",
                headers=client,
                json={
                    "region": region,
                    "plan": plan,
                    "snapshot_id": backup.unique_id,
                    "label": restore.name,
                    "hostname": restore.name,
                },
                verify=True,
            )
            if result.status_code == 201:
                instance = result.json()["instance"]
                restore.resource_id = instance["id"]
                restore.save()
            elif result.status_code == 401:
                raise Exception(
                    "Unable to connect to your Vultr account. Please reconnect your account to refresh authentication token."
                )
            elif result.status_code == 429:
                raise Exception("API rate limit exceeded. Please try again shortly.")
            else:
                raise Exception(f"API call returned with status {result.status_code}")

        elif self.node.type == CoreNode.Type.VOLUME:
            params = restore.params or {}
            region = params.get("region")
            size_gb = params.get("size_gb")

            if not region or not size_gb:
                result = requests.get(
                    f"{settings.VULTR_API}/v2/blocks/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if result.status_code == 200:
                    block = result.json()["block"]
                    region = region or block["region"]
                    size_gb = size_gb or block["size_gb"]
                else:
                    raise Exception(
                        f"Unable to get block storage details. API call returned with status {result.status_code}"
                    )

            # Restoring a block snapshot creates a brand new volume via POST /v2/blocks
            # with snapshot_id set; region and size_gb are required alongside it.
            result = requests.post(
                f"{settings.VULTR_API}/v2/blocks",
                headers=client,
                json={
                    "region": region,
                    "size_gb": size_gb,
                    "snapshot_id": backup.unique_id,
                    "label": restore.name,
                },
                verify=True,
            )
            if result.status_code == 201:
                block = result.json()["block"]
                restore.resource_id = block["id"]
                restore.save()
            elif result.status_code == 401:
                raise Exception(
                    "Unable to connect to your Vultr account. Please reconnect your account to refresh authentication token."
                )
            elif result.status_code == 429:
                raise Exception("API rate limit exceeded. Please try again shortly.")
            else:
                raise Exception(f"API call returned with status {result.status_code}")

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore

        client = self.node.connection.auth_vultr.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            result = requests.get(
                f"{settings.VULTR_API}/v2/instances/{restore.resource_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                instance = result.json()["instance"]
                if instance["status"] == "active":
                    return CoreCloudRestore.Status.COMPLETE
                elif instance["status"] == "suspended":
                    return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS

        elif self.node.type == CoreNode.Type.VOLUME:
            result = requests.get(
                f"{settings.VULTR_API}/v2/blocks/{restore.resource_id}",
                headers=client,
                verify=True,
            )
            if result.status_code == 200:
                block = result.json()["block"]
                if block["status"] == "active":
                    return CoreCloudRestore.Status.COMPLETE
            return CoreCloudRestore.Status.IN_PROGRESS


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
        from oci.core.models import BootVolume, Volume

        node_ok = False

        if self.node.type == CoreNode.Type.VOLUME:
            config = self.node.connection.auth_oracle.get_client()
            block_storage_client = oci.core.BlockstorageClient(config)

            if self.metadata.get("_bs_vol_type") == "boot":
                request = block_storage_client.get_boot_volume(self.unique_id)
                if request.status == 200:
                    if (
                        request.data.id == self.unique_id
                        and request.data.lifecycle_state == BootVolume.LIFECYCLE_STATE_AVAILABLE
                    ):
                        node_ok = True
            elif self.metadata.get("_bs_vol_type") == "block":
                request = block_storage_client.get_volume(self.unique_id)
                if request.status == 200:
                    if (
                        request.data.id == self.unique_id
                        and request.data.lifecycle_state == Volume.LIFECYCLE_STATE_AVAILABLE
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

    def restore_snapshot(self, backup, restore):
        import oci
        from oci.core.models import (
            BootVolumeSourceFromBootVolumeBackupDetails,
            CreateBootVolumeDetails,
            CreateVolumeDetails,
        )

        if self.node.type == CoreNode.Type.VOLUME:
            try:
                config = self.node.connection.auth_oracle.get_client()
                block_storage_client = oci.core.BlockstorageClient(config)
                params = restore.params or {}

                if self.metadata.get("_bs_vol_type") == "boot":
                    compartment_id = params.get("compartment_id")
                    availability_domain = params.get("availability_domain")
                    if not compartment_id or not availability_domain:
                        source_volume = block_storage_client.get_boot_volume(self.unique_id).data
                        compartment_id = compartment_id or source_volume.compartment_id
                        availability_domain = availability_domain or source_volume.availability_domain

                    request = block_storage_client.create_boot_volume(
                        create_boot_volume_details=CreateBootVolumeDetails(
                            compartment_id=compartment_id,
                            availability_domain=availability_domain,
                            display_name=restore.name,
                            source_details=BootVolumeSourceFromBootVolumeBackupDetails(
                                id=backup.unique_id
                            ),
                        )
                    )
                    if request.status == 200:
                        restore.resource_id = request.data.id
                        restore.save()
                    else:
                        raise Exception(f"API call returned with status {request.status}")
                elif self.metadata.get("_bs_vol_type") == "block":
                    compartment_id = params.get("compartment_id")
                    availability_domain = params.get("availability_domain")
                    if not compartment_id or not availability_domain:
                        source_volume = block_storage_client.get_volume(self.unique_id).data
                        compartment_id = compartment_id or source_volume.compartment_id
                        availability_domain = availability_domain or source_volume.availability_domain

                    request = block_storage_client.create_volume(
                        create_volume_details=CreateVolumeDetails(
                            compartment_id=compartment_id,
                            availability_domain=availability_domain,
                            volume_backup_id=backup.unique_id,
                            display_name=restore.name,
                        )
                    )
                    if request.status == 200:
                        restore.resource_id = request.data.id
                        restore.save()
                    else:
                        raise Exception(f"API call returned with status {request.status}")
            except Exception as e:
                raise Exception(f"Unable to restore snapshot: {get_error(e)}")

    def check_restore(self, restore):
        from apps.console.backup.models import CoreCloudRestore
        import oci
        from oci.core.models import BootVolume, Volume

        config = self.node.connection.auth_oracle.get_client()
        block_storage_client = oci.core.BlockstorageClient(config)

        if self.metadata.get("_bs_vol_type") == "boot":
            request = block_storage_client.get_boot_volume(restore.resource_id)
            if request.status == 200:
                if request.data.lifecycle_state == BootVolume.LIFECYCLE_STATE_AVAILABLE:
                    return CoreCloudRestore.Status.COMPLETE
                elif request.data.lifecycle_state == BootVolume.LIFECYCLE_STATE_FAULTY:
                    return CoreCloudRestore.Status.FAILED
        elif self.metadata.get("_bs_vol_type") == "block":
            request = block_storage_client.get_volume(restore.resource_id)
            if request.status == 200:
                if request.data.lifecycle_state == Volume.LIFECYCLE_STATE_AVAILABLE:
                    return CoreCloudRestore.Status.COMPLETE
                elif request.data.lifecycle_state == Volume.LIFECYCLE_STATE_FAULTY:
                    return CoreCloudRestore.Status.FAILED
        return CoreCloudRestore.Status.IN_PROGRESS


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

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.node.google_cloud.project_id}"
                f"/zones/{self.node.google_cloud.zone}"
                f"/instances/{self.node.google_cloud.unique_id}"
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

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.node.google_cloud.project_id}"
                f"/zones/{self.node.google_cloud.zone}"
                f"/disks/{self.node.google_cloud.unique_id}"
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

                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/zones/{self.node.google_cloud.zone}"
                    f"/instances/{self.node.google_cloud.unique_id}"
                )
                if result.status_code == 200:
                    instance = result.json()

                    result = client.post(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.node.google_cloud.project_id}"
                        f"/global/machineImages",
                        json={
                            "name": backup.uuid_str,
                            "sourceInstance": f"projects/{self.node.google_cloud.project_id}"
                                              f"/zones/{self.node.google_cloud.zone}"
                                              f"/instances/{instance['name']}"
                        },
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
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.node.google_cloud.project_id}"
                    f"/zones/{self.node.google_cloud.zone}"
                    f"/disks/{self.node.google_cloud.unique_id}"
                )
                if result.status_code == 200:
                    disk = result.json()
                    result = client.post(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.node.google_cloud.project_id}"
                        f"/zones/{self.node.google_cloud.zone}"
                        f"/disks/{disk['name']}/createSnapshot",
                        json={"name": backup.uuid_str},
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
                            f"Unable to create disk snapshot. API call returned with status {result.status_code}",
                        )
                else:
                    raise NodeBackupFailedError(
                        self.node,
                        backup.uuid_str,
                        backup.attempt_no,
                        backup.type,
                        f"Unable to get disk details. API call returned with status {result.status_code}",
                    )
            except Exception as e:
                raise NodeBackupFailedError(
                    self.node, backup.uuid_str, backup.attempt_no, backup.type, message=get_error(e)
                )

    def restore_snapshot(self, backup, restore):
        """Initiate a restore of a snapshot to a NEW instance/disk (never in-place).
        Sets restore.resource_id on success and saves; raises with a clear message on failure."""
        params = restore.params or {}
        client = self.node.connection.auth_google_cloud.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            zone = params.get("zone")
            if not zone:
                # Default to the source instance's zone (last segment of its zone URL);
                # fall back to the node's configured zone if the instance no longer exists.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/instances/{self.unique_id}"
                )
                if result.status_code == 200:
                    zone = result.json()["zone"].split("/")[-1]
                else:
                    zone = self.zone

            result = client.post(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/instances",
                json={
                    "name": restore.name,
                    # Machine images are addressed by name (= backup.uuid_str);
                    # backup.unique_id holds the id of the insert Operation.
                    "sourceMachineImage": f"global/machineImages/{backup.uuid_str}",
                },
            )
            if result.status_code == 200:
                operation = result.json()
                restore.resource_id = restore.name
                params["zone"] = zone
                params["operation_id"] = operation.get("name")
                restore.params = params
                restore.save()
            else:
                raise Exception(
                    f"Unable to restore instance from machine image. API call returned with status {result.status_code}"
                )
        elif self.node.type == CoreNode.Type.VOLUME:
            import math

            zone = params.get("zone")
            size_gb = params.get("sizeGb")
            if not zone or not size_gb:
                # Default to the source disk's zone and size.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/disks/{self.unique_id}"
                )
                if result.status_code == 200:
                    disk = result.json()
                    if not zone:
                        zone = disk["zone"].split("/")[-1]
                    if not size_gb:
                        size_gb = disk.get("sizeGb")
            if not zone:
                zone = self.zone
            if not size_gb and backup.size_gigabytes:
                size_gb = math.ceil(backup.size_gigabytes)
            if not size_gb:
                raise Exception(
                    "Unable to determine the restored disk size. Provide sizeGb in the restore params."
                )

            result = client.post(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/disks",
                json={
                    "name": restore.name,
                    # Snapshots are addressed by name (= backup.uuid_str);
                    # backup.unique_id holds the id of the insert Operation.
                    "sourceSnapshot": f"global/snapshots/{backup.uuid_str}",
                    "sizeGb": str(size_gb),
                    "type": f"zones/{zone}/diskTypes/pd-balanced",
                },
            )
            if result.status_code == 200:
                operation = result.json()
                restore.resource_id = restore.name
                params["zone"] = zone
                params["operation_id"] = operation.get("name")
                restore.params = params
                restore.save()
            else:
                raise Exception(
                    f"Unable to restore disk from snapshot. API call returned with status {result.status_code}"
                )

    def check_restore(self, restore):
        """Single non-blocking restore status check: COMPLETE / FAILED / IN_PROGRESS."""
        from apps.console.backup.models import CoreCloudRestore

        params = restore.params or {}
        zone = params.get("zone")
        client = self.node.connection.auth_google_cloud.get_client()

        if self.node.type == CoreNode.Type.CLOUD:
            if not zone:
                # Fall back to the source instance's zone, then the node's configured zone.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/instances/{self.unique_id}"
                )
                if result.status_code == 200:
                    zone = result.json()["zone"].split("/")[-1]
                else:
                    zone = self.zone

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/instances/{restore.resource_id or restore.name}"
            )
            if result.status_code == 200:
                instance = result.json()
                if instance.get("status") == "RUNNING":
                    return CoreCloudRestore.Status.COMPLETE
            return CoreCloudRestore.Status.IN_PROGRESS
        elif self.node.type == CoreNode.Type.VOLUME:
            if not zone:
                # Fall back to the source disk's zone, then the node's configured zone.
                result = client.get(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.project_id}"
                    f"/zones/{self.zone}"
                    f"/disks/{self.unique_id}"
                )
                if result.status_code == 200:
                    zone = result.json()["zone"].split("/")[-1]
                else:
                    zone = self.zone

            result = client.get(
                f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                f"/projects/{self.project_id}"
                f"/zones/{zone}"
                f"/disks/{restore.resource_id or restore.name}"
            )
            if result.status_code == 200:
                disk = result.json()
                if disk.get("status") == "READY":
                    return CoreCloudRestore.Status.COMPLETE
                elif disk.get("status") == "FAILED":
                    return CoreCloudRestore.Status.FAILED
            return CoreCloudRestore.Status.IN_PROGRESS


class CoreWebsite(TimeStampedModel):
    class BackupType(models.IntegerChoices):
        FULL = 1, "Full"
        FULL_V2 = 4, "Full (Server-Side Tar)"

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
    incremental = models.BooleanField(default=False)
    tar_temp_backup_dir = models.TextField(null=True, blank=True)
    tar_exclude_vcs_ignores = models.BooleanField(default=False, null=True)
    tar_exclude_vcs = models.BooleanField(default=False, null=True)
    tar_exclude_backups = models.BooleanField(default=False, null=True)
    tar_exclude_caches = models.BooleanField(default=False, null=True)

    class Meta:
        db_table = "core_website"

    def create_snapshot(self, backup):
        from apps._tasks.integration.backup.website import snapshot_website
        from apps._tasks.integration.storage.tasks import storage_upload, finalize_backup
        from ..backup.models import CoreWebsiteBackupStoragePoints

        backup.status = UtilBackup.Status.DOWNLOAD_IN_PROGRESS
        backup.save()

        """
        Run a website backup. snapshot_website dispatches internally: incremental
        mode mirrors into the per-node persistent cache, key-based FULL_V2 sources
        use the server-side tar transport, and everything else is a full lftp
        re-download.
        """
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
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_website_backup.id
                    ).set()
                )

            if storage_upload_task_list:
                backup.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
                backup.save()
                chord(
                    storage_upload_task_list,
                    finalize_backup.si(self.node.id, backup.id),
                ).apply_async()
            else:
                # No storage destination accepted the backup; finalize_backup will
                # mark it failed and clean up rather than silently discarding it.
                finalize_backup.apply_async(args=[self.node.id, backup.id])
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

    def validate(self):
        """A database node is valid when its connection can still reach the server."""
        try:
            self.node.connection.auth_database.check_connection(check_errors=True)
            return True
        except Exception:
            return False

    def create_snapshot(self, backup):
        from ..connection.models import CoreAuthDatabase
        from apps._tasks.integration.storage.tasks import storage_upload, finalize_backup
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
        elif (
                self.node.connection.auth_database.type
                == CoreAuthDatabase.DatabaseType.MARIADB
        ):
            snapshot_mariadb(backup)
        elif (
                self.node.connection.auth_database.type
                == CoreAuthDatabase.DatabaseType.POSTGRESQL
        ):
            snapshot_postgresql(backup)
        else:
            # Unknown/unsupported engine type: fail loudly instead of silently
            # uploading an empty zip.
            raise NodeBackupFailedError(
                self.node,
                backup.uuid_str,
                backup.attempt_no,
                backup.type,
                message=f"Unsupported database engine type: "
                        f"{self.node.connection.auth_database.type}",
            )

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
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_database_backup.id
                    ).set()
                )

            if storage_upload_task_list:
                backup.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
                backup.save()
                chord(
                    storage_upload_task_list,
                    finalize_backup.si(self.node.id, backup.id),
                ).apply_async()
            else:
                # No storage destination accepted the backup; finalize_backup will
                # mark it failed and clean up rather than silently discarding it.
                finalize_backup.apply_async(args=[self.node.id, backup.id])
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
        from apps._tasks.integration.storage.tasks import storage_upload, finalize_backup
        from ..backup.models import CoreWordPressBackupStoragePoints

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
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_wordpress_backup.id
                    ).set()
                )

            if storage_upload_task_list:
                backup.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
                backup.save()
                chord(
                    storage_upload_task_list,
                    finalize_backup.si(self.node.id, backup.id),
                ).apply_async()
            else:
                # No storage destination accepted the backup; finalize_backup will
                # mark it failed and clean up rather than silently discarding it.
                finalize_backup.apply_async(args=[self.node.id, backup.id])
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
        from apps._tasks.integration.storage.tasks import storage_upload, finalize_backup
        from ..backup.models import CoreBasecampBackupStoragePoints

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
                storage_upload_task_list.append(
                    storage_upload.s(
                        self.node.id, backup.id, stored_basecamp_backup.id
                    ).set()
                )

            if storage_upload_task_list:
                backup.status = UtilBackup.Status.UPLOAD_IN_PROGRESS
                backup.save()
                chord(
                    storage_upload_task_list,
                    finalize_backup.si(self.node.id, backup.id),
                ).apply_async()
            else:
                # No storage destination accepted the backup; finalize_backup will
                # mark it failed and clean up rather than silently discarding it.
                finalize_backup.apply_async(args=[self.node.id, backup.id])
        except Exception as e:
            capture_exception(e)
        return backup


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

    def _periodic_schedule(self):
        """Return (PeriodicTask field name, schedule object) for this schedule's type."""
        from django_celery_beat.models import (
            CrontabSchedule,
            IntervalSchedule,
            ClockedSchedule,
        )

        if self.type == CoreSchedule.Type.CRON:
            crontab, _ = CrontabSchedule.objects.get_or_create(
                minute=self.minute or "*",
                hour=self.hour or "*",
                day_of_week=self.day_of_week or "*",
                day_of_month=self.day_of_month or "*",
                month_of_year=self.month_of_year or "*",
                timezone=self.timezone or "UTC",
            )
            return "crontab", crontab
        elif self.type == CoreSchedule.Type.RATE:
            interval, _ = IntervalSchedule.objects.get_or_create(
                every=self.rate_value,
                period=self.rate_unit,
            )
            return "interval", interval
        elif self.type == CoreSchedule.Type.ONETIME:
            clocked, _ = ClockedSchedule.objects.get_or_create(clocked_time=self.at_datetime)
            return "clocked", clocked
        return None, None

    def schedule_create(self):
        """Create the local django-celery-beat PeriodicTask that drives this schedule."""
        field, schedule_obj = self._periodic_schedule()
        if not field:
            return
        periodic_task = PeriodicTask.objects.create(
            name=self.uuid_str,
            task="run_scheduled_backup",
            args=json.dumps([self.id]),
            enabled=(self.status == CoreSchedule.Status.ACTIVE),
            one_off=(self.type == CoreSchedule.Type.ONETIME),
            **{field: schedule_obj},
        )
        self.celery_periodic_task = periodic_task
        self.save(update_fields=["celery_periodic_task"])

    def schedule_update(self):
        """Update (or create) the PeriodicTask to match this schedule."""
        if not self.celery_periodic_task:
            return self.schedule_create()
        field, schedule_obj = self._periodic_schedule()
        if not field:
            return
        periodic_task = self.celery_periodic_task
        periodic_task.crontab = None
        periodic_task.interval = None
        periodic_task.clocked = None
        setattr(periodic_task, field, schedule_obj)
        periodic_task.one_off = self.type == CoreSchedule.Type.ONETIME
        periodic_task.enabled = self.status == CoreSchedule.Status.ACTIVE
        periodic_task.args = json.dumps([self.id])
        periodic_task.save()

    def schedule_delete(self):
        """Remove the local PeriodicTask for this schedule."""
        if self.celery_periodic_task:
            self.celery_periodic_task.delete()
            self.celery_periodic_task = None


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

    def get_cloud_backup(self, backup_id):
        """Return this node's provider-specific backup by id (used by the async
        poll_cloud_backup task to re-load a snapshot it is waiting on)."""
        node_type_object = getattr(self, self.connection.integration.code)
        return node_type_object.backups.filter(id=backup_id).first()

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
        """
        Duplicate-backup guard: lock this node's row so concurrent backup tasks for
        the same node serialize here, then refuse to start a second backup while one
        is still in flight. An active backup (see UtilBackup.ACTIVE_STATUSES) created
        by a DIFFERENT celery task means its snapshot may already exist at the
        provider, so the new task must exit without creating a backup record or
        calling the provider API -- in that case this returns None and the caller
        (the celery task) returns immediately. A retry of the SAME task reuses its
        own backup (same celery_task_id) and is never blocked by it.
        """
        with transaction.atomic():
            CoreNode.objects.select_for_update().get(id=self.id)
            node_type_object = getattr(self, self.connection.integration.code)
            active_backup = node_type_object.backups.filter(
                status__in=UtilBackup.ACTIVE_STATUSES
            ).exclude(celery_task_id=celery_task_id).first()
            if active_backup:
                print(
                    f"Skipping duplicate backup of node {self.id}: backup "
                    f"{active_backup.id} is already in flight (status "
                    f"{active_backup.get_status_display()}, task "
                    f"{active_backup.celery_task_id}); task {celery_task_id} exiting."
                )
                return None
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
                    self.notify_storage_validation_fail(storage_point, backup)

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

    def notify_storage_validation_fail(self, storage, backup):
        """Email 'fail' recipients when a storage point fails validation at backup start.

        Called from backup_initiate, so everything is wrapped: a notification
        problem must never break the backup itself. The email's action_url is
        built inside the storage_validation_failed template from the injected
        site_app_url + node_id passed here.
        """
        from apps._tasks.helper.tasks import send_postmark_email

        try:
            if self.notify_on_fail and self.connection.account.notify_on_fail:
                account = self.connection.account
                data = {
                    "message": f"Storage validation failed for {storage.name} ({storage.type.name}) "
                               f"during backup ({backup.uuid_str}) of your node ({self.name}).",
                    "node_id": self.id,
                    "node_name": self.name,
                    "node_type": self.get_type_display().lower(),
                    "storage_type": storage.type.name,
                    "storage_name": storage.name,
                    "backup_name": backup.uuid_str,
                    "connection_name": self.connection.name,
                    "help_url": "https://support.backupsheep.com",
                    "sender_name": "BackupSheep - Notification Bot",
                }
                for _member, to_email in account.get_notification_recipients("fail"):
                    send_postmark_email.delay(
                        to_email,
                        "storage_validation_failed",
                        data,
                    )
        except Exception as e:
            capture_exception(e)

    def notify_backup_fail(self, error, backup_type):
        from apps._tasks.helper.tasks import send_postmark_email
        from datetime import datetime

        if str(backup_type) == "1":
            backup_type = "On-Demand"
        elif str(backup_type) == "2":
            backup_type = "Scheduled"

        try:
            if self.notify_on_fail and self.connection.account.notify_on_fail:
                account = self.connection.account
                # Email every eligible member (notify_on_fail honored; the primary
                # membership is always included) instead of only the primary member.
                recipients = account.get_notification_recipients("fail")

                def notify_recipients(template, data):
                    for _member, to_email in recipients:
                        send_postmark_email.delay(to_email, template, data)

                member = recipients[0][0] if recipients else None

                timezone = pytz.timezone((member.timezone if member else None) or "UTC")
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

                    notify_recipients(
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

                    notify_recipients(
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

                    notify_recipients(
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

                    notify_recipients(
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

                    notify_recipients(
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

                    notify_recipients(
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
                account = self.connection.account
                # Email every eligible member (notify_on_fail honored; the primary
                # membership is always included) instead of only the primary member.
                recipients = account.get_notification_recipients("fail")

                member = recipients[0][0] if recipients else None

                timezone = pytz.timezone((member.timezone if member else None) or "UTC")
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

                for _member, to_email in recipients:
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
                account = self.connection.account
                # Email every eligible member (notify_on_success honored; the primary
                # membership is always included) instead of only the primary member.
                recipients = account.get_notification_recipients("success")

                member = recipients[0][0] if recipients else None

                timezone = pytz.timezone((member.timezone if member else None) or "UTC")
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

                for _member, to_email in recipients:
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
