import subprocess
import time

import dropbox
import humanfriendly
import ibm_boto3
import paramiko
import requests
from botocore.exceptions import ClientError
from django.conf import settings
from django.db import models, IntegrityError
from django.db.models import UniqueConstraint
from django.urls import reverse
from gcloud.exceptions import NotFound
from model_utils import Choices
from model_utils.fields import StatusField
from model_utils.models import TimeStampedModel
from ovh import ResourceNotFoundError
from paramiko.ssh_exception import SSHException
from sentry_sdk import capture_exception, capture_message

from apps.console.storage.models import CoreStorage
from apps._tasks.exceptions import (
    NodeBackupFailedError,
    NodeBackupStatusCheckTimeOutError,
    NodeBackupStatusCheckCallError,
    NodeSnapshotDeleteFailed,
)
from apps.api.v1.utils.api_helpers import bs_decrypt, bs_encrypt
from ..utils.models import UtilBackup
from apps._tasks.helper.tasks import delete_from_disk
from backupsheep.celery import app
from botocore.config import Config


class CoreBackupType(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_backup_type"


class CoreDOBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_do_backup_status"


class CoreOVHCABackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_ovh_ca_backup_status"


class CoreOVHEUBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_ovh_eu_backup_status"


class CoreVultrBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_vultr_backup_status"


class CoreLinodeBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_linode_backup_status"


class CoreWebsiteBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_website_backup_status"


class CoreDatabaseBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_database_backup_status"


class CoreAWSBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_aws_backup_status"


class CoreLightsailBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_lightsail_backup_status"


class CoreAWSRDSBackupStatus(TimeStampedModel):
    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=64)
    description = models.TextField(null=True)

    class Meta:
        db_table = "core_aws_rds_backup_status"


class CoreDigitalOceanBackup(UtilBackup):
    digitalocean = models.ForeignKey(
        "CoreDigitalOcean", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="digitalocean_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    action_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_digitalocean_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.CLOUD == self.digitalocean.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.digitalocean.node, self.uuid_str, self.attempt_no, self.type, "DigitalOcean returned snapshot status as errored.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.digitalocean.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = (
                        self.digitalocean.node.connection.auth_digitalocean.get_client()
                    )
                    result = requests.get(
                        f"{settings.DIGITALOCEAN_API}/v2/actions/{self.action_id}",
                        headers=client,
                        verify=True,
                    )
                    if result.status_code == 200:
                        action = result.json()["action"]
                        if action.get("status") == "completed":
                            backup_status = UtilBackup.Status.COMPLETE

                            data = {
                                "resource_type": "droplet",
                                "per_page": 200,
                                "page": 1,
                            }
                            result = requests.get(
                                f"{settings.DIGITALOCEAN_API}/v2/snapshots/",
                                headers=client,
                                params=data,
                                verify=True,
                            )
                            if result.status_code == 200:
                                snapshots = result.json()["snapshots"]
                                snapshots_total = result.json()["meta"]["total"]
                                while len(snapshots) < snapshots_total:
                                    data["page"] += 1
                                    result = requests.get(
                                        f"{settings.DIGITALOCEAN_API}/v2/snapshots/",
                                        headers=client,
                                        params=data,
                                        verify=True,
                                    )
                                    if result.status_code == 200:
                                        snapshots = (
                                                snapshots + result.json()["snapshots"]
                                        )
                                    else:
                                        raise NodeBackupStatusCheckCallError(
                                            self.digitalocean.node, self.uuid_str
                                        )
                                for snapshot in snapshots:
                                    if snapshot["name"] == self.uuid_str:
                                        self.unique_id = snapshot["id"]
                                        self.size_gigabytes = snapshot["size_gigabytes"]
                                        self.status = backup_status
                                        self.save()
                            else:
                                raise NodeBackupStatusCheckCallError(
                                    self.digitalocean.node, self.uuid_str
                                )
                        elif action.get("status") == "errored":
                            backup_status = UtilBackup.Status.FAILED
                        elif action.get("status") == "in-progress":
                            backup_status = UtilBackup.Status.IN_PROGRESS
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1
        elif CoreNode.Type.VOLUME == self.digitalocean.node.type:
            self.status = UtilBackup.Status.COMPLETE
            self.save()

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.digitalocean.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.digitalocean.node.connection.auth_digitalocean.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
            f"is being deleted using connection {self.digitalocean.node.connection.name}"
        )

        try:
            if CoreNode.Type.CLOUD == self.digitalocean.node.type:
                result = requests.delete(
                    f"{settings.DIGITALOCEAN_API}/v2/snapshots/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if not (result.status_code == 204 or result.status_code == 200):
                    raise NodeSnapshotDeleteFailed(
                        self.digitalocean.node,
                        self.uuid_str,
                        message=result.json().get("message"),
                    )
            elif CoreNode.Type.VOLUME == self.digitalocean.node.type:
                snapshots = []
                next_page = 1
                while next_page is not None:
                    payload = {"page": next_page, "per_page": 200, "resource_type": "volume"}
                    result = requests.get(
                        f"{settings.DIGITALOCEAN_API}/v2/snapshots",
                        params=payload,
                        headers=client,
                        verify=True,
                    )
                    if result.status_code == 200:
                        snapshots += result.json()["snapshots"]
                        if len(snapshots) >= result.json()["meta"]["total"]:
                            next_page = None
                        else:
                            next_page += 1
                    else:
                        next_page = None
                    result.close()

                if len(snapshots) > 0:
                    selected_snapshot = next(
                        (
                            snapshot
                            for snapshot in snapshots
                            if self.uuid_str in snapshot["name"]
                        ),
                        None,
                    )
                    if selected_snapshot:
                        result = requests.delete(
                            f"{settings.DIGITALOCEAN_API}/v2/snapshots/{selected_snapshot['id']}",
                            headers=client,
                            verify=True,
                        )
                        if result.status_code == 204:
                            print(f"deleted backup id {self.uuid_str}")
                        if result.status_code != 204:
                            raise NodeSnapshotDeleteFailed(
                                self.digitalocean.node,
                                self.uuid_str,
                                message=f"Request status code {result.status_code}",
                            )
                    else:
                        raise NodeSnapshotDeleteFailed(
                            self.digitalocean.node,
                            self.uuid_str,
                            message="Unable to locate snapshot for deletion.",
                        )
                else:
                    raise NodeSnapshotDeleteFailed(
                        self.digitalocean.node,
                        self.uuid_str,
                        message="Unable to get list of snapshots.",
                    )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
                f"deleted successfully using connection {self.digitalocean.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.digitalocean.node.name} "
                f"failed to using connection {self.digitalocean.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.digitalocean.node.connection.account.create_backup_log(msg, self.digitalocean.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.digitalocean.node.backup_complete_reset()


class CoreHetznerBackup(UtilBackup):
    hetzner = models.ForeignKey(
        "CoreHetzner", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="hetzner_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    action_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_hetzner_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.CLOUD == self.hetzner.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.hetzner.node, self.uuid_str, self.attempt_no, self.type, "Hetzner returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.hetzner.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.hetzner.node.connection.auth_hetzner.get_client()
                    result = requests.get(
                        f"{settings.HETZNER_API}/v1/actions/{self.action_id}",
                        headers=client,
                        verify=True,
                    )
                    if result.status_code == 200:
                        action = result.json()["action"]

                        if action["status"] == "success":
                            backup_status = UtilBackup.Status.COMPLETE
                            snapshot_id = self.unique_id
                            result = requests.get(
                                f"{settings.HETZNER_API}/v1/images/{snapshot_id}",
                                headers=client,
                                verify=True,
                            )
                            if result.status_code == 200:
                                image = result.json()["image"]
                                self.size_gigabytes = image["disk_size"]
                                self.status = backup_status
                                self.metadata = image
                                self.save()
                            else:
                                raise NodeBackupStatusCheckCallError(
                                    self.hetzner.node, self.uuid_str
                                )
                        elif action.get("status") == "error":
                            backup_status = UtilBackup.Status.FAILED
                        elif action.get("status") == "running":
                            backup_status = UtilBackup.Status.IN_PROGRESS
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.hetzner.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.hetzner.node.connection.auth_hetzner.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.hetzner.node.name} "
            f"is being deleted using connection {self.hetzner.node.connection.name}"
        )

        try:
            if CoreNode.Type.CLOUD == self.hetzner.node.type:
                """
                If unique ID is not available then find image using name.
                """
                if not self.unique_id:
                    next_page = 1
                    while next_page is not None:
                        data = {
                            "page": next_page,
                            "per_page": 50,
                            "type": "snapshot",
                            "status": "available",
                        }
                        result = requests.get(
                            f"{settings.HETZNER_API}/v1/images/",
                            headers=client,
                            params=data,
                            verify=True,
                        )
                        if result.status_code == 200:
                            next_page = result.json()["meta"]["pagination"]["next_page"]
                            images = result.json()["images"]
                            image_found = next(
                                (
                                    item
                                    for item in images
                                    if item.get("description") == self.uuid_str
                                ),
                                None,
                            )
                            if image_found:
                                self.unique_id = image_found["id"]
                                self.save()
                                next_page = None
                        else:
                            raise ValueError("Invalid response from Hetzner APIs")

                result = requests.delete(
                    f"{settings.HETZNER_API}/v1/images/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if not (result.status_code == 204 or result.status_code == 200):
                    raise NodeSnapshotDeleteFailed(
                        self.hetzner.node,
                        self.uuid_str,
                        message=result.json().get("error").get("message"),
                    )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.hetzner.node.name} "
                f"deleted successfully using connection {self.hetzner.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.hetzner.node.name} "
                f"failed to using connection {self.hetzner.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.hetzner.node.connection.account.create_backup_log(msg, self.hetzner.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.hetzner.node.backup_complete_reset()


class CoreUpCloudBackup(UtilBackup):
    upcloud = models.ForeignKey(
        "CoreUpCloud", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="upcloud_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_upcloud_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.VOLUME == self.upcloud.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.upcloud.node, self.uuid_str, self.attempt_no, self.type, "UpCloud returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.upcloud.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.upcloud.node.connection.auth_upcloud.get_client()
                    result = requests.get(
                        f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
                        auth=client,
                        verify=True,
                        headers={"content-type": "application/json"},
                    )
                    if result.status_code == 200:
                        storage = result.json()["storage"]

                        if storage["state"] == "online":
                            backup_status = UtilBackup.Status.COMPLETE
                            self.size_gigabytes = storage["size"]
                            self.status = backup_status
                            self.metadata = storage
                            self.save()
                        elif storage["state"] == "error":
                            backup_status = UtilBackup.Status.FAILED
                        elif (
                                storage["state"] == "backuping"
                                or storage["state"] == "syncing"
                                or storage["state"] == "cloning"
                                or storage["state"] == "maintenance"
                        ):
                            backup_status = UtilBackup.Status.IN_PROGRESS
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.upcloud.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.upcloud.node.connection.auth_upcloud.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
            f"is being deleted using connection {self.upcloud.node.connection.name}"
        )

        try:
            if CoreNode.Type.VOLUME == self.upcloud.node.type:
                result = requests.delete(
                    f"{settings.UPCLOUD_API}/storage/{self.unique_id}",
                    auth=client,
                    verify=True,
                    headers={"content-type": "application/json"},
                )
                if not (result.status_code == 204):
                    raise NodeSnapshotDeleteFailed(
                        self.upcloud.node,
                        self.uuid_str,
                        message=result.json().get("error").get("message"),
                    )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
                f"deleted successfully using connection {self.upcloud.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.upcloud.node.name} "
                f"failed to using connection {self.upcloud.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.upcloud.node.connection.account.create_backup_log(msg, self.upcloud.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.upcloud.node.backup_complete_reset()


class CoreOracleBackup(UtilBackup):
    oracle = models.ForeignKey("CoreOracle", related_name="backups", on_delete=models.CASCADE)
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="oracle_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=255, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_oracle_backup"

    def validate(self):
        import oci
        from oci.core.models import BootVolumeBackup, VolumeBackup
        from ..node.models import CoreNode

        if CoreNode.Type.VOLUME == self.oracle.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(
                        self.oracle.node,
                        self.uuid_str,
                        self.attempt_no,
                        self.type,
                        "Oracle returned snapshot status as error.",
                    )
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(self.oracle.node, self.uuid_str)
                time.sleep(60)
                try:
                    config = self.oracle.node.connection.auth_oracle.get_client()
                    block_storage_client = oci.core.BlockstorageClient(config)

                    if self.oracle.metadata.get("_bs_vol_type") == "boot":
                        request = block_storage_client.get_boot_volume_backup(boot_volume_backup_id=self.unique_id)
                        if request.status == 200:
                            if request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_AVAILABLE:
                                backup_status = UtilBackup.Status.COMPLETE
                                self.size_gigabytes = request.data.size_in_gbs
                                self.status = backup_status
                                self.metadata = {
                                    "_bs_name": request.data.display_name,
                                    "_bs_size": request.data.size_in_gbs,
                                    "_bs_vol_type": "boot",
                                }
                                self.save()
                            elif request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_CREATING:
                                backup_status = UtilBackup.Status.IN_PROGRESS
                            elif request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_REQUEST_RECEIVED:
                                backup_status = UtilBackup.Status.IN_PROGRESS
                            elif request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_FAULTY:
                                backup_status = UtilBackup.Status.FAILED
                            elif request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_TERMINATED:
                                backup_status = UtilBackup.Status.FAILED
                            elif request.data.lifecycle_state == BootVolumeBackup.LIFECYCLE_STATE_TERMINATING:
                                backup_status = UtilBackup.Status.FAILED
                    elif self.oracle.metadata.get("_bs_vol_type") == "block":
                        request = block_storage_client.get_volume_backup(volume_backup_id=self.unique_id)
                        if request.status == 200:
                            if request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_AVAILABLE:
                                backup_status = UtilBackup.Status.COMPLETE
                                self.size_gigabytes = request.data.size_in_gbs
                                self.status = backup_status
                                self.metadata = {
                                    "_bs_name": request.data.display_name,
                                    "_bs_size": request.data.size_in_gbs,
                                    "_bs_vol_type": "block",
                                }
                                self.save()
                            elif request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_CREATING:
                                backup_status = UtilBackup.Status.IN_PROGRESS
                            elif request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_REQUEST_RECEIVED:
                                backup_status = UtilBackup.Status.IN_PROGRESS
                            elif request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_FAULTY:
                                backup_status = UtilBackup.Status.FAILED
                            elif request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_TERMINATED:
                                backup_status = UtilBackup.Status.FAILED
                            elif request.data.lifecycle_state == VolumeBackup.LIFECYCLE_STATE_TERMINATING:
                                backup_status = UtilBackup.Status.FAILED
                    # Save backup status
                    self.status = backup_status
                    self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.oracle.node

    def soft_delete(self):
        import oci
        from ..node.models import CoreNode

        msg = (
            f"Backup {self.uuid_str} of node {self.oracle.node.name} "
            f"is being deleted using integration {self.oracle.node.connection.name}"
        )

        try:
            if CoreNode.Type.VOLUME == self.oracle.node.type:
                config = self.oracle.node.connection.auth_oracle.get_client()
                block_storage_client = oci.core.BlockstorageClient(config)

                if self.oracle.metadata.get("_bs_vol_type") == "boot":
                    response = block_storage_client.delete_boot_volume_backup(boot_volume_backup_id=self.unique_id)
                    if response.status == 204:
                        self.status = UtilBackup.Status.DELETE_COMPLETED
                    else:
                        self.status = UtilBackup.Status.DELETE_FAILED
                elif self.oracle.metadata.get("_bs_vol_type") == "block":
                    response = block_storage_client.delete_volume_backup(volume_backup_id=self.unique_id)
                    if response.status == 204:
                        self.status = UtilBackup.Status.DELETE_COMPLETED
                    else:
                        self.status = UtilBackup.Status.DELETE_FAILED
                self.save()

                if self.status == UtilBackup.Status.DELETE_COMPLETED:
                    msg = (
                        f"Backup {self.uuid_str} of node {self.oracle.node.name} "
                        f"deleted successfully using integration {self.oracle.node.connection.name}"
                    )
                else:
                    msg = (
                        f"Invalid response from Oracle API. The backup {self.uuid_str} "
                        f"is marked {self.get_status_display()}. "
                        f"Please check your Oracle Cloud account."
                    )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Invalid response from Oracle API. The backup {self.uuid_str} "
                f"is marked {self.get_status_display()}. "
                f"Please check your Oracle Cloud account. Error: {e.__str__()}"
            )
        finally:
            self.oracle.node.connection.account.create_backup_log(msg, self.oracle.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.oracle.node.backup_complete_reset()


class CoreOVHCABackup(UtilBackup):
    ovh_ca = models.ForeignKey(
        "CoreOVHCA", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreOVHCABackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="ovh_ca_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="ovh_ca_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64, null=True)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_ca_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.CLOUD == self.ovh_ca.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.ovh_ca.node, self.uuid_str, self.attempt_no, self.type, "OVH returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.ovh_ca.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.ovh_ca.node.connection.auth_ovh_ca.get_client()
                    snapshots = client.get(
                        f"/cloud/project/{self.ovh_ca.project_id}/snapshot"
                    )
                    if next(
                            (
                                    item
                                    for item in snapshots
                                    if item["name"] == self.unique_id
                                       and item["status"] == "active"
                            ),
                            None,
                    ):
                        backup_status = UtilBackup.Status.COMPLETE
                        ovh_snapshot = next(
                            (
                                item
                                for item in snapshots
                                if item["name"] == self.unique_id
                                   and item["status"] == "active"
                            ),
                            None,
                        )
                        self.unique_id = ovh_snapshot["id"]
                        self.size_gigabytes = ovh_snapshot["size"]
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1
        elif CoreNode.Type.VOLUME == self.ovh_ca.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.ovh_ca.node, self.uuid_str, self.attempt_no, self.type, "OVH returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.ovh_ca.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.ovh_ca.node.connection.auth_ovh_ca.get_client()
                    snapshots = client.get(
                        f"/cloud/project/{self.ovh_ca.project_id}/volume/snapshot"
                    )
                    if next(
                            (
                                    item
                                    for item in snapshots
                                    if item["name"] == self.unique_id
                                       and item["status"] == "available"
                            ),
                            None,
                    ):
                        backup_status = UtilBackup.Status.COMPLETE
                        ovh_snapshot = next(
                            (
                                item
                                for item in snapshots
                                if item["name"] == self.unique_id
                                   and item["status"] == "available"
                            ),
                            None,
                        )

                        self.unique_id = ovh_snapshot["id"]
                        self.size_gigabytes = ovh_snapshot["size"]
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.ovh_ca.node

    def soft_delete(self):
        from ..node.models import CoreNode
        from ..log.models import CoreLog

        client = self.ovh_ca.node.connection.auth_ovh_ca.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
            f"is being deleted using connection {self.ovh_ca.node.connection.name}"
        )

        try:
            if CoreNode.Type.CLOUD == self.ovh_ca.node.type:
                client.delete(
                    f"/cloud/project/{self.ovh_ca.project_id}/snapshot/{self.unique_id}"
                )
            elif CoreNode.Type.VOLUME == self.ovh_ca.node.type:
                client.delete(
                    f"/cloud/project/{self.ovh_ca.project_id}/volume/snapshot/{self.unique_id}"
                )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
                f"deleted successfully using connection {self.ovh_ca.node.connection.name}"
            )
        except ResourceNotFoundError:
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
                f"was not found on hosting using {self.ovh_ca.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_ca.node.name} "
                f"failed to using connection {self.ovh_ca.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.ovh_ca.node.connection.account.create_backup_log(msg, self.ovh_ca.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.ovh_ca.node.backup_complete_reset()


class CoreOVHEUBackup(UtilBackup):
    ovh_eu = models.ForeignKey(
        "CoreOVHEU", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreOVHEUBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="ovh_eu_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="ovh_eu_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_eu_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.CLOUD == self.ovh_eu.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.ovh_eu.node, self.uuid_str, self.attempt_no, self.type, "OVH returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.ovh_eu.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.ovh_eu.node.connection.auth_ovh_eu.get_client()
                    snapshots = client.get(
                        f"/cloud/project/{self.ovh_eu.project_id}/snapshot"
                    )
                    if next(
                            (
                                    item
                                    for item in snapshots
                                    if item["name"] == self.unique_id
                                       and item["status"] == "active"
                            ),
                            None,
                    ):
                        backup_status = UtilBackup.Status.COMPLETE
                        ovh_snapshot = next(
                            (
                                item
                                for item in snapshots
                                if item["name"] == self.unique_id
                                   and item["status"] == "active"
                            ),
                            None,
                        )
                        self.unique_id = ovh_snapshot["id"]
                        self.size_gigabytes = ovh_snapshot["size"]
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1
        elif CoreNode.Type.VOLUME == self.ovh_eu.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.ovh_eu.node, self.uuid_str, self.attempt_no, self.type, "OVH returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.ovh_eu.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.ovh_eu.node.connection.auth_ovh_eu.get_client()
                    snapshots = client.get(
                        f"/cloud/project/{self.ovh_eu.project_id}/volume/snapshot"
                    )
                    if next(
                            (
                                    item
                                    for item in snapshots
                                    if item["name"] == self.unique_id
                                       and item["status"] == "available"
                            ),
                            None,
                    ):
                        backup_status = UtilBackup.Status.COMPLETE
                        ovh_snapshot = next(
                            (
                                item
                                for item in snapshots
                                if item["name"] == self.unique_id
                                   and item["status"] == "available"
                            ),
                            None,
                        )

                        self.unique_id = ovh_snapshot["id"]
                        self.size_gigabytes = ovh_snapshot["size"]
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.ovh_eu.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.ovh_eu.node.connection.auth_ovh_eu.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
            f"is being deleted using connection {self.ovh_eu.node.connection.name}"
        )
        try:
            if CoreNode.Type.CLOUD == self.ovh_eu.node.type:
                client.delete(
                    f"/cloud/project/{self.ovh_eu.project_id}/snapshot/{self.unique_id}"
                )
            elif CoreNode.Type.VOLUME == self.ovh_eu.node.type:
                client.delete(
                    f"/cloud/project/{self.ovh_eu.project_id}/volume/snapshot/{self.unique_id}"
                )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
                f"deleted successfully using connection {self.ovh_eu.node.connection.name}"
            )
        except ResourceNotFoundError:
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
                f"was not found on hosting using {self.ovh_eu.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_eu.node.name} "
                f"failed to using connection {self.ovh_eu.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.ovh_eu.node.connection.account.create_backup_log(msg, self.ovh_eu.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.ovh_eu.node.backup_complete_reset()


class CoreOVHUSBackup(UtilBackup):
    ovh_us = models.ForeignKey(
        "CoreOVHUS", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="ovh_us_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_ovh_us_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.CLOUD == self.ovh_us.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.ovh_us.node, self.uuid_str, self.attempt_no, self.type, "OVH returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.ovh_us.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.ovh_us.node.connection.auth_ovh_us.get_client()
                    snapshots = client.get(
                        f"/cloud/project/{self.ovh_us.project_id}/snapshot"
                    )
                    if next(
                            (
                                    item
                                    for item in snapshots
                                    if item["name"] == self.unique_id
                                       and item["status"] == "active"
                            ),
                            None,
                    ):
                        backup_status = UtilBackup.Status.COMPLETE
                        ovh_snapshot = next(
                            (
                                item
                                for item in snapshots
                                if item["name"] == self.unique_id
                                   and item["status"] == "active"
                            ),
                            None,
                        )
                        self.unique_id = ovh_snapshot["id"]
                        self.size_gigabytes = ovh_snapshot["size"]
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1
        elif CoreNode.Type.VOLUME == self.ovh_us.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.ovh_us.node, self.uuid_str, self.attempt_no, self.type, "OVH returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.ovh_us.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.ovh_us.node.connection.auth_ovh_us.get_client()
                    snapshots = client.get(
                        f"/cloud/project/{self.ovh_us.project_id}/volume/snapshot"
                    )
                    if next(
                            (
                                    item
                                    for item in snapshots
                                    if item["name"] == self.unique_id
                                       and item["status"] == "available"
                            ),
                            None,
                    ):
                        backup_status = UtilBackup.Status.COMPLETE
                        ovh_snapshot = next(
                            (
                                item
                                for item in snapshots
                                if item["name"] == self.unique_id
                                   and item["status"] == "available"
                            ),
                            None,
                        )

                        self.unique_id = ovh_snapshot["id"]
                        self.size_gigabytes = ovh_snapshot["size"]
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.ovh_us.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.ovh_us.node.connection.auth_ovh_us.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
            f"is being deleted using connection {self.ovh_us.node.connection.name}"
        )
        try:
            if CoreNode.Type.CLOUD == self.ovh_us.node.type:
                client.delete(
                    f"/cloud/project/{self.ovh_us.project_id}/snapshot/{self.unique_id}"
                )
            elif CoreNode.Type.VOLUME == self.ovh_us.node.type:
                client.delete(
                    f"/cloud/project/{self.ovh_us.project_id}/volume/snapshot/{self.unique_id}"
                )
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
                f"deleted successfully using connection {self.ovh_us.node.connection.name}"
            )
        except ResourceNotFoundError:
            self.status = UtilBackup.Status.DELETE_FAILED_NOT_FOUND
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
                f"was not found on hosting using {self.ovh_us.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.ovh_us.node.name} "
                f"failed to using connection {self.ovh_us.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.ovh_us.node.connection.account.create_backup_log(msg, self.ovh_us.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.ovh_us.node.backup_complete_reset()


class CoreVultrBackup(UtilBackup):
    vultr = models.ForeignKey(
        "CoreVultr", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreVultrBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="vultr_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="vultr_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_vultr_backup"

    def validate(self):
        backup_status = UtilBackup.Status.IN_PROGRESS
        check_counter = 0
        while backup_status != UtilBackup.Status.COMPLETE:
            if backup_status == UtilBackup.Status.FAILED:
                raise NodeBackupFailedError(self.vultr.node, self.uuid_str, self.attempt_no, self.type, "Vultr returned snapshot status as error.")
            elif check_counter > 720:
                raise NodeBackupStatusCheckTimeOutError(self.vultr.node, self.uuid_str)
            time.sleep(60)
            try:
                client = self.vultr.node.connection.auth_vultr.get_client()
                r = requests.get(
                    f"{settings.VULTR_API}/v2/snapshots/{self.unique_id}",
                    headers=client,
                    verify=True,
                )
                if r.status_code == 200:
                    snapshot = r.json()["snapshot"]
                    if snapshot["status"] == "complete":
                        backup_status = UtilBackup.Status.COMPLETE
                        self.size_gigabytes = round(int(snapshot.get("size", 0)) / (1000 ** 3), 2)
                self.status = backup_status
                self.save()
                r.close()
            except Exception as e:
                backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.vultr.node

    def soft_delete(self):
        from ..log.models import CoreLog

        client = self.vultr.node.connection.auth_vultr.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.vultr.node.name} "
            f"is being deleted using connection {self.vultr.node.connection.name}"
        )
        try:
            r = requests.delete(
                f"{settings.VULTR_API}/v2/snapshots/{self.unique_id}",
                headers=client,
                verify=True,
            )

            if r.status_code == 204:
                self.status = UtilBackup.Status.DELETE_COMPLETED
                self.save()
                msg = (
                    f"Backup {self.uuid_str} of node {self.vultr.node.name} "
                    f"deleted successfully using connection {self.vultr.node.connection.name}"
                )
            else:
                raise NodeSnapshotDeleteFailed(
                    self.vultr.node,
                    self.uuid_str,
                    message="Unable to locate snapshot for deletion.",
                )
            r.close()
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.vultr.node.name} "
                f"failed to using connection {self.vultr.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.vultr.node.connection.account.create_backup_log(msg, self.vultr.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.vultr.node.backup_complete_reset()


class CoreLinodeBackup(UtilBackup):
    linode = models.ForeignKey(
        "CoreLinode", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreLinodeBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="linode_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="linode_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_linode_backup"

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.linode.node.backup_complete_reset()


class CoreGoogleCloudBackup(UtilBackup):
    google_cloud = models.ForeignKey(
        "CoreGoogleCloud", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="google_cloud_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_google_cloud_backup"

    def validate(self):
        from ..node.models import CoreNode

        if self.google_cloud.node.type == CoreNode.Type.CLOUD:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(
                        self.google_cloud.node, self.uuid_str, self.attempt_no, self.type, "Google Cloud returned"
                                                                                           " snapshot status as error."
                    )
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.google_cloud.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.google_cloud.node.connection.auth_google_cloud.get_client()
                    result = requests.get(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.google_cloud.project_id}"
                        f"/global/machineImages/{self.uuid_str}",
                        headers=client
                    )
                    if result.status_code == 200:
                        image = result.json()
                        if image["status"] == "READY":
                            backup_status = UtilBackup.Status.COMPLETE
                            self.size_gigabytes = int(image.get("totalStorageBytes", 0))/(1000**3)
                        elif image["status"] == "CREATING":
                            pass
                        elif image["status"] == "UPLOADING":
                            pass
                        elif image["status"] == "INVALID":
                            backup_status = UtilBackup.Status.FAILED
                        elif image["status"] == "DELETING":
                            backup_status = UtilBackup.Status.FAILED

                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1
        elif self.google_cloud.node.type == CoreNode.Type.VOLUME:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(
                        self.google_cloud.node, self.uuid_str, self.attempt_no, self.type, "Google Cloud returned"
                                                                                           " snapshot status as error."
                    )
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.google_cloud.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.google_cloud.node.connection.auth_google_cloud.get_client()
                    result = requests.get(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.google_cloud.project_id}"
                        f"/global/snapshots/{self.uuid_str}",
                        headers=client
                    )
                    if result.status_code == 200:
                        disk = result.json()
                        if disk["status"] == "READY":
                            backup_status = UtilBackup.Status.COMPLETE
                            self.size_gigabytes = int(disk.get("storageBytes", 0))/(1000**3)
                        elif disk["status"] == "CREATING":
                            pass
                        elif disk["status"] == "UPLOADING":
                            pass
                        elif disk["status"] == "FAILED":
                            backup_status = UtilBackup.Status.FAILED
                        elif disk["status"] == "DELETING":
                            backup_status = UtilBackup.Status.FAILED

                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.google_cloud.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.google_cloud.node.connection.auth_google_cloud.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.google_cloud.node.name} "
            f"is being deleted using connection {self.google_cloud.node.connection.name}"
        )
        try:
            if self.google_cloud.node.type == CoreNode.Type.CLOUD:
                result = requests.delete(
                    f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                    f"/projects/{self.google_cloud.project_id}"
                    f"/global/machineImages/{self.uuid_str}",
                    headers=client
                )
                if result.status_code == 200:
                    self.status = UtilBackup.Status.DELETE_COMPLETED
                    self.save()
                    msg = (
                        f"Backup {self.uuid_str} of node {self.google_cloud.node.name} "
                        f"deleted successfully using connection {self.google_cloud.node.connection.name}"
                    )
                else:
                    raise NodeSnapshotDeleteFailed(
                        self.google_cloud.node,
                        self.uuid_str,
                        message="Unable to delete instance image.",
                    )
            elif self.google_cloud.node.type == CoreNode.Type.VOLUME:
                result = requests.delete(
                        f"{settings.GOOGLE_COMPUTE_API}/compute/v1"
                        f"/projects/{self.google_cloud.project_id}"
                        f"/global/snapshots/{self.uuid_str}",
                        headers=client
                    )
                if result.status_code == 200:
                    self.status = UtilBackup.Status.DELETE_COMPLETED
                    self.save()
                    msg = (
                        f"Backup {self.uuid_str} of node {self.google_cloud.node.name} "
                        f"deleted successfully using connection {self.google_cloud.node.connection.name}"
                    )
                else:
                    raise NodeSnapshotDeleteFailed(
                        self.google_cloud.node,
                        self.uuid_str,
                        message="Unable to delete disk snapshot.",
                    )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.google_cloud.node.name} "
                f"failed to using connection {self.google_cloud.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.google_cloud.node.connection.account.create_backup_log(msg, self.google_cloud.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.google_cloud.node.backup_complete_reset()


class CoreWebsiteBackup(UtilBackup):
    UNZIP_REQUEST = Choices("requested", "in_progress", "available", "disable")
    website = models.ForeignKey(
        "CoreWebsite", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="website_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    size = models.BigIntegerField(null=True)
    zip_size = models.BigIntegerField(null=True)
    raw_size = models.BigIntegerField(null=True)
    total_files = models.BigIntegerField(null=True)
    total_folders = models.BigIntegerField(null=True)
    total_files_n_folders_calculated = models.BooleanField(null=True)
    excludes = models.JSONField(null=True)
    paths = models.JSONField(null=True)
    file_list_json = models.JSONField(null=True)
    file_list_path = models.JSONField(null=True)
    all_paths = models.BooleanField(null=True)
    unzip_request = StatusField(choices_name="UNZIP_REQUEST", default=None, null=True)
    unzip_sftp_time = models.BigIntegerField(null=True)
    unzip_sftp_docker = models.CharField(null=True, max_length=2048)
    unzip_sftp_user = models.CharField(null=True, max_length=2048)
    unzip_sftp_pass = models.CharField(null=True, max_length=2048)
    unzip_sftp_host = models.CharField(null=True, max_length=2048)
    unzip_sftp_port = models.IntegerField(null=True)
    unique_id = models.CharField(max_length=255, null=True)
    storage_points = models.ManyToManyField(
        CoreStorage,
        related_name="website_backups",
        through="CoreWebsiteBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_website_backup"

    def soft_delete(self):
        for stored_website_backup in self.stored_website_backups.all():
            stored_website_backup.soft_delete()
        self.status = self.Status.DELETE_COMPLETED
        self.save()

    def all_storage_points_uploaded(self):
        return self.stored_website_backups.all().count() == self.stored_website_backups.filter(
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE).count()

    def partial_storage_points_uploaded(self):
        return self.stored_website_backups.filter(
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE).count() > 0

    def storage_points_uploaded(self):
        return self.stored_website_backups.filter(
            status=CoreWebsiteBackupStoragePoints.Status.UPLOAD_COMPLETE).count()


    @property
    def node(self):
        return self.website.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        for stored_website_backup in self.stored_website_backups.all():
            try:
                stored_website_backup.status = (
                    CoreWebsiteBackupStoragePoints.Status.CANCELLED
                )
                stored_website_backup.save()
                app.control.revoke(stored_website_backup.celery_task_id, terminate=True)
            except IntegrityError:
                stored_website_backup.delete()
        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Delete files
        """
        queue = f"delete_from_disk__{self.website.node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
            queue=queue,
        )

        """
        Reset the node status
        """
        self.website.node.backup_complete_reset()
        self.save()

        """
        Stop docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )


class CoreWebsiteBackupFiles(TimeStampedModel):
    md5_hash = models.TextField()
    path = models.TextField()
    backup = models.ForeignKey(CoreWebsiteBackup, related_name="files", on_delete=models.CASCADE)

    class Meta:
        db_table = "core_website_backup_file"


class BaseBackupStoragePoints(TimeStampedModel):
    class Meta:
        abstract = True

    def generate_download_url(self):
        import boto3
        encryption_key = self.storage.account.get_encryption_key()

        if self.storage.type.code == "aws_s3":
            s3_client = boto3.client(
                "s3",
                self.storage.storage_aws_s3.region.code,
                aws_access_key_id=bs_decrypt(self.storage.storage_aws_s3.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_aws_s3.secret_key, encryption_key
                ),
            )
            s3_object = s3_client.head_object(
                Bucket=self.storage.storage_aws_s3.bucket_name,
                Key=f"{self.storage_file_id}",
            )
            if s3_object.get("StorageClass") and (
                    s3_object.get("StorageClass") == "GLACIER"
                    or s3_object.get("StorageClass") == "DEEP_ARCHIVE"
            ):
                if not s3_object.get("Restore"):
                    s3_client.restore_object(
                        Bucket=self.storage.storage_aws_s3.bucket_name,
                        Key=f"{self.storage_file_id}",
                        RestoreRequest={
                            "Days": 2,
                            "GlacierJobParameters": {
                                "Tier": "Expedited",
                            },
                        },
                    )
                    return "restore_requested"
                elif 'ongoing-request="true"' in s3_object.get("Restore"):
                    return "restore_in_progress"
                elif 'ongoing-request="false"' in s3_object.get("Restore"):
                    response = s3_client.generate_presigned_url(
                        "get_object",
                        Params={
                            "Bucket": self.storage.storage_aws_s3.bucket_name,
                            "Key": f"{self.storage_file_id}",
                        },
                        ExpiresIn=24 * 3600,
                    )
                    return response
            else:
                response = s3_client.generate_presigned_url(
                    "get_object",
                    Params={
                        "Bucket": self.storage.storage_aws_s3.bucket_name,
                        "Key": f"{self.storage_file_id}",
                    },
                    ExpiresIn=24 * 3600,
                )
                return response
        elif self.storage.type.code == "do_spaces":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_do_spaces.region.endpoint}",
                aws_access_key_id=bs_decrypt(
                    self.storage.storage_do_spaces.access_key, encryption_key
                ),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_do_spaces.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_do_spaces.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "filebase":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://s3.filebase.com",
                aws_access_key_id=bs_decrypt(self.storage.storage_filebase.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_filebase.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_filebase.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "exoscale":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_exoscale.region.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_exoscale.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_exoscale.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_exoscale.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "oracle":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_oracle.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_oracle.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_oracle.secret_key, encryption_key
                ),
                region_name=self.storage.storage_oracle.region.code
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_oracle.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "scaleway":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_scaleway.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_scaleway.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_scaleway.secret_key, encryption_key
                ),
                region_name=self.storage.storage_scaleway.region.code
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_scaleway.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "backblaze_b2":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_backblaze_b2.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_backblaze_b2.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_backblaze_b2.secret_key, encryption_key
                ),
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_backblaze_b2.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "linode":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_linode.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_linode.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_linode.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_linode.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "vultr":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_vultr.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_vultr.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_vultr.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_vultr.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "upcloud":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_upcloud.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_upcloud.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_upcloud.secret_key, encryption_key
                ),
                region_name=self.storage.storage_upcloud.endpoint.split('.')[1],
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_upcloud.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "cloudflare":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_cloudflare.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_cloudflare.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_cloudflare.secret_key, encryption_key
                ),
                region_name="auto",
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_cloudflare.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "wasabi":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_wasabi.region.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_wasabi.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_wasabi.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_wasabi.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "dropbox":
            dbx = dropbox.Dropbox(
                bs_decrypt(self.storage.storage_dropbox.access_token, encryption_key)
            )
            url = dbx.files_get_temporary_link(self.storage_file_id).link
            return url
        elif self.storage.type.code == "google_drive":
            client = self.storage.storage_google_drive.get_client()

            search_params = {
                "fields": "webViewLink",
            }

            result = client.get(
                f"https://www.googleapis.com/drive/v3/files/{self.storage_file_id}",
                params=search_params,
                headers={"Content-Type": "application/json; charset=UTF-8"},
            )

            if result.status_code == 200:
                response = result.json()["webViewLink"]
                return response
            else:
                return None
        elif self.storage.type.code == "pcloud":
            url = f"https://my.pcloud.com/#page=filemanager" \
                  f"&q=name:{self.backup.uuid_str}" \
                  f"&folderid={self.metadata.get('parentfolderid')}" \
                  f"&filter=all"
            return url
        elif self.storage.type.code == "onedrive":
            onedrive_path = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.storage.storage_onedrive.drive_id}/root:/{self.storage_file_id}"

            r = requests.get(
                onedrive_path + "", headers=self.storage.storage_onedrive.get_client()
            )

            url = r.json().get("@microsoft.graph.downloadUrl")

            return url
        elif self.storage.type.code == "google_cloud":
            from google.cloud import storage as gc_storage
            from datetime import timedelta

            storage_client = gc_storage.Client(credentials=self.storage.storage_google_cloud.get_credentials())
            bucket = storage_client.bucket(self.storage.storage_google_cloud.bucket_name)

            if bucket.exists():
                blob = bucket.blob(self.storage_file_id)
                if blob.exists():
                    url = blob.generate_signed_url(
                        version="v4",
                        expiration=timedelta(hours=24),
                        method="GET",
                    )
                    return url
                else:
                    return None
            else:
                return None

        elif self.storage.type.code == "azure":
            import time
            import datetime
            from azure.storage.blob import BlobSasPermissions, generate_blob_sas
            from datetime import timedelta

            bucket_name = self.storage.storage_azure.bucket_name

            blob_service_client = self.storage.storage_azure.get_client()

            # Create a SAS token that expires in 1 hour
            sas_expiry = datetime.datetime.utcnow() + timedelta(hours=48)
            sas_permissions = BlobSasPermissions(read=True, write=False, delete=False)
            sas_token = generate_blob_sas(
                account_name=blob_service_client.account_name,
                container_name=bucket_name,
                blob_name=self.storage_file_id,
                account_key=blob_service_client.credential.account_key,
                permission=sas_permissions,
                expiry=sas_expiry,
            )

            return f"https://{blob_service_client.account_name}.blob.core.windows.net/{bucket_name}/{self.storage_file_id}?{sas_token}"

        elif self.storage.type.code == "alibaba":
            import oss2

            auth = oss2.Auth(
                bs_decrypt(self.storage.storage_alibaba.access_key, encryption_key),
                bs_decrypt(self.storage.storage_alibaba.secret_key, encryption_key),
            )
            bucket = oss2.Bucket(auth, f"https://{self.storage.storage_alibaba.endpoint}", self.storage.storage_alibaba.bucket_name)
            return bucket.sign_url(
                "GET", self.storage_file_id, 3600 * 24, headers={"content-disposition": "attachment"}, slash_safe=True
            )

        elif self.storage.type.code == "tencent":
            from qcloud_cos import CosConfig
            from qcloud_cos import CosS3Client

            config = CosConfig(
                Region=self.storage.storage_tencent.region.code,
                SecretId=bs_decrypt(self.storage.storage_tencent.access_key, encryption_key),
                SecretKey=bs_decrypt(self.storage.storage_tencent.secret_key, encryption_key),
                Scheme="https",
            )
            client = CosS3Client(config)
            return client.get_presigned_url(
                Method='GET',
                Bucket=self.storage.storage_tencent.bucket_name,
                Key=self.storage_file_id,
                Expired=24 * 3600
            )
        elif self.storage.type.code == "leviia":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_leviia.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_leviia.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_leviia.secret_key, encryption_key
                ),
                region_name="auto",
                config=Config(signature_version='s3v4')
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_leviia.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "idrive":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_idrive.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_idrive.access_key, encryption_key),
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_idrive.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_idrive.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "ionos":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_ionos.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_ionos.access_key, encryption_key),
                region_name=self.storage.storage_ionos.region.code,
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_ionos.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_ionos.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "rackcorp":
            s3_client = boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_rackcorp.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_rackcorp.access_key, encryption_key),
                region_name=self.storage.storage_rackcorp.region.code,
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_rackcorp.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_rackcorp.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response
        elif self.storage.type.code == "ibm":
            s3_client = ibm_boto3.client(
                "s3",
                endpoint_url=f"https://{self.storage.storage_ibm.endpoint}",
                aws_access_key_id=bs_decrypt(self.storage.storage_ibm.access_key, encryption_key),
                region_name=self.storage.storage_ibm.region.code,
                aws_secret_access_key=bs_decrypt(
                    self.storage.storage_ibm.secret_key, encryption_key
                ),
            )
            response = s3_client.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.storage.storage_ibm.bucket_name,
                    "Key": f"{self.storage_file_id}",
                },
                ExpiresIn=24 * 3600,
            )
            return response


    def delete_requested(self):

        self.status = self.Status.DELETE_REQUESTED
        self.save()

    def soft_delete(self):
        import boto3
        from ..log.models import CoreLog
        import subprocess

        encryption_key = self.storage.account.get_encryption_key()

        data = {
            "account_id": self.storage.account.id,
            "backup_uuid": self.backup.uuid_str,
            "storage_id": self.storage.id,
            "storage_type_id": self.storage.type.id,
            "storage_type_name": self.storage.type.name,
            "storage_name": self.storage.name,
        }

        try:
            if self.storage_file_id:
                if self.storage.type.code == "aws_s3":
                    s3_client = boto3.client(
                        "s3",
                        # self.storage.storage_aws_s3.region.code,
                        aws_access_key_id=bs_decrypt(self.storage.storage_aws_s3.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_aws_s3.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_aws_s3.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "do_spaces":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_do_spaces.region.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_do_spaces.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_do_spaces.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_do_spaces.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "filebase":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://s3.filebase.com",
                        aws_access_key_id=bs_decrypt(self.storage.storage_filebase.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_filebase.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_filebase.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "exoscale":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_exoscale.region.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_exoscale.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_exoscale.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_exoscale.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "oracle":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_oracle.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_oracle.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_oracle.secret_key, encryption_key),
                        region_name=self.storage.storage_oracle.region.code,
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_oracle.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "scaleway":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_scaleway.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_scaleway.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_scaleway.secret_key, encryption_key),
                        region_name=self.storage.storage_scaleway.region.code,
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_scaleway.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "backblaze_b2":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_backblaze_b2.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_backblaze_b2.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_backblaze_b2.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_backblaze_b2.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "linode":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_linode.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_linode.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_linode.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_linode.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "vultr":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_vultr.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_vultr.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_vultr.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_vultr.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "upcloud":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_upcloud.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_upcloud.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_upcloud.secret_key, encryption_key),
                        region_name=self.storage.storage_upcloud.endpoint.split(".")[1],
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_upcloud.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "cloudflare":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_cloudflare.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_cloudflare.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_cloudflare.secret_key, encryption_key),
                        region_name="auto",
                        config=Config(signature_version='s3v4')
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_cloudflare.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "wasabi":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_wasabi.region.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_wasabi.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_wasabi.secret_key, encryption_key),
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_wasabi.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "dropbox":
                    if self.storage_file_id:
                        dbx = dropbox.Dropbox(bs_decrypt(self.storage.storage_dropbox.access_token, encryption_key))
                        file_path = dbx.files_get_metadata(self.storage_file_id).path_lower
                        dbx.files_delete_v2(file_path)
                elif self.storage.type.code == "google_drive":
                    client = self.storage.storage_google_drive.get_client()
                    result = client.delete(
                        f"https://www.googleapis.com/drive/v3/files/{self.storage_file_id}",
                        headers={"Content-Type": "application/json; charset=UTF-8"},
                    )
                    if result.status_code == 204:
                        return True
                elif self.storage.type.code == "pcloud":
                    requests.post(
                        f"https://{self.storage.storage_pcloud.hostname}/deletefile?fileid={self.metadata.get('fileid')}",
                        headers=self.storage.storage_pcloud.get_client(),
                        verify=True,
                    )
                elif self.storage.type.code == "onedrive":
                    onedrive_path = f"{settings.MS_GRAPH_ENDPOINT}/drives/{self.storage.storage_onedrive.drive_id}/root:/{self.storage_file_id}"
                    requests.delete(onedrive_path, headers=self.storage.storage_onedrive.get_client())

                elif self.storage.type.code == "google_cloud":
                    from google.cloud import storage as gc_storage

                    storage_client = gc_storage.Client(credentials=self.storage.storage_google_cloud.get_credentials())
                    bucket = storage_client.bucket(self.storage.storage_google_cloud.bucket_name)

                    if bucket.exists():
                        blob = bucket.blob(self.storage_file_id)
                        if blob.exists():
                            blob.delete()

                elif self.storage.type.code == "azure":
                    import time
                    import datetime
                    from azure.storage.blob import BlobSasPermissions, generate_blob_sas
                    from datetime import timedelta

                    bucket_name = self.storage.storage_azure.bucket_name

                    blob_service_client = self.storage.storage_azure.get_client()
                    blob_client = blob_service_client.get_blob_client(container=bucket_name, blob=self.storage_file_id)
                    blob_client.delete_blob()

                elif self.storage.type.code == "alibaba":
                    import oss2

                    auth = oss2.Auth(
                        bs_decrypt(self.storage.storage_alibaba.access_key, encryption_key),
                        bs_decrypt(self.storage.storage_alibaba.secret_key, encryption_key),
                    )
                    bucket = oss2.Bucket(auth, f"https://{self.storage.storage_alibaba.endpoint}", self.storage.storage_alibaba.bucket_name)
                    bucket.delete_object(self.storage_file_id)

                elif self.storage.type.code == "tencent":
                    from qcloud_cos import CosConfig
                    from qcloud_cos import CosS3Client

                    config = CosConfig(
                        Region=self.storage.storage_tencent.region.code,
                        SecretId=bs_decrypt(self.storage.storage_tencent.access_key, encryption_key),
                        SecretKey=bs_decrypt(self.storage.storage_tencent.secret_key, encryption_key),
                        Scheme="https",
                    )
                    client = CosS3Client(config)

                    client.delete_object(Bucket=self.storage.storage_tencent.bucket_name, Key=self.storage_file_id)

                elif self.storage.type.code == "leviia":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_leviia.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_leviia.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_leviia.secret_key, encryption_key),
                        region_name="auto",
                        config=Config(signature_version='s3v4')
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_leviia.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "idrive":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_idrive.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_idrive.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_idrive.secret_key, encryption_key),
                        config=Config(signature_version='s3v4')
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_idrive.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "ionos":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_ionos.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_ionos.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_ionos.secret_key, encryption_key),
                        region_name=self.storage.storage_ionos.region.code,
                        config=Config(signature_version='s3v4')
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_ionos.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "rackcorp":
                    s3_client = boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_rackcorp.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_rackcorp.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_rackcorp.secret_key, encryption_key),
                        region_name=self.storage.storage_rackcorp.region.code,
                        config=Config(signature_version='s3v4')
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_rackcorp.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )
                elif self.storage.type.code == "ibm":
                    s3_client = ibm_boto3.client(
                        "s3",
                        endpoint_url=f"https://{self.storage.storage_ibm.endpoint}",
                        aws_access_key_id=bs_decrypt(self.storage.storage_ibm.access_key, encryption_key),
                        aws_secret_access_key=bs_decrypt(self.storage.storage_ibm.secret_key, encryption_key),
                        region_name=self.storage.storage_ibm.region.code,
                        config=Config(signature_version='s3v4')
                    )
                    s3_client.delete_object(
                        Bucket=self.storage.storage_ibm.bucket_name,
                        Key=f"{self.storage_file_id}",
                    )

                self.status = self.Status.DELETE_COMPLETED
                self.save()

            message = (
                f"Backup {self.backup.uuid_str} was deleted "
                f"from storage point {self.storage.name} - {self.storage.type.name}."
            )

            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)
        except SSHException as e:
            self.status = self.Status.DELETE_FAILED
            self.save()
            message = (
                f"Backup {self.backup.uuid_str} "
                f"unable to delete from storage point {self.storage.name} - {self.storage.type.name}. "
                f"Error: {e.__str__()}"
            )
            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)
        except NotFound as e:
            self.status = self.Status.DELETE_FAILED
            self.save()
            message = (
                f"Backup {self.backup.uuid_str} "
                f"unable to delete from storage point {self.storage.name} - {self.storage.type.name}. "
                f"Error: {e.__str__()}"
            )
            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)
        except Exception as e:
            capture_exception(e)
            self.status = self.Status.DELETE_FAILED
            self.save()

            message = (
                f"Backup {self.backup.uuid_str} "
                f"unable to delete from storage point {self.storage.name} - {self.storage.type.name}. "
                f"Error: {e.__str__()}"
            )
            self.storage.account.create_storage_log(message, self.backup.node, self.backup, self.storage)


class CoreWebsiteBackupStoragePoints(BaseBackupStoragePoints):
    class Status(models.IntegerChoices):
        UPLOAD_READY = 1, "Ready For Upload"
        UPLOAD_RETRY = 9, "Retrying Upload"
        UPLOAD_IN_PROGRESS = 2, "Upload In Progress"
        UPLOAD_COMPLETE = 3, "Upload Complete"
        UPLOAD_VALIDATION = 13, "Upload Validation"
        UPLOAD_FAILED = 4, "Upload Failed"
        UPLOAD_FAILED_STORAGE_LIMIT = 10, "Upload Failed - Storage Limit"
        UPLOAD_FAILED_FILE_NOT_FOUND = 11, "Upload Failed - File Not Found"
        UPLOAD_TIME_LIMIT_REACHED = 12, "Upload Failed - Time Limit Reached"
        DELETE_REQUESTED = 5, "Delete REQUESTED"
        DELETE_COMPLETED = 7, "Delete Completed"
        DELETE_FAILED = 8, "Delete Failed"
        CANCELLED = 6, "Cancelled"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"
        TRANSFERRED = 40, "Transferred"

    backup = models.ForeignKey(
        CoreWebsiteBackup,
        on_delete=models.CASCADE,
        related_name="stored_website_backups",
    )
    storage = models.ForeignKey(
        CoreStorage, on_delete=models.CASCADE, related_name="stored_website_backups"
    )

    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_website_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage", "status"],
                name="unique_stored_website_backups",
            ),
        ]


class CoreWordPressBackup(UtilBackup):
    UNZIP_REQUEST = Choices("requested", "in_progress", "available", "disable")
    wordpress = models.ForeignKey(
        "CoreWordPress", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="wordpress_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    size = models.BigIntegerField(null=True)
    zip_size = models.BigIntegerField(null=True)
    raw_size = models.BigIntegerField(null=True)
    total_files = models.BigIntegerField(null=True)
    total_folders = models.BigIntegerField(null=True)
    total_files_n_folders_calculated = models.BooleanField(null=True)
    excludes = models.JSONField(null=True)
    paths = models.JSONField(null=True)
    file_list_json = models.JSONField(null=True)
    file_list_path = models.JSONField(null=True)
    all_paths = models.BooleanField(null=True)
    unzip_request = StatusField(choices_name="UNZIP_REQUEST", default=None, null=True)
    unzip_sftp_time = models.BigIntegerField(null=True)
    unzip_sftp_docker = models.CharField(null=True, max_length=2048)
    unzip_sftp_user = models.CharField(null=True, max_length=2048)
    unzip_sftp_pass = models.CharField(null=True, max_length=2048)
    unzip_sftp_host = models.CharField(null=True, max_length=2048)
    unzip_sftp_port = models.IntegerField(null=True)
    unique_id = models.CharField(max_length=255, null=True)
    storage_points = models.ManyToManyField(
        CoreStorage,
        related_name="wordpress_backups",
        through="CoreWordPressBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_wordpress_backup"

    def soft_delete(self):
        for stored_wordpress_backup in self.stored_wordpress_backups.all():
            stored_wordpress_backup.soft_delete()
        self.status = self.Status.DELETE_COMPLETED
        self.save()

    def all_storage_points_uploaded(self):
        return self.stored_wordpress_backups.all().count() == self.stored_wordpress_backups.filter(
            status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE).count()

    def partial_storage_points_uploaded(self):
        return self.stored_wordpress_backups.filter(
            status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE).count() > 0

    def storage_points_uploaded(self):
        return self.stored_wordpress_backups.filter(
            status=CoreWordPressBackupStoragePoints.Status.UPLOAD_COMPLETE).count()


    @property
    def node(self):
        return self.wordpress.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        for stored_wordpress_backup in self.stored_wordpress_backups.all():
            stored_wordpress_backup.status = (
                CoreWordPressBackupStoragePoints.Status.CANCELLED
            )
            stored_wordpress_backup.save()
            app.control.revoke(stored_wordpress_backup.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Delete files
        """
        queue = f"delete_from_disk__{self.wordpress.node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
            queue=queue,
        )

        """
        Reset the node status
        """
        self.wordpress.node.backup_complete_reset()
        self.save()

        """
        Stop main docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )

        """
        Stop upload docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}-storage"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )

        """
        Delete files from wordpress
        """
        client = self.wordpress.node.connection.auth_wordpress.get_client()
        auth = self.wordpress.node.connection.auth_wordpress.get_auth()
        try:
            result = requests.get(
                f"{self.wordpress.node.connection.auth_wordpress.url}"
                f"/?rest_route=/backupsheep/updraftplus/files&backup_uuid={self.uuid_str}"
                f"&key={self.wordpress.node.connection.auth_wordpress.key}"
                f"&t={time.time()}",
                auth=auth,
                headers=client,
                verify=False,
                timeout=180,
            )
            if result.status_code == 200:
                try:
                    backup_files = result.json().get("files", [])
                    for backup_file in backup_files:
                        # delete the downloaded file from WordPress
                        r_delete = requests.get(
                            f"{self.wordpress.node.connection.auth_wordpress.url}"
                            f"/?rest_route=/backupsheep/updraftplus/delete&backup_file={backup_file}"
                            f"&backup_uuid={self.uuid_str}"
                            f"&key={self.wordpress.node.connection.auth_wordpress.key}"
                            f"&t={time.time()}",
                            allow_redirects=True,
                            auth=auth,
                            headers=client,
                            verify=False
                        )
                        if r_delete.status_code == 200:
                            if r_delete.json().get("deleted"):
                                msg = f"Cancelled backup - Deleted file from WordPress: {backup_file}"
                                self.wordpress.node.connection.account.create_backup_log(msg, self.wordpress.node, self)
                except Exception as e:
                    pass
        except Exception as e:
            pass


class CoreWordPressBackupStoragePoints(BaseBackupStoragePoints):
    class Status(models.IntegerChoices):
        UPLOAD_READY = 1, "Ready For Upload"
        UPLOAD_RETRY = 9, "Retrying Upload"
        UPLOAD_IN_PROGRESS = 2, "Upload In Progress"
        UPLOAD_COMPLETE = 3, "Upload Complete"
        UPLOAD_VALIDATION = 13, "Upload Validation"
        UPLOAD_FAILED = 4, "Upload Failed"
        UPLOAD_FAILED_STORAGE_LIMIT = 10, "Upload Failed - Storage Limit"
        UPLOAD_FAILED_FILE_NOT_FOUND = 11, "Upload Failed - File Not Found"
        UPLOAD_TIME_LIMIT_REACHED = 12, "Upload Failed - Time Limit Reached"
        DELETE_REQUESTED = 5, "Delete REQUESTED"
        DELETE_COMPLETED = 7, "Delete Completed"
        DELETE_FAILED = 8, "Delete Failed"
        CANCELLED = 6, "Cancelled"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"
        TRANSFERRED = 40, "Transferred"

    backup = models.ForeignKey(
        CoreWordPressBackup,
        on_delete=models.CASCADE,
        related_name="stored_wordpress_backups",
    )
    storage = models.ForeignKey(
        CoreStorage, on_delete=models.CASCADE, related_name="stored_wordpress_backups"
    )

    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_wordpress_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage", "status"],
                name="unique_stored_wordpress_backups",
            ),
        ]


class CoreBasecampBackup(UtilBackup):
    UNZIP_REQUEST = Choices("requested", "in_progress", "available", "disable")
    basecamp = models.ForeignKey("CoreBasecamp", related_name="backups", on_delete=models.CASCADE)
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="basecamp_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    size = models.BigIntegerField(null=True)
    zip_size = models.BigIntegerField(null=True)
    raw_size = models.BigIntegerField(null=True)
    total_files = models.BigIntegerField(null=True)
    total_folders = models.BigIntegerField(null=True)
    total_files_n_folders_calculated = models.BooleanField(null=True)
    projects = models.JSONField(null=True)
    file_list_json = models.JSONField(null=True)
    file_list_path = models.JSONField(null=True)
    all_paths = models.BooleanField(null=True)
    unique_id = models.CharField(max_length=255, null=True)
    storage_points = models.ManyToManyField(
        CoreStorage,
        related_name="basecamp_backups",
        through="CoreBasecampBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_basecamp_backup"

    def soft_delete(self):
        for stored_basecamp_backup in self.stored_basecamp_backups.all():
            stored_basecamp_backup.soft_delete()
        self.status = self.Status.DELETE_COMPLETED
        self.save()

    def all_storage_points_uploaded(self):
        return (
            self.stored_basecamp_backups.all().count()
            == self.stored_basecamp_backups.filter(
                status=CoreBasecampBackupStoragePoints.Status.UPLOAD_COMPLETE
            ).count()
        )

    def partial_storage_points_uploaded(self):
        return (
            self.stored_basecamp_backups.filter(status=CoreBasecampBackupStoragePoints.Status.UPLOAD_COMPLETE).count()
            > 0
        )

    def storage_points_uploaded(self):
        return self.stored_basecamp_backups.filter(
            status=CoreBasecampBackupStoragePoints.Status.UPLOAD_COMPLETE
        ).count()


    @property
    def node(self):
        return self.basecamp.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        for stored_basecamp_backup in self.stored_basecamp_backups.all():
            stored_basecamp_backup.status = CoreBasecampBackupStoragePoints.Status.CANCELLED
            stored_basecamp_backup.save()
            app.control.revoke(stored_basecamp_backup.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Delete files
        """
        queue = f"delete_from_disk__{self.basecamp.node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
            queue=queue,
        )

        """
        Reset the node status
        """
        self.basecamp.node.backup_complete_reset()
        self.save()

        """
        Stop main docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )

        """
        Stop upload docker container if any
        """
        execstr = f"sudo docker stop {self.uuid_str}-storage"
        subprocess.run(
            execstr,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
            timeout=60,
        )


class CoreBasecampBackupStoragePoints(BaseBackupStoragePoints):
    class Status(models.IntegerChoices):
        UPLOAD_READY = 1, "Ready For Upload"
        UPLOAD_RETRY = 9, "Retrying Upload"
        UPLOAD_IN_PROGRESS = 2, "Upload In Progress"
        UPLOAD_COMPLETE = 3, "Upload Complete"
        UPLOAD_VALIDATION = 13, "Upload Validation"
        UPLOAD_FAILED = 4, "Upload Failed"
        UPLOAD_FAILED_STORAGE_LIMIT = 10, "Upload Failed - Storage Limit"
        UPLOAD_FAILED_FILE_NOT_FOUND = 11, "Upload Failed - File Not Found"
        UPLOAD_TIME_LIMIT_REACHED = 12, "Upload Failed - Time Limit Reached"
        DELETE_REQUESTED = 5, "Delete REQUESTED"
        DELETE_COMPLETED = 7, "Delete Completed"
        DELETE_FAILED = 8, "Delete Failed"
        CANCELLED = 6, "Cancelled"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"
        TRANSFERRED = 40, "Transferred"

    backup = models.ForeignKey(
        CoreBasecampBackup,
        on_delete=models.CASCADE,
        related_name="stored_basecamp_backups",
    )
    storage = models.ForeignKey(CoreStorage, on_delete=models.CASCADE, related_name="stored_basecamp_backups")

    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_basecamp_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage", "status"],
                name="unique_stored_basecamp_backups",
            ),
        ]


class CoreDatabaseBackupLegacy(models.Model):
    storage_id = models.IntegerField(null=True)

    class Meta:
        db_table = "core_database_backup"
        managed = False


class CoreHostingBackupLegacy(models.Model):
    storage_id = models.IntegerField(null=True)

    class Meta:
        db_table = "core_hosting_backup"
        managed = False


class CoreDatabaseBackup(UtilBackup):
    database = models.ForeignKey(
        "CoreDatabase", related_name="backups", on_delete=models.CASCADE
    )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="database_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    size = models.BigIntegerField(null=True)
    tables = models.JSONField(null=True)
    all_tables = models.BooleanField(null=True)
    all_databases = models.BooleanField(null=True)
    storage_points = models.ManyToManyField(
        CoreStorage,
        related_name="database_backups",
        through="CoreDatabaseBackupStoragePoints",
    )
    metadata = models.JSONField(null=True)
    option_postgres = models.TextField(null=True, blank=True)
    option_mysql = models.TextField(null=True, blank=True)
    option_mariadb = models.TextField(null=True, blank=True)
    option_mongodb = models.TextField(null=True, blank=True)

    class Meta:
        db_table = "core_database_backup"

    def all_storage_points_uploaded(self):
        return self.stored_database_backups.all().count() == self.stored_database_backups.filter(
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE).count()

    def partial_storage_points_uploaded(self):
        return self.stored_database_backups.filter(
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE).count() > 0

    def storage_points_uploaded(self):
        return self.stored_database_backups.filter(
            status=CoreDatabaseBackupStoragePoints.Status.UPLOAD_COMPLETE).count()


    def soft_delete(self):
        for stored_database_backup in self.stored_database_backups.all():
            stored_database_backup.soft_delete()
        self.status = self.Status.DELETE_COMPLETED
        self.save()

    @property
    def node(self):
        return self.database.node

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        First cancel the storage point uploads
        """
        for stored_database_backup in self.stored_database_backups.all():
            stored_database_backup.status = (
                CoreDatabaseBackupStoragePoints.Status.CANCELLED
            )
            stored_database_backup.save()
            app.control.revoke(stored_database_backup.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Delete files
        """
        queue = f"delete_from_disk__{self.database.node.connection.location.queue}"
        delete_from_disk.apply_async(
            args=[self.uuid_str, "both"],
            queue=queue,
        )

        """
        Reset the node status
        """
        self.database.node.backup_complete_reset()
        self.save()


class CoreDatabaseBackupStoragePoints(BaseBackupStoragePoints):
    class Status(models.IntegerChoices):
        UPLOAD_READY = 1, "Ready For Upload"
        UPLOAD_RETRY = 9, "Retrying Upload"
        UPLOAD_IN_PROGRESS = 2, "Upload In Progress"
        UPLOAD_COMPLETE = 3, "Upload Complete"
        UPLOAD_VALIDATION = 15, "Upload Validation"
        UPLOAD_FAILED = 4, "Upload Failed"
        UPLOAD_FAILED_STORAGE_LIMIT = 10, "Upload Failed - Storage Limit"
        UPLOAD_FAILED_FILE_NOT_FOUND = 11, "Upload Failed - File Not Found"
        UPLOAD_TIME_LIMIT_REACHED = 14, "Upload Failed - Time Limit Reached"
        DELETE_REQUESTED = 12, "Delete REQUESTED"
        CANCELLED = 13, "Cancelled"
        DELETE_COMPLETED = 7, "Delete Completed"
        DELETE_FAILED = 8, "Delete Failed"
        STORAGE_VALIDATION_FAILED = 30, "Storage Validation Failed"
        TRANSFERRED = 40, "Transferred"

    backup = models.ForeignKey(
        CoreDatabaseBackup,
        on_delete=models.CASCADE,
        related_name="stored_database_backups",
    )
    storage = models.ForeignKey(
        CoreStorage, on_delete=models.CASCADE, related_name="stored_database_backups"
    )
    status = models.IntegerField(choices=Status.choices, default=Status.UPLOAD_READY)
    storage_file_id = models.CharField(max_length=255, null=True)
    celery_task_id = models.CharField(max_length=255, null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_database_backup_mtm_storage_points"
        constraints = [
            UniqueConstraint(
                fields=["backup", "storage", "status"],
                name="unique_stored_database_backups",
            ),
        ]


class CoreAWSBackup(UtilBackup):
    aws = models.ForeignKey("CoreAWS", related_name="backups", on_delete=models.CASCADE)
    # old_status = models.ForeignKey(
    #     CoreAWSBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="aws_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule", related_name="aws_backups", null=True, on_delete=models.SET_NULL
    )
    region = models.CharField(max_length=255, null=True)
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.CLOUD == self.aws.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.aws.node, self.uuid_str, self.attempt_no, self.type, "AWS returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.aws.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.aws.node.connection.auth_aws.get_client()
                    if (
                            len(client.describe_images(ImageIds=[self.unique_id])["Images"])
                            > 0
                    ):
                        new_image = client.describe_images(ImageIds=[self.unique_id])[
                            "Images"
                        ][0]
                        if new_image["State"] == "available":
                            backup_status = UtilBackup.Status.COMPLETE
                            """
                            Snapshot is good. So we can save size now
                            """
                            size_gigabytes = 0
                            if new_image:
                                for device in new_image["BlockDeviceMappings"]:
                                    if device.get("Ebs", None):
                                        size_gigabytes += device["Ebs"]["VolumeSize"]
                            self.size_gigabytes = size_gigabytes
                        elif (
                                new_image["State"] == "failed"
                                or new_image["State"] == "error"
                                or new_image["State"] == "invalid"
                        ):
                            client.deregister_image(ImageId=self.unique_id)
                            backup_status = UtilBackup.Status.FAILED
                        self.status = backup_status
                        self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1
        elif CoreNode.Type.VOLUME == self.aws.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.aws.node, self.uuid_str, self.attempt_no, self.type, "AWS returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.aws.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.aws.node.connection.auth_aws.get_client()
                    new_snapshot = client.describe_snapshots(
                        SnapshotIds=[self.unique_id]
                    )["Snapshots"][0]

                    if new_snapshot["State"] == "completed":
                        backup_status = UtilBackup.Status.COMPLETE
                        """
                        Snapshot is good. So we can save size now
                        """
                        volume_size = new_snapshot["VolumeSize"]
                        self.size_gigabytes = volume_size
                    elif new_snapshot["State"] == "error":
                        client.delete_snapshot(SnapshotId=self.unique_id)
                        backup_status = UtilBackup.Status.FAILED
                    self.status = backup_status
                    self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.aws.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.aws.node.connection.auth_aws.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.aws.node.name} "
            f"is being deleted using connection {self.aws.node.connection.name}"
        )

        try:
            if CoreNode.Type.CLOUD == self.aws.node.type:
                image_to_delete = client.describe_images(ImageIds=[self.unique_id])[
                    "Images"
                ][0]
                client.deregister_image(ImageId=self.unique_id)
                time.sleep(60)
                snapshots_to_delete = image_to_delete["BlockDeviceMappings"]

                for snapshot in snapshots_to_delete:
                    snapshots_to_delete_id = snapshot["Ebs"]["SnapshotId"]
                    client.delete_snapshot(SnapshotId=snapshots_to_delete_id)
            elif CoreNode.Type.VOLUME == self.aws.node.type:
                client.delete_snapshot(SnapshotId=self.unique_id)

            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.aws.node.name} "
                f"deleted successfully using connection {self.aws.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.aws.node.name} "
                f"failed to using connection {self.aws.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.aws.node.connection.account.create_backup_log(msg, self.aws.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.aws.node.backup_complete_reset()


class CoreLightsailBackup(UtilBackup):
    lightsail = models.ForeignKey(
        "CoreLightsail", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreLightsailBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="lightsail_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="lightsail_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    region = models.CharField(max_length=255, null=True)
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_lightsail_backup"

    def validate(self):
        from ..node.models import CoreNode

        if CoreNode.Type.CLOUD == self.lightsail.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.lightsail.node, self.uuid_str, self.attempt_no, self.type, "Lightssail returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.lightsail.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.lightsail.node.connection.auth_lightsail.get_client()
                    response = client.get_instance_snapshot(
                        instanceSnapshotName=self.unique_id
                    )
                    if response.get("instanceSnapshot"):
                        snapshot = response["instanceSnapshot"]
                        if snapshot["state"] == "available":
                            backup_status = UtilBackup.Status.COMPLETE
                            self.size_gigabytes = snapshot["sizeInGb"]
                        elif snapshot["state"] == "error":
                            backup_status = UtilBackup.Status.FAILED
                    self.status = backup_status
                    self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1
        elif CoreNode.Type.VOLUME == self.lightsail.node.type:
            backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter = 0
            while backup_status != UtilBackup.Status.COMPLETE:
                if backup_status == UtilBackup.Status.FAILED:
                    raise NodeBackupFailedError(self.lightsail.node, self.uuid_str, self.attempt_no, self.type, "Lightsail returned snapshot status as error.")
                elif check_counter > 720:
                    raise NodeBackupStatusCheckTimeOutError(
                        self.lightsail.node, self.uuid_str
                    )
                time.sleep(60)
                try:
                    client = self.lightsail.node.connection.auth_lightsail.get_client()
                    response = client.get_disk_snapshot(diskSnapshotName=self.unique_id)
                    if response.get("diskSnapshot"):
                        snapshot = response["diskSnapshot"]
                        if snapshot["state"] == "available":
                            backup_status = UtilBackup.Status.COMPLETE
                            self.size_gigabytes = snapshot["sizeInGb"]
                        elif snapshot["state"] == "error":
                            backup_status = UtilBackup.Status.FAILED
                    self.status = backup_status
                    self.save()
                except Exception as e:
                    backup_status = UtilBackup.Status.IN_PROGRESS
                check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.lightsail.node

    def soft_delete(self):
        from ..node.models import CoreNode

        client = self.lightsail.node.connection.auth_lightsail.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.lightsail.node.name} "
            f"is being deleted using connection {self.lightsail.node.connection.name}"
        )

        try:
            if CoreNode.Type.CLOUD == self.lightsail.node.type:
                client.delete_instance_snapshot(instanceSnapshotName=self.unique_id)
            elif CoreNode.Type.VOLUME == self.lightsail.node.type:
                client.delete_disk_snapshot(diskSnapshotName=self.unique_id)

            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.lightsail.node.name} "
                f"deleted successfully using connection {self.lightsail.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.lightsail.node.name} "
                f"failed to using connection {self.lightsail.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.lightsail.node.connection.account.create_backup_log(msg, self.lightsail.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.lightsail.node.backup_complete_reset()


class CoreAWSRDSBackup(UtilBackup):
    aws_rds = models.ForeignKey(
        "CoreAWSRDS", related_name="backups", on_delete=models.CASCADE
    )
    # old_status = models.ForeignKey(
    #     CoreAWSRDSBackupStatus, related_name="backups", on_delete=models.PROTECT
    # )
    # old_type = models.ForeignKey(
    #     CoreBackupType, related_name="aws_rds_backups", on_delete=models.PROTECT
    # )
    schedule = models.ForeignKey(
        "CoreSchedule",
        related_name="aws_rds_backups",
        null=True,
        on_delete=models.SET_NULL,
    )
    region = models.CharField(max_length=255, null=True)
    unique_id = models.CharField(max_length=64)
    size_gigabytes = models.FloatField(null=True)
    metadata = models.JSONField(null=True)

    class Meta:
        db_table = "core_aws_rds_backup"

    def validate(self):
        backup_status = UtilBackup.Status.IN_PROGRESS
        check_counter = 0
        while backup_status != UtilBackup.Status.COMPLETE:
            if backup_status == UtilBackup.Status.FAILED:
                raise NodeBackupFailedError(self.aws_rds.node, self.uuid_str, self.attempt_no, self.type, "AWS RDS returned snapshot status as error.")
            elif check_counter > 720:
                raise NodeBackupStatusCheckTimeOutError(
                    self.aws_rds.node, self.uuid_str
                )
            time.sleep(60)
            try:
                client = self.aws_rds.node.connection.auth_aws_rds.get_client()
                result = client.describe_db_snapshots(
                    DBSnapshotIdentifier=str(self.uuid_str),
                    DBInstanceIdentifier=self.unique_id,
                )
                if len(result["DBSnapshots"]) > 0:
                    if result["DBSnapshots"][0]["Status"] == "available":
                        backup_status = UtilBackup.Status.COMPLETE
                    elif result["DBSnapshots"][0]["Status"] == "failed":
                        backup_status = UtilBackup.Status.FAILED
                    self.status = backup_status
                    self.save()
            except Exception as e:
                backup_status = UtilBackup.Status.IN_PROGRESS
            check_counter += 1

    def delete_requested(self):
        self.status = self.Status.DELETE_REQUESTED
        self.save()

    @property
    def node(self):
        return self.aws_rds.node

    def soft_delete(self):
        client = self.aws_rds.node.connection.auth_aws_rds.get_client()

        msg = (
            f"Backup {self.uuid_str} of node {self.aws_rds.node.name} "
            f"is being deleted using connection {self.aws_rds.node.connection.name}"
        )

        try:
            client.delete_dbsnapshot(identifier=self.unique_id)
            self.status = UtilBackup.Status.DELETE_COMPLETED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.aws_rds.node.name} "
                f"deleted successfully using connection {self.aws_rds.node.connection.name}"
            )
        except Exception as e:
            self.status = UtilBackup.Status.DELETE_FAILED
            self.save()
            msg = (
                f"Backup {self.uuid_str} of node {self.aws_rds.node.name} "
                f"failed to using connection {self.aws_rds.node.connection.name}. Error: {e.__str__()}"
            )
        finally:
            self.aws_rds.node.connection.account.create_backup_log(msg, self.aws_rds.node, self)

    def cancel(self):
        app.control.revoke(self.celery_task_id, terminate=True)

        """
        Set backup status to cancelled
        """
        self.status = self.Status.CANCELLED
        self.save()

        """
        Reset the node status
        """
        self.aws_rds.node.backup_complete_reset()
