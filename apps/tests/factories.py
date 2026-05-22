"""Factory helpers for the account -> connection -> node graph that nearly every test
needs. Reference data (integrations, storage types, regions) is seeded by migration
0007, so it's available in the test database.
"""
import itertools

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model

from apps.api.v1.utils.api_helpers import bs_encrypt
from apps.console.account.models import CoreAccount
from apps.console.connection.models import (
    CoreAuthWebsite,
    CoreConnection,
    CoreConnectionLocation,
    CoreIntegration,
)
from apps.console.member.models import CoreMember, CoreMemberAccount
from apps.console.node.models import (
    CoreDigitalOcean,
    CoreNode,
    CoreSchedule,
    CoreWebsite,
)
from apps.console.storage.models import CoreStorage, CoreStorageAWSS3, CoreStorageType

User = get_user_model()
_seq = itertools.count(1)


def make_account(email=None):
    """Create the full owner chain: User -> CoreMember -> CoreAccount (with a real
    Fernet key) -> primary CoreMemberAccount. Returns (account, member, user)."""
    n = next(_seq)
    email = email or f"user{n}@example.com"
    user = User.objects.create_user(username=email, email=email, password="x-Secret-123")
    member = CoreMember.objects.create(user=user, timezone="UTC")
    account = CoreAccount.objects.create(name=f"Account {n}", encryption_key=Fernet.generate_key())
    CoreMemberAccount.objects.create(
        member=member, account=account,
        status=CoreMemberAccount.Status.ACTIVE, current=True, primary=True,
    )
    return account, member, user


def make_location(code="test-loc"):
    loc, _ = CoreConnectionLocation.objects.get_or_create(code=code)
    return loc


def make_connection(account, member, code="website", name=None):
    integration = CoreIntegration.objects.get(code=code)
    return CoreConnection.objects.create(
        account=account, integration=integration, location=make_location(),
        name=name or f"{code}-conn", added_by=member,
    )


def make_website_node(account, member, *, host="ftp.example.com", protocol=None,
                      all_paths=True):
    conn = make_connection(account, member, code="website")
    key = account.get_encryption_key()
    CoreAuthWebsite.objects.create(
        connection=conn,
        host=host, port=21,
        protocol=protocol or CoreAuthWebsite.Protocol.FTP,
        username=bs_encrypt("u", key), password=bs_encrypt("p", key),
        verify_ssl=True,
    )
    node = CoreNode.objects.create(connection=conn, type=CoreNode.Type.WEBSITE,
                                   name="site", added_by=member)
    CoreWebsite.objects.create(node=node, name="site", all_paths=all_paths)
    return node


def make_cloud_node(account, member, *, code="digitalocean", node_type=None):
    conn = make_connection(account, member, code=code)
    node = CoreNode.objects.create(
        connection=conn, type=node_type or CoreNode.Type.CLOUD, name="server", added_by=member,
    )
    # digitalocean is the cloud provider used across the backup-engine tests
    CoreDigitalOcean.objects.create(node=node, name="server", unique_id="droplet-1")
    return node


def make_storage(account, member, *, code="aws_s3", bucket="test-bucket"):
    storage = CoreStorage.objects.create(
        account=account, type=CoreStorageType.objects.get(code=code),
        name=f"{code}-store", added_by=member,
    )
    if code == "aws_s3":
        CoreStorageAWSS3.objects.create(storage=storage, bucket_name=bucket)
    return storage


def make_schedule(node, member, *, keep_last=None, storages=(), status=None):
    schedule = CoreSchedule.objects.create(
        node=node, name="daily", timezone="UTC", added_by=member,
        type="cron", keep_last=keep_last,
        status=status if status is not None else CoreSchedule.Status.ACTIVE,
    )
    for s in storages:
        schedule.storage_points.add(s)
    return schedule
