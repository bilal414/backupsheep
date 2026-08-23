"""Create the exact-owned MySQL 5M connection and database node."""

import json

from django.db import transaction

from apps.console.connection.models import CoreAuthDatabase, CoreConnection
from apps.console.node.models import CoreDatabase, CoreNode


RUN_ID = "bs-remed-20260818-0d08dcf"
NAME = f"{RUN_ID} MySQL 5M scale"
DATABASE_NAME = "bs_remed_mysql_lg5_0d08dcf"
SOURCE_CONNECTION_ID = 75
SOURCE_NODE_ID = 103


source_connection = CoreConnection.objects.select_related(
    "account", "integration", "location", "added_by", "auth_database"
).get(pk=SOURCE_CONNECTION_ID)
source_auth = source_connection.auth_database
source_node = CoreNode.objects.select_related("database").get(pk=SOURCE_NODE_ID)
if source_node.connection_id != SOURCE_CONNECTION_ID:
    raise RuntimeError("the retained MySQL 1M source identity changed")

with transaction.atomic():
    connection = CoreConnection.objects.filter(
        account=source_connection.account,
        integration=source_connection.integration,
        name=NAME,
    ).first()
    connection_created = connection is None
    if connection is None:
        connection = CoreConnection.objects.create(
            account=source_connection.account,
            old_status=source_connection.old_status,
            status=CoreConnection.Status.ACTIVE,
            notification=source_connection.notification,
            integration=source_connection.integration,
            location=source_connection.location,
            name=NAME,
            notes=f"Exact-owned {RUN_ID} MySQL 5M/larger acceptance connection.",
            added_by=source_connection.added_by,
        )
        CoreAuthDatabase.objects.create(
            connection=connection,
            host="bs-remed-mysql84-scale-tunnel",
            port=3309,
            database_name=DATABASE_NAME,
            all_databases=False,
            username=source_auth.username,
            password=source_auth.password,
            type=source_auth.type,
            version=source_auth.version,
            include_stored_procedure=source_auth.include_stored_procedure,
            use_ssl=True,
            info_name=NAME,
            ssh_username=None,
            ssh_password=None,
            ssh_port=None,
            ssh_host=None,
            use_public_key=False,
            use_private_key=False,
            private_key=None,
            encryption_updated=source_auth.encryption_updated,
            flag_use_sha1_key_verification=False,
        )

    auth = connection.auth_database
    if (
        auth.host != "bs-remed-mysql84-scale-tunnel"
        or auth.port != 3309
        or auth.database_name != DATABASE_NAME
        or not auth.use_ssl
    ):
        raise RuntimeError("the existing exact-owned MySQL scale connection changed")

    node = CoreNode.objects.filter(connection=connection, name=NAME).first()
    node_created = node is None
    if node is None:
        node = CoreNode.objects.create(
            connection=connection,
            status=CoreNode.Status.ACTIVE,
            type=CoreNode.Type.DATABASE,
            name=NAME,
            notify_on_success=False,
            notify_on_fail=False,
            timezone="UTC",
            added_by=source_node.added_by,
        )
        CoreDatabase.objects.create(
            node=node,
            name=NAME,
            tables=[],
            all_tables=True,
            databases=[DATABASE_NAME],
            all_databases=False,
            option_single_transaction=True,
            option_skip_opt=False,
            option_compress=True,
            option_gtid_purged_off=True,
            option_postgres_format_custom=False,
            notes=f"Exact-owned {RUN_ID} MySQL 5M/larger acceptance source.",
            option_postgres=None,
            option_mysql=source_node.database.option_mysql,
            option_mariadb=None,
            option_mongodb=None,
        )

validation = connection.validate(check_errors=True, raise_exp=True)
print(
    json.dumps(
        {
            "connection_created": connection_created,
            "connection_id": connection.pk,
            "node_created": node_created,
            "node_id": node.pk,
            "database_id": node.database.pk,
            "name": node.name,
            "host": connection.auth_database.host,
            "port": connection.auth_database.port,
            "database_name": connection.auth_database.database_name,
            "use_ssl": connection.auth_database.use_ssl,
            "option_skip_opt": node.database.option_skip_opt,
            "validation": validation,
        },
        sort_keys=True,
    )
)
