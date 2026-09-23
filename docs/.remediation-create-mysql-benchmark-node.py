from django.db import transaction

from apps.console.node.models import CoreDatabase, CoreNode


RUN_ID = "bs-remed-20260818-0d08dcf"
SOURCE_NODE_ID = 103
BENCHMARK_NODE_NAME = f"{RUN_ID} MySQL 1M row benchmark"


source = CoreNode.objects.select_related("database", "connection").get(
    pk=SOURCE_NODE_ID
)

with transaction.atomic():
    benchmark = (
        CoreNode.objects.select_for_update()
        .filter(connection_id=source.connection_id, name=BENCHMARK_NODE_NAME)
        .first()
    )
    created = benchmark is None
    if created:
        benchmark = CoreNode.objects.create(
            connection_id=source.connection_id,
            status=CoreNode.Status.ACTIVE,
            type=CoreNode.Type.DATABASE,
            name=BENCHMARK_NODE_NAME,
            notify_on_success=False,
            notify_on_fail=False,
            email_data=None,
            timezone=source.timezone,
            added_by_id=source.added_by_id,
        )
        original = source.database
        CoreDatabase.objects.create(
            node=benchmark,
            name=BENCHMARK_NODE_NAME,
            tables=original.tables,
            all_tables=original.all_tables,
            databases=original.databases,
            all_databases=original.all_databases,
            option_single_transaction=original.option_single_transaction,
            option_skip_opt=True,
            option_compress=original.option_compress,
            option_gtid_purged_off=original.option_gtid_purged_off,
            option_postgres_format_custom=original.option_postgres_format_custom,
            notes=(
                f"Owned benchmark fixture {RUN_ID}; same source as node "
                f"{SOURCE_NODE_ID}; deliberate historical --skip-opt format."
            ),
            option_postgres=original.option_postgres,
            option_mysql=original.option_mysql,
            option_mariadb=original.option_mariadb,
            option_mongodb=original.option_mongodb,
        )

    benchmark.refresh_from_db()
    database = benchmark.database
    expected = {
        "connection_id": source.connection_id,
        "status": CoreNode.Status.ACTIVE,
        "type": CoreNode.Type.DATABASE,
        "all_tables": source.database.all_tables,
        "all_databases": source.database.all_databases,
        "tables": source.database.tables,
        "databases": source.database.databases,
        "option_single_transaction": source.database.option_single_transaction,
        "option_skip_opt": True,
        "option_compress": source.database.option_compress,
    }
    actual = {
        "connection_id": benchmark.connection_id,
        "status": benchmark.status,
        "type": benchmark.type,
        "all_tables": database.all_tables,
        "all_databases": database.all_databases,
        "tables": database.tables,
        "databases": database.databases,
        "option_single_transaction": database.option_single_transaction,
        "option_skip_opt": database.option_skip_opt,
        "option_compress": database.option_compress,
    }
    if actual != expected:
        raise RuntimeError(
            f"Refusing mismatched benchmark node: expected={expected!r} actual={actual!r}"
        )

print(
    {
        "run_id": RUN_ID,
        "result": "exact-owned MySQL benchmark node is ready",
        "option_skip_opt": True,
    }
)
