"""Fail closed before serving: migrated schema, guard table and first admin."""
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "infra_settings")
import django
django.setup()
from django.contrib.auth import get_user_model
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from infra_support import check_database, guard_state

check_database()
executor = MigrationExecutor(connection)
if executor.migration_plan(executor.loader.graph.leaf_nodes()):
    raise RuntimeError("reviewed migration Job must finish before application startup")
guard_state()
if not get_user_model().objects.filter(
        email=os.environ["GLITCHTIP_BOOTSTRAP_ADMIN_EMAIL"], is_superuser=True,
        is_staff=True, is_active=True).exists():
    raise RuntimeError("first administrator must exist before web/worker startup")
print("schema, TLS and first administrator ready")
