"""Latch ingestion closed at the soft DB threshold; never delete or reopen."""
import json
import os
import time

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "infra_settings")
import django
django.setup()
from django.db import connection, transaction
from apps.organizations_ext.models import Organization
from infra_support import check_database

check_database()
threshold = int(os.environ["GLITCHTIP_CAPACITY_BYTES"])
if threshold != 2 * 1024**3:
    raise RuntimeError("threshold changes require explicit code/config review")
with transaction.atomic(), connection.cursor() as cur:
    cur.execute("SET LOCAL statement_timeout='15s'")
    cur.execute("SET LOCAL lock_timeout='5s'")
    cur.execute("SELECT latched, threshold_bytes FROM infra_capacity_guard "
                "WHERE id=true FOR UPDATE")
    state = cur.fetchone()
    if not state or state[1] != threshold:
        raise RuntimeError("capacity guard state is absent or changed")
    cur.execute("SELECT pg_database_size(current_database())")
    size = cur.fetchone()[0]
    latched = state[0] or size >= threshold
    changed = 0
    if latched:
        changed = Organization.objects.filter(is_accepting_events=True).update(
            is_accepting_events=False)
    closed = Organization.objects.filter(is_accepting_events=False).count()
    cur.execute("UPDATE infra_capacity_guard SET last_success=%s,latched=%s,"
                "database_bytes=%s,closed_organizations=%s WHERE id=true",
                [time.time(), latched, size, closed])
print(json.dumps({"success": True, "latched": latched, "database_bytes": size,
                  "closed_organizations": closed, "newly_closed": changed}))
