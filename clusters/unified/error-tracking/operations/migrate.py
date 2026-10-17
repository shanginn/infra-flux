"""Run explicitly once per reviewed image upgrade, never on web startup."""
import os
import subprocess

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "infra_settings")
import django
django.setup()
from django.db import connection, transaction
from infra_support import check_database

check_database()
# A transaction pins the native driver's connection while children migrate.
with transaction.atomic(), connection.cursor() as cur:
    # The dedicated role otherwise has a 60s idle-transaction timeout. Child
    # migrations may legitimately run longer; this transaction only owns a lock.
    cur.execute("SET LOCAL idle_in_transaction_session_timeout='900s'")
    cur.execute("SELECT pg_try_advisory_xact_lock(723666, 626)")
    if not cur.fetchone()[0]:
        raise RuntimeError("another GlitchTip migration owns the lock")
    subprocess.run(["./bin/run-migrate.sh"], check=True, timeout=780)
    cur.execute("""CREATE TABLE IF NOT EXISTS infra_capacity_guard (
        id boolean PRIMARY KEY CHECK(id),
        latched boolean NOT NULL DEFAULT false,
        last_success double precision NOT NULL DEFAULT 0,
        database_bytes bigint NOT NULL DEFAULT 0,
        threshold_bytes bigint NOT NULL,
        closed_organizations bigint NOT NULL DEFAULT 0)""")
    cur.execute("INSERT INTO infra_capacity_guard(id,threshold_bytes) "
                "VALUES(true,%s) ON CONFLICT(id) DO NOTHING",
                [int(os.environ["GLITCHTIP_CAPACITY_BYTES"])])
print("migration and capacity schema completed", flush=True)
subprocess.run(["python", "/opt/infra/bootstrap.py", "--from-files"], check=True, timeout=60)
