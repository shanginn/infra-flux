"""Shared TLS/identity checks and private capacity metrics."""
from asgiref.sync import sync_to_async
from django.conf import settings
from django.db import connection
from django.utils.decorators import async_only_middleware


def check_database():
    cfg = settings.DATABASES["default"]
    opts = cfg.get("OPTIONS", {})
    if not (cfg["NAME"] == cfg["USER"] == "glitchtip"
            and cfg["HOST"] == "unified-postgres.database.svc"
            and opts.get("sslmode") == "verify-full"
            and opts.get("sslrootcert") == "/etc/postgresql/ca.crt"):
        raise RuntimeError("unexpected database identity or TLS configuration")
    with connection.cursor() as cur:
        cur.execute("SELECT current_database(), current_user, pg_is_in_recovery(), "
                    "(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())")
        if cur.fetchone() != ("glitchtip", "glitchtip", False, True):
            raise RuntimeError("database identity/TLS/primary check failed")


def guard_state():
    with connection.cursor() as cur:
        cur.execute("SELECT last_success, latched, database_bytes, threshold_bytes, "
                    "closed_organizations FROM infra_capacity_guard WHERE id=true")
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("capacity guard has not been initialized")
    return row


@async_only_middleware
def capacity_metrics(get_response):
    async def middleware(request):
        response = await get_response(request)
        if request.path == "/metrics" and response.status_code == 200:
            state = await sync_to_async(guard_state, thread_sensitive=True)()
            names = ("last_success_timestamp_seconds", "latched", "database_bytes",
                     "threshold_bytes", "closed_organizations")
            lines = []
            for name, value in zip(names, state):
                metric = "glitchtip_capacity_guard_" + name
                lines += [f"# TYPE {metric} gauge", f"{metric} {float(value)}"]
            response.content += ("\n" + "\n".join(lines) + "\n").encode()
            if response.has_header("Content-Length"):
                del response["Content-Length"]
        return response
    return middleware
