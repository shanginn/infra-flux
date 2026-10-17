"""One real Sentry SDK exception through local HTTP, then durable DB readback.

Run explicitly inside a web Pod after bootstrap. Public HTTPS/auth checks are
separate acceptance checks. This script never prints a DSN or a credential.
"""
import json
import os
import time
import uuid

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "infra_settings")
import django
django.setup()
import sentry_sdk
from apps.projects.models import Project, ProjectKey
from apps.issue_events.models import IssueEvent
from infra_support import check_database

check_database()
project = Project.objects.get(organization__slug="unified", slug="platform-canary")
key = ProjectKey.objects.get(project=project, is_active=True)
run = uuid.uuid4().hex
with sentry_sdk.init(dsn=f"http://{key.public_key.hex}@127.0.0.1:8000/{project.id}",
                     default_integrations=False, send_default_pii=False,
                     sample_rate=1.0, traces_sample_rate=0.0,
                     auto_session_tracking=False):
    try:
        raise RuntimeError("Infrastructure error-tracking canary " + run)
    except RuntimeError as error:
        event_id = sentry_sdk.capture_exception(error)
    sentry_sdk.flush(timeout=10)
if not event_id:
    raise RuntimeError("Sentry SDK did not create an event ID")
deadline = time.monotonic() + 90
while time.monotonic() < deadline:
    event = IssueEvent.objects.filter(event_id=uuid.UUID(event_id),
        organization_id=project.organization_id, issue__project_id=project.id).first()
    if event is not None:
        if run not in event.title:
            raise RuntimeError("unexpected stored canary title")
        print(json.dumps({"success": True, "event_id": event_id, "issue_id": event.issue_id,
                          "project": project.slug, "stored": True}))
        break
    time.sleep(2)
else:
    raise RuntimeError("event accepted by SDK but storage/worker proof timed out")
