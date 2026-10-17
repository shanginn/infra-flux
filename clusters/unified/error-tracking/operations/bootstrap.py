"""Create the first administrator/org/canary atomically, credentials on stdin."""
import json
import os
import sys
from pathlib import Path

if sys.argv[1:] == ["--from-files"]:
    payload = {k: Path("/etc/glitchtip-bootstrap", k).read_text().strip()
               for k in ("email", "password")}
elif not sys.argv[1:]:
    payload = json.loads(sys.stdin.buffer.read(8193))
else:
    raise RuntimeError("unsupported bootstrap arguments")
if set(payload) != {"email", "password"}:
    raise RuntimeError("expected only email and password on private stdin")
if not isinstance(payload["password"], str) or len(payload["password"]) < 24:
    raise RuntimeError("administrator password must contain at least 24 characters")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "infra_settings")
import django
django.setup()
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django.db import connection, transaction
from apps.organizations_ext.models import Organization
from apps.teams.models import Team
from apps.projects.models import Project
from infra_support import check_database

validate_email(payload["email"])
if payload["email"] != os.environ["GLITCHTIP_BOOTSTRAP_ADMIN_EMAIL"]:
    raise RuntimeError("unexpected bootstrap administrator identity")
check_database()
with transaction.atomic(), connection.cursor() as cur:
    cur.execute("SELECT pg_advisory_xact_lock(723666, 627)")
    User = get_user_model()
    if User.objects.exists():
        expected = User.objects.filter(email=payload["email"], is_superuser=True,
                                       is_staff=True, is_active=True)
        if expected.count() != 1:
            raise RuntimeError("existing app does not contain the expected active administrator")
        print(json.dumps({"created": False, "existing_admin_verified": True}))
        sys.exit(0)
    if Organization.objects.exists() or Project.objects.exists():
        raise RuntimeError("bootstrap requires an empty app; never adopts orphaned app data")
    user = User.objects.create_superuser(payload["email"], payload["password"])
    org = Organization.objects.create(name="Unified", slug="unified", open_membership=False)
    member = org.add_user(user)
    team = Team.objects.create(organization=org, slug="apps")
    team.members.add(member)
    project = Project.objects.create(organization=org, name="Platform Canary",
                                     slug="platform-canary", platform="python")
    project.teams.add(team)
print(json.dumps({"created": True, "user_id": user.pk,
                  "organization": org.slug, "team": team.slug, "project": project.slug}))
