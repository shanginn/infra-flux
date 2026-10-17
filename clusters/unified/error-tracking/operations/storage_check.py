"""Explicit tiny write/read/delete through Django's configured Garage backend."""
import hashlib
import json
import os
import uuid
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "infra_settings")
import django
django.setup()
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from infra_support import check_database

check_database()
key = "infra-canary/" + uuid.uuid4().hex
payload = ("glitchtip-storage-" + uuid.uuid4().hex).encode()
saved = default_storage.save(key, ContentFile(payload))
if saved != key:
    raise RuntimeError("unexpected storage key; inspect own canary before cleanup")
with default_storage.open(key, "rb") as handle:
    result = handle.read(len(payload) + 1)
if result != payload:
    raise RuntimeError("storage readback differs; retain canary for inspection")
default_storage.delete(key)
if default_storage.exists(key):
    raise RuntimeError("canary deletion not observed")
print(json.dumps({"success": True, "bytes": len(payload),
                  "sha256": hashlib.sha256(payload).hexdigest(), "canary_removed": True}))
