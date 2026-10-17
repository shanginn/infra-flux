"""Small deployment adapter; application behavior stays in the pinned image."""
from glitchtip.settings import *  # noqa: F403

# Upstream 6.2.6 does not expose these django-storages settings through env.
# Garage's private Service is reached through Calico over the encrypted VPN.
AWS_S3_REGION_NAME = "garage"
AWS_S3_ADDRESSING_STYLE = "path"
AWS_S3_SIGNATURE_VERSION = "s3v4"
AWS_DEFAULT_ACL = None
AWS_QUERYSTRING_AUTH = True
# Traefik overwrites the scheme header; NetworkPolicy admits only the ingress
# Pods and Prometheus on the web port. Keep Django's secure-origin behavior.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Read-only metrics from the dedicated DB; failures remain failed scrapes.
MIDDLEWARE = ["infra_support.capacity_metrics", *MIDDLEWARE]  # noqa: F405
