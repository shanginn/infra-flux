# Phenogram TLS entry

This unreferenced base stays at zero replicas. It supplies only the TLS proxy;
PostgreSQL, the platform, gateway, Telegram pools and data migration are separate.
A controlled preparation may start the proxy before the application, while the
old site remains live. Proxy readiness does not prove application readiness.

Provide `api-phenogram-io-tls`, `app-phenogram-io-tls` and `phenogram-io-tls` in
`phenogram` before activation. Private keys are never part of this base.

The API preserves the original case-insensitive Bot API path routing, unlimited
body size, disabled request/response buffering, 500-second client timeouts,
large headers and one-hour upstream timeouts. API access logging remains off
because Bot API request paths contain tokens. The app and landing hosts retain
their separate path and upload policies. Traefik passes TLS and PROXY v2 to
this private Service; only its Pods can connect to the TLS listener.

Before client handover, check the native Nginx configuration, certificates,
current images and bindings, final database/file parity, and actual application
health through both FIN and the old cached address. Start only one producer set.
