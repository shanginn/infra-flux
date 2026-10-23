This inactive edge preserves the existing HTTP paths, upload limits, long Sistent
requests, and Generach's optional client-certificate verification headers. Traefik
passes TLS through and supplies PROXY protocol v2. Nginx terminates TLS and buffers
large uploads on HOME; FIN remains the public entry point.

TLS Secrets and the exact legacy proxy fingerprint map are supplied separately.
The edge mounts public client CAs and does not need a signing key. The original
Mac worker CA remains trusted. Only the dedicated verified proxy certificate may
forward the original client's certificate status and identity through the old
address during the cache window; direct callers cannot forge those headers.

This directory has no parent Flux reference and starts with zero replicas.
Native configuration and owned backend/TLS acceptance must pass for the current
configuration before activation. Existing application data must be synchronized after producer
coordination, then verified before enabling the target consumers and changing
public routing. Preserve old endpoints through their actual dependency and cache
windows.
