# Squid on Finland

This directory is optional and is not referenced by the applications parent.
`base` creates a private authenticated proxy on the Finland node. `public`
adds port 31128 on the explicitly substituted `SQUID_FIN_PUBLIC_IP` only.
A scoped Flux owner must require the private substitution ConfigMap; an unset
address must fail validation. The Service uses `externalIPs`, not a NodePort.
Check support when upgrading Kubernetes and test the actual incoming path.

The image is pinned to the migrated Squid 6.13 digest. The configuration and
original NCSA password hashes must match the source. Provide `squid-auth` with
the `passwd` key through the private bootstrap; never commit hashes or passwords.
The proxy accepts only authenticated clients. Its existing destination-port
rules are preserved, with DNS egress to cluster DNS.

Before enabling the public overlay, verify authenticated HTTP and HTTPS CONNECT,
rejection of anonymous and incorrect credentials, and the original mounted
configuration and password file. A temporary test credential must be removed
before publication. Secret files use subPath mounts and Squid caches credentials:
replace only the new staging Pod after restoring the original Secret, then verify
that the removed credential is rejected by the replacement process. Do not
restart the old proxy as part of this check.

After enabling the public Service, test it from an external non-Russian network
using a valid client credential as well as anonymous and incorrect credentials.
A private port-forward test does not validate public routing or firewall rules.
Retain the old endpoint until clients have moved; IP-based clients do not follow
DNS changes. Keep credentials unchanged unless a separate rotation is requested.

The cache and logs are bounded ephemeral volumes. This proxy has one instance on
Finland; the Moscow node and the old endpoint are not automatic proxy replicas.
The public overlay is not activated by rendering or committing this directory.
