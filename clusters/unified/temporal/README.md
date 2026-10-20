# Unified Temporal — inactive preparation

This directory prepares the single Temporal installation for applications from
both former sites. No parent Kustomization or Flux owner references it. All four
Deployments have zero replicas. Publishing these files does not start a server,
change an application endpoint, import data, or create credentials.

The first migration preserves the Contabo 1.28.4 persistence pair, including its
namespace UUIDs, cluster identity, 512 history shards, mutable workflow state and
internal queues. Selected Rubase namespaces must later join this same
installation. Do not create a second permanent Temporal or import empty and
obsolete namespace duplicates. Keep source inventories and migration receipts
in the private checkpoint.

## Runtime choices

The pinned image is the observed Contabo server digest. Frontend, history,
matching and the Temporal system worker remain separate processes on HOME.
The image entrypoint is bypassed: the native server reads its configuration and
renders environment values with its own template loader. Passwords come from
the private `temporal-default-store` and `temporal-visibility-store` Secrets,
key `password`, in `temporal-system`; neither Secret is included here.

Both stores use `unified-postgres.database.svc.cluster.local:5432` and the
preserved `temporal_user` role. Each process/store pool is capped at eight
connections instead of the source's twenty. Four processes and two pools allow
up to 64 connections, before administrative or other application connections.
Check actual shared PostgreSQL headroom and load before activation. Do not
change the database's primary merely to match placement preference.

The cluster remains named `active`, with initial failover version 1 and increment
10. The source's obsolete global-domain key is represented by the native
`enableGlobalNamespace: false` setting. The cluster RPC address is changed to the
new frontend's actual port 7233; the old configuration's loopback port 7933 is
not retained as a destination. Archival stays disabled. Dynamic configuration
remains empty.

Pods run without root, a writable root filesystem, Kubernetes credentials or
external egress. Only intra-Temporal traffic, cluster DNS and the PostgreSQL
members are allowed. The frontend is private and has **no application ingress
permission yet**. Add only reviewed caller namespace/Pod selectors during
handover, together with the corresponding caller egress policy. Public gateways,
TLS/authentication and external worker access need their own concrete migration.

Startup/readiness checks show that the process exposes its listener. The system
worker uses its metrics listener, since it need not expose a worker gRPC server.
These checks do not establish database parity, correct membership, working
applications or successful workflow execution. Resource settings are initial
budgets that still need runtime validation.

## Before any activation

1. Restore both existing archived databases into an isolated, externally blocked
   fixture. Verify complete table/sequence/catalog coverage before starting the
   exact server image, then validate namespaces and existing workflow state.
   A historical observational pair is not a final consistent migration pair.
2. Prepare the complete final cutover: coordinate source Temporal writers and
   application producers, capture the final persistence pair and application
   changes, and validate restoration. Measure the write interruption.
3. Preserve the original cluster and namespace identities, review the empty
   duplicate namespace's disposition, and prevent the copied server's membership
   or workers from contacting the still-active source.
4. Validate current PostgreSQL identities, readiness, remaining disk space,
   replica replay and connection capacity. Install private credentials through
   the reviewed migration operation.
5. Create the scoped Flux owner and activate only after the final database
   receipts, configuration and caller routes are verified. Start each consumer
   exactly once; do not run old and new bot/queue consumers simultaneously.
6. Verify actual client requests and workflow progress. Preserve old data and
   recovery archives. Do not blindly restart old writing after target writes.

Local rendering: `kubectl kustomize clusters/unified/temporal/base`.
Rendering and native configuration parsing do not constitute runtime acceptance.
