# Application storage on HOME

This component prepares four retained local volumes. It has no workloads or
parent Flux reference. Creating claims does not restore data or start consumers.
Create and verify the exact backing directories on the bound HOME node before
mounting a volume. Never reuse a nonempty directory or a claim from another app.

The declarations reserve planning budgets of 20 GiB for Sistent uploads, 5 GiB
for Generach persistence, 8 GiB for Redis and 12 GiB for Dragonfly. They share
HOME's physical disk with the runtime, PostgreSQL and Garage; local volume sizes
are neither additional disks nor enforced filesystem quotas. Check actual free
space and pressure before restoration and each large image download.

All volumes use `Retain` and HOME node affinity. They do not fail over to a VPS.
Verify ownership, ACLs, extended attributes and a real read/write mount through
an owned isolated probe. Preserve original data metadata in the backup; record
any target permission adaptation separately.

Restore the existing baseline, rehearse changes including deletions and metadata,
then perform final synchronization immediately before the validated handover.
Redis and Dragonfly remain separate data stores. Their current native contents
and expiry semantics require coordinated native preservation; old live filesystem
copies alone do not prove current application state.
