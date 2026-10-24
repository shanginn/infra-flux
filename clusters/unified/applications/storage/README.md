# Application storage on HOME

This component prepares six retained local volumes. It has no workloads or
parent Flux reference. Creating claims does not restore data or start consumers.
Create and verify the exact backing directories on the bound HOME node before
mounting a volume. Never reuse a nonempty directory or a claim from another app.

The declarations reserve planning budgets of 20 GiB for Sistent uploads, 5 GiB
for Generach persistence, 8 GiB for Redis, 12 GiB for Dragonfly and 20 GiB for
the shared local Telegram API's sessions and files, plus 4 GiB for Generach's
PHP runtime storage. They share
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

The shared Telegram API is a Sistent dependency. Restore its encrypted baseline
to the initially absent HOME data path, then compare and synchronize current
files after coordinating its writers. Keep the original path layout and file
service bindings. Do not start a second Telegram API against the same sessions
or treat a live filesystem copy as a final consistent handover.

Generach's PHP API mounts the `api` directory of `php-runtime-data` at
`/var/www/app/storage`. Preserve its file sessions, application files and cache
metadata during the final delta. Keep the old Octane process state in the
backup, but exclude `logs/octane-server-state.json` from the restored runtime.
That file describes the old process and must not mark the new server as running.

PHP Temporal workers use `workers/$(MIGRATION_POD_UID)` through `subPathExpr`.
An init container, using the same pinned PHP image and UID/GID 1337, runs
`seed-storage.sh worker` with the Pod UID supplied by the Downward API. The API
uses `seed-storage.sh api`. Both init containers mount the whole claim at
`/state`; main containers mount only their storage directory. Keep old worker
directories for recovery rather than merging independent log files or deleting
them during an image update. Provision the claim's backing directory with
UID/GID 1337 before use and verify an actual mount with the application identity.

Do not mount an old complete application code volume over the new image or copy
`bootstrap/cache/config.php` from the old server. Cached Laravel configuration
can override new database and service environment values. Preserve that source
file in the encrypted backup and keep the target's reviewed image configuration.
