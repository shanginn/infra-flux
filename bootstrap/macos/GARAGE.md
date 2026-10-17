# Garage object backups

`garage-stream.py export` is a standalone producer for `restic backup --stdin-from-command`. It streams every current completed S3 object and its HTTP/user metadata, bucket configuration, quotas, aliases, and recoverable access keys. These secrets must go directly into encrypted restic over SSH. The exporter refuses terminal output, uses no object/archive staging on VPS disks, and opens only a temporary loopback `kubectl port-forward`. Kubernetes CA and ownership markers must match the managed installation.

The Mac runner accepts a `garage` job; the example leaves it disabled until service and recovery checks pass. These standalone commands do not change installed jobs or the schedule. Install/review the files together in a protected server directory before invoking them; `prepare-garage-backup-key.py` and `check-garage-restore.py` import the sibling `garage-stream.py`.

## Access and bounds

Run `prepare-garage-backup-key.py --provision-read-only-key` explicitly on a managed node after Garage is Ready. It creates one owned S3 key with read permission for every existing bucket, no write/owner permission, and no permission to create buckets. Only its ID and ownership marker are stored in `/etc/infra-garage/backup-key.json` (0600); the exporter obtains its secret privately from the existing Garage administrative channel. Ambiguous key creation leaves an intent file and refuses automatic retry. After adding a bucket, rerun this provisioning command. A backup fails if its key cannot read every bucket, instead of silently omitting an inaccessible bucket.

Exports are bounded to 32 GiB of archive bytes, 100,000 objects, and two hours. The current 24 GiB data budget leaves room for tar and recovery metadata. On the Mac, require free space of at least the configured disk reserve **plus 32 GiB** before starting a full export. Keep the usual password file, encrypted repository, lock, pending/verified tags, notifications, and retention behavior. The runner uses a two-hour restic producer timeout for this component. A failed producer must fail `--stdin-from-command`; do not use an unchecked shell pipe that can turn a partial stream into a successful snapshot.

The archive contains fixed safe filenames; arbitrary object keys, including Unicode, slashes, and `..`, exist only inside JSON metadata. Object bodies stream through SHA-256. GET uses the listing's ETag as `If-Match`; length, complete body and returned ETag are checked. A second full listing and a second bucket/key configuration inventory must match before the final completion manifest is emitted. Access-key secrets and bucket settings are inside the encrypted archive, never in Git or logs.

## Verification and recovery

`garage-stream.py verify --cluster-name unified` reads a decrypted archive from stdin, hashes every object, checks object order/count/length and the final manifest, and writes only a small non-secret JSON result. It does not extract plaintext objects onto the Mac. Restic must successfully finish `dump`; the caller must check its exit status too. Only then may the snapshot receive the `verified` tag.

`check-garage-restore.py --isolated-bucket-roundtrip` is a separate explicitly invoked recovery check. It creates one uniquely named temporary bucket and temporary read/write key, uploads a 128 KiB binary object with a Unicode key and metadata, exports and verifies its archive in bounded RAM, deletes that test object, restores it from the archive, and compares bytes and metadata through S3 GET. Cleanup addresses only IDs created by this invocation. A failure can leave a nonempty validation bucket for inspection; the script never force-deletes unknown objects. This check does not touch application buckets and does not replace encrypted Mac snapshot verification.

For disaster recovery, restore into a new managed Garage layout. Recreate bucket aliases and quotas from `admin.json`; import access keys with their original IDs/secrets, then reapply permissions, aliases, and key expiration settings. Stream each `.bin` back with the object key and headers in its paired `.json`; compare downloaded SHA-256 to the recorded digest. Apply lifecycle expiration rules only after object verification, so old policy does not remove data during restoration. Full automatic application-bucket restore is deliberately separate from the isolated validation command.

Garage 2.4.1 has no S3 object versioning. This export contains current completed objects, not overwritten versions, delete markers, unfinished multipart uploads, K2V data, or a raw Garage metadata database. Older restic snapshots retain objects they previously captured, but cannot reconstruct changes that happened entirely between runs. Listing twice detects many concurrent changes; it is **not** a transactionally consistent snapshot across objects or buckets. Quiesce application writers and lifecycle deletion for a point-in-time dataset. Metadata-only rewrites within timestamp granularity and changes between the final checks remain possible. Restoration records but cannot preserve original S3 Last-Modified timestamps or multipart ETags; content SHA-256 is the comparison that matters.

Offline tests (the restic roundtrip is enabled only when `RESTIC_BINARY` points to a local binary):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 bootstrap/macos/test_garage_stream.py
```

Interfaces and limitations follow the [Garage S3 compatibility documentation](https://garagehq.deuxfleurs.fr/documentation/reference-manual/s3-compatibility/) and the [Garage 2.4.1 administration API definitions](https://github.com/deuxfleurs-org/garage/blob/v2.4.1/src/api/admin/api.rs). No S3 write, key creation, deployment, or backup schedule is triggered by importing these files.
