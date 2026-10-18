# Reload existing BIND static zones

`reload-static-zones.py` validates an existing legacy BIND process and sends one
`SIGHUP` only with `--execute`. It does not change Kubernetes resources, copy zone
files, restart containers, invoke `rndc`, or alter dynamic journals. Its default
mode performs the same preflight without sending a signal.

Use this for the static zone files mounted at `/etc/bind/zones`. The two dynamic
zones (`vibesites.ru` and `xn--80aacc0bc7ayl4g.xn--p1ai`) and their files are refused.
Their RFC2136 key is restricted to challenge TXT records; it cannot authorize apex
NS edits. Updating those zones requires a separate procedure preserving current
in-memory data and journals. Editing their seed files in Git is not a live update.

## Prepare and publish

1. Read the current cluster, Deployment, Pod, container and process identities;
   save them privately. Capture current served SOAs and all mounted file hashes.
2. Change only the intended static zone files and advance each SOA serial. Render
   both legacy Kustomizations before and after. The complete Deployment specs,
   configuration ConfigMaps and every unrelated zone must be identical.
3. Keep the zone ConfigMap name `bind9-zones-ttm842m5bt` and its
   `disableNameSuffixHash: true`. Configuration files still use a hashed ConfigMap
   and subPath mounts: changing them would change the Pod template. Do not change
   them as part of this operation.
4. Publish the reviewed source. Confirm each Flux controller's actual applied
   revision, stable workload and projected ConfigMap bytes. A targeted ConfigMap
   change, if necessary, must compare its UID, resourceVersion and complete old
   data before replacing only the reviewed key. This helper performs no such
   change. Do not reconcile unrelated stale cluster changes as a shortcut.
5. Build the private guard from fresh runtime identities and the reviewed rendered
   bytes. A pending projection or any mismatch is a reason to wait or investigate,
   not to relax the guard. A broad HUP reloads all static zones, so all 22 source
   files and four configuration files are pinned, including unchanged files.

## Guard schema

The JSON object has these exact keys (version `1`); keep it outside Git with mode
`0600`. No credentials or key contents are needed.

| Key | Expected value |
| --- | --- |
| `cluster_uid` | UID of namespace `kube-system` |
| `deployment_uid` | UID of `bind9/bind9-deployment` |
| `template_sha256` | SHA256 of the live Deployment's `spec.template`, serialized with Python `json.dumps(value, sort_keys=True, separators=(',', ':'))` |
| `pod_name`, `pod_uid` | Existing BIND Pod name and UID |
| `container_id`, `restarts` | Exact `bind9` container ID including runtime prefix, and integer restart count |
| `pid_start` | String field 22 of `/proc/1/stat` in that container; `/proc/1/comm` must be `named` |
| `configmap_uid`, `configmap_resource_version` | Current zone ConfigMap UID and resourceVersion, after publication |
| `config_sha256` | Map of all four mounted configuration filenames to SHA256 of exact UTF-8 bytes |
| `zone_sha256` | Map of all 22 zone filenames to SHA256 of exact reviewed bytes |
| `zones` | List of objects with `name` (ASCII without trailing dot), `file`, `before_serial` and `expected_serial` (integers) |

The four configuration keys are `named.conf`, `named.conf.acl`, `named.conf.local`
and `named.conf.options`. The secret key file is never read or included in output.

## Run one host at a time

The controller needs Python 3.9+ and SSH; the remote host needs Python 3.9+.
Use an existing SSH alias. The `kubectl` profile uses host `kubectl`; the `minikube`
profile uses `sudo -u dev minikube kubectl --` and executes against the pinned
container ID through the existing `minikube` Docker container.

```sh
python3 bootstrap/dns/reload-static-zones.py --via LEGACY_ALIAS \
  --profile kubectl --guard /private/path/reload-guard.json \
  --output /private/path/reload-check.json

python3 bootstrap/dns/reload-static-zones.py --via LEGACY_ALIAS \
  --profile kubectl --guard /private/path/reload-guard.json \
  --output /private/path/reload-result.json --execute
```

The output file is created exclusively before remote dispatch. Existing output
paths are refused. **If SSH or validation fails after dispatch, do not rerun with
another output path.** Independently read the Pod/process identities and SOAs,
then determine whether the signal took effect. The helper never retries its HUP;
there is no automatic rollback or restart. The exclusive record guards accidental
replay of the same invocation, not concurrent operations under different names.
Have one operator own the maintenance window.

`verified` means the target serials appeared, all other SOAs stayed unchanged,
and the original process, Pod, restart count, Deployment template, ConfigMap
revision and mounted bytes survived. A concurrent legitimate dynamic update can
fail the unchanged-SOA check; inspect it instead of retrying the signal. ConfigMap
projection and external Kubernetes controllers cannot be locked by this helper;
keep unrelated reconciliations and edits out of the maintenance window.

After each host, run `verify-zones.py` and independent UDP/TCP public probes from
multiple locations. Verify the complete intended RRset changes, including apex
NS; serial verification alone does not prove public routing or record parity.
Keep old public listeners serving during delegation and cache overlap.

BIND documents SIGHUP as a configuration and database reload in its
[administration manual](https://bind9.readthedocs.io/en/v9.20.23/chapter4.html).
The helper retains the already-running process and explicitly excludes dynamic
zone-file replacement.
