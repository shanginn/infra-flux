#!/usr/bin/env python3
"""Read-only gate before and after each fault. Fails closed until all sites recover."""
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from common import get, identity, kube, ready, require


def check(ca_sha256):
    local = identity(ca_sha256)
    nodes = get('nodes')['items']
    require({n['metadata']['name'] for n in nodes} == {'home', 'msk', 'fin'}, 'Expected exactly three managed nodes')
    require(all(ready(n) for n in nodes), 'A node is not Ready')
    for node in nodes:
        address = next(a['address'] for a in node['status']['addresses'] if a['type'] == 'InternalIP')
        require(kube(['--server=https://' + address + ':6443', 'get', '--raw=/readyz']).strip() == b'ok', 'API is not ready')
    etcd = kube(['exec', '-n', 'kube-system', 'etcd-' + local['node_name'], '--', 'etcdctl',
                 '--endpoints=https://127.0.0.1:2379', '--cacert=/etc/kubernetes/pki/etcd/ca.crt',
                 '--cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt', '--key=/etc/kubernetes/pki/etcd/healthcheck-client.key',
                 'endpoint', 'health', '--cluster', '-w', 'json'])
    endpoints = json.loads(etcd)
    require(len(endpoints) == 3 and all(e['health'] is True for e in endpoints), 'Three healthy etcd members are required')
    garage = get('pods', namespace='garage')['items']
    garage = [p for p in garage if p['metadata'].get('labels', {}).get('app.kubernetes.io/name') == 'garage']
    require(len(garage) == 3 and all(ready(p) for p in garage) and {p['spec']['nodeName'] for p in garage} == {'home', 'msk', 'fin'}, 'Garage placement/readiness differs')
    health = json.loads(kube(['exec', '-n', 'garage', garage[0]['metadata']['name'], '-c', 'garage', '--', '/garage', 'json-api', 'GetClusterHealth', 'null']))
    require(health['storageNodes'] == health['storageNodesUp'] == 3 and health['partitions'] == health['partitionsAllOk'] > 0, 'Garage has not repaired all replicas')
    pg = [p for p in get('pods', namespace='database')['items'] if p['metadata'].get('labels', {}).get('cluster-name') == 'unified-postgres']
    require(len(pg) == 3 and all(ready(p) for p in pg) and {p['spec']['nodeName'] for p in pg} == {'home', 'msk', 'fin'}, 'Three Ready PostgreSQL members required')
    query = "SELECT json_build_object('recovery',pg_is_in_recovery(),'replicas',(SELECT json_agg(json_build_object('state',state,'sync',sync_state,'lag',CASE WHEN pg_is_in_recovery() THEN 0 ELSE pg_wal_lsn_diff(pg_current_wal_lsn(),replay_lsn) END)) FROM pg_stat_replication));"
    def inspect(pod):
        prefix = ['exec', '-n', 'database', pod['metadata']['name'], '-c', 'postgres', '--']
        runtime = json.loads(kube(prefix + ['/opt/patroni/bin/python', '/opt/infra/verify-runtime.py']))
        state = json.loads(kube(prefix + ['/usr/lib/postgresql/18/bin/psql', '-X', '-h', '/run/postgresql', '-U', 'postgres', '-d', 'postgres', '-At', '-c', query]))
        require(state['recovery'] is (runtime['role'] != 'primary'), 'PostgreSQL role differs from Patroni')
        return runtime, state
    with ThreadPoolExecutor(3) as pool:
        members = list(pool.map(inspect, pg))
    primaries = [(r, s) for r, s in members if not s['recovery']]
    require(len(primaries) == 1, 'Exactly one writable primary required')
    replicas = primaries[0][1]['replicas'] or []
    require(len(replicas) == 2 and all(r['state'] == 'streaming' and r['sync'] == 'async' and r['lag'] is not None and 0 <= r['lag'] <= 16777216 for r in replicas), 'Replicas must be streaming asynchronously within 16 MiB')
    require(primaries[0][0].get('watchdog_timeout_seconds') == 30, 'Approved software watchdog is not active')
    return {'ok': True, 'nodes': 3, 'api_ready': 3, 'etcd_healthy': 3, 'garage_nodes': 3,
            'garage_partitions_healthy': health['partitionsAllOk'], 'postgres_primary': primaries[0][0]['member'],
            'postgres_replicas': 2, 'postgres_replay_lag_bytes': [r['lag'] for r in replicas]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ca-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.ca_sha256)))
