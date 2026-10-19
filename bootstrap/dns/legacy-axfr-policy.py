#!/usr/bin/env python3
"""Render an additive Headscale permission for two DNS transfer readers.

Reads JSON on stdin: policy, readers (two IPv4 addresses), primary (IPv4).
Writes the proposed policy only; applying/reloading it is a separate operation.
"""
import copy
import ipaddress
import json
import sys


def address(value):
    result = ipaddress.IPv4Address(value)
    if str(result) != value or result not in ipaddress.IPv4Network('100.64.0.0/10'):
        raise ValueError('An explicit overlay IPv4 address is required')
    return value


def proposed(policy, readers, primary):
    if not isinstance(policy, dict) or set(policy) != {'tagOwners', 'acls', 'tests'}:
        raise ValueError('Unexpected existing policy features')
    if not isinstance(readers, list) or len(readers) != 2:
        raise ValueError('Exactly two readers are required')
    readers = sorted(address(a) for a in readers)
    primary = address(primary)
    if len(set(readers + [primary])) != 3:
        raise ValueError('Reader and primary addresses must be distinct')
    if not isinstance(policy['acls'], list) or not isinstance(policy['tests'], list):
        raise ValueError('Explicit existing rules and tests are required')
    # Do not reinterpret earlier permission changes or a partially applied stage.
    if len(policy['acls']) != 4:
        raise ValueError('Expected the existing mesh plus three legacy capabilities')
    core = policy['acls'][0]
    if set(core) != {'action', 'src', 'dst'} or core['action'] != 'accept':
        raise ValueError('Unexpected existing mesh')
    peers = sorted(address(a) for a in core['src'])
    if len(peers) != 3 or len(set(peers)) != 3 or primary in peers:
        raise ValueError('Unexpected core membership')
    if core['dst'] != [a + ':*' for a in peers] or not set(readers) < set(peers):
        raise ValueError('Readers must be two existing mesh peers')
    for rule, tag, proto, port in zip(policy['acls'][1:],
            ['reader', 'reader', 'writer'], ['udp', 'tcp', 'tcp'], [5354, 5354, 18081]):
        expected = {'action': 'accept', 'src': ['tag:legacy-pdns-' + tag],
                    'proto': proto, 'dst': [a + ':' + str(port) for a in readers]}
        if rule != expected:
            raise ValueError('Existing legacy permission differs')
    if policy['tagOwners'] != {'tag:legacy-pdns-reader': ['infra@'],
                              'tag:legacy-pdns-writer': ['infra@']}:
        raise ValueError('Existing tag ownership differs')
    result = copy.deepcopy(policy)
    for proto in ('udp', 'tcp'):
        result['acls'].append({'action': 'accept', 'src': readers,
                              'dst': [primary + ':5355'], 'proto': proto})
    for reader in readers:
        result['tests'].append({'src': reader, 'accept': [primary + ':5355'],
                                'deny': [primary + ':' + str(p)
                                         for p in (22, 53, 443, 5432, 6443, 8081, 18081)]})
    other = next(a for a in peers if a not in readers)
    result['tests'].append({'src': other, 'deny': [primary + ':5355']})
    return result


if __name__ == '__main__':
    request = json.load(sys.stdin)
    print(json.dumps(proposed(request['policy'], request['readers'], request['primary']),
                     sort_keys=True, indent=2))
