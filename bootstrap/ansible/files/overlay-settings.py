#!/usr/bin/env python3
"""Pure configuration guards shared by overlay bootstrap and bounded maintenance."""
import ipaddress
import json
import re
import sys


RELAY_OWNER = 'infra-flux/ansible/coordinator-relay'
RELAY_KEYS = {'owner', 'format', 'standby_host', 'active_host', 'server_url',
              'upstream_ipv4', 'upstream_port'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_policy(policy):
    """Reject Headscale's implicit allow-all form; semantic validation is CheckPolicy."""
    require(isinstance(policy, dict), 'An explicit Headscale policy object is required')
    require('acls' in policy or 'grants' in policy,
            'Policy must explicitly declare acls or grants; omitted rules allow all traffic')
    for key in ('acls', 'grants'):
        if key in policy:
            require(isinstance(policy[key], list), 'Policy rules must be an explicit list')
    # YAML values must survive conversion to ordinary JSON, including no NaN/Infinity.
    json.dumps(policy, allow_nan=False)
    return policy


def validate_relay_record(record, *, local_host, active_host, server_url, local_ipv4,
                          namespace_addresses, tailnet_prefix, expected_upstream=None):
    """Bind a standby transport to its identity and a non-local public IPv4 literal."""
    require(isinstance(record, dict) and set(record) == RELAY_KEYS,
            'Coordinator relay record has unexpected fields')
    require(record['owner'] == RELAY_OWNER and type(record['format']) is int
            and record['format'] == 1, 'Unknown coordinator relay ownership or format')
    require(isinstance(local_host, str) and isinstance(active_host, str)
            and local_host != active_host, 'Active coordinator cannot relay to itself')
    require(record['standby_host'] == local_host and record['active_host'] == active_host,
            'Coordinator relay roles differ from the declared hosts')
    hostname = server_url.removeprefix('https://') if isinstance(server_url, str) else ''
    require(server_url == 'https://' + hostname and '.' in hostname and len(hostname) <= 253
            and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                    for p in hostname.split('.')), 'Invalid coordinator HTTPS identity')
    require(record['server_url'] == server_url, 'Coordinator relay HTTPS identity differs')
    require(type(record['upstream_port']) is int and record['upstream_port'] == 443,
            'Coordinator relay must use the public TLS listener')
    require(isinstance(record['upstream_ipv4'], str), 'Relay target must be an IPv4 literal')
    upstream = ipaddress.IPv4Address(record['upstream_ipv4'])
    require(str(upstream) == record['upstream_ipv4'] and upstream.is_global
            and not upstream.is_multicast and not upstream.is_reserved,
            'Relay target must be a public unicast IPv4 literal')
    require(isinstance(local_ipv4, list) and bool(local_ipv4),
            'Local IPv4 inventory is required to exclude forwarding loops')
    local = {ipaddress.IPv4Address(address) for address in local_ipv4}
    require(upstream not in local, 'Coordinator relay cannot target a local interface')
    require(isinstance(namespace_addresses, list) and len(namespace_addresses) == 2,
            'Both namespace interface addresses are required')
    namespaces = [ipaddress.IPv4Interface(address).network for address in namespace_addresses]
    tailnet = ipaddress.IPv4Network(tailnet_prefix)
    require(tailnet.subnet_of(ipaddress.IPv4Network('100.64.0.0/10')),
            'Unexpected tailnet prefix')
    require(not any(upstream in network for network in [tailnet, *namespaces]),
            'Coordinator transport must not depend on its overlay or namespace')
    if expected_upstream is not None:
        require(record['upstream_ipv4'] == expected_upstream,
                'Declared coordinator target conflicts with the persisted relay')
    return str(upstream)


def make_relay_record(upstream_ipv4, **identity):
    record = {'owner': RELAY_OWNER, 'format': 1, 'standby_host': identity['local_host'],
              'active_host': identity['active_host'], 'server_url': identity['server_url'],
              'upstream_ipv4': upstream_ipv4, 'upstream_port': 443}
    validate_relay_record(record, **identity)
    return record


def resolve_routing(settings):
    """Bootstrap may create a relay record; later callers must preserve the saved one."""
    record = settings.get('record')
    if settings['local_host'] == settings['active_host']:
        require(record is None, 'An active coordinator must not retain a standby relay record')
        return {'record': None, 'upstream_ipv4': None}
    identity = {key: settings[key] for key in ('local_host', 'active_host', 'server_url',
                'local_ipv4', 'namespace_addresses', 'tailnet_prefix')}
    identity['expected_upstream'] = settings.get('expected_upstream')
    if record is None:
        require(settings.get('allow_initial_record') is True,
                'Missing persisted coordinator relay; use bounded maintenance first')
        record = make_relay_record(settings.get('expected_upstream'), **identity)
    upstream = validate_relay_record(record, **identity)
    return {'record': record, 'upstream_ipv4': upstream}



DERP_TRANSPORT_OWNER = 'infra-flux/ansible/derp-transports'


def resolve_derp_transports(settings):
    """Preserve optional public TLS paths to the same remote DERP process."""
    record = settings.get('record')
    expected = settings.get('expected')
    require(expected is None or isinstance(expected, list), 'DERP transports must be an explicit list')
    if record is None:
        require(not settings.get('existing_cross_route'), 'Cross-DERP route has no owned transport record')
        if not expected:
            return {'record': None, 'transports': []}
        require(settings.get('allow_initial_record') is True,
                'Initialize DERP transports through bounded maintenance first')
        record = {'owner': DERP_TRANSPORT_OWNER, 'format': 1, 'transports': expected}
    require(isinstance(record, dict) and set(record) == {'owner', 'format', 'transports'}
            and record['owner'] == DERP_TRANSPORT_OWNER and type(record['format']) is int
            and record['format'] == 1, 'Unknown DERP transport record')
    transports = record['transports']
    require(isinstance(transports, list) and len(transports) <= 2, 'Invalid DERP transport list')
    if expected is not None:
        require(expected == transports, 'Declared DERP transports conflict with saved state')
    hosts = settings['derp_hosts']
    require(set(hosts) == {'msk', 'fin'} and settings['local_host'] in hosts,
            'Unknown DERP transport site')
    require(isinstance(settings['local_ipv4'], list) and settings['local_ipv4'], 'Local addresses required')
    local = {ipaddress.IPv4Address(value) for value in settings['local_ipv4']}
    networks = [ipaddress.IPv4Interface(value).network for value in settings['namespace_addresses']]
    tailnet = ipaddress.IPv4Network(settings['tailnet_prefix'])
    require(tailnet.subnet_of(ipaddress.IPv4Network('100.64.0.0/10')), 'Unexpected tailnet prefix')
    seen = set()
    for item in transports:
        require(isinstance(item, dict) and set(item) ==
                {'region_host', 'via_host', 'via_ipv4', 'upstream_ipv4'}, 'Unexpected DERP transport fields')
        region, via = item['region_host'], item['via_host']
        require(region in hosts and via in hosts and region != via, 'DERP transport cannot relay to itself')
        require(region not in seen, 'Duplicate DERP transport region')
        seen.add(region)
        addresses = []
        for key in ('via_ipv4', 'upstream_ipv4'):
            address = ipaddress.IPv4Address(item[key])
            require(isinstance(item[key], str) and str(address) == item[key] and address.is_global
                    and not address.is_multicast and not address.is_reserved,
                    'DERP transports require public unicast IPv4 literals')
            require(not any(address in net for net in [tailnet, *networks]), 'DERP transport depends on overlay')
            addresses.append(address)
        require(addresses[0] != addresses[1], 'DERP transport loops to its listener')
        own_index = 0 if settings['local_host'] == via else 1
        require(addresses[own_index] in local and addresses[1-own_index] not in local,
                'DERP transport does not match actual site addresses')
        hostname = hosts[region]['hostname']
        require(isinstance(hostname, str) and '.' in hostname and len(hostname) <= 253
                and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                        for part in hostname.split('.')), 'Invalid DERP TLS identity')
    return {'record': record, 'transports': transports}


def main():
    settings = json.load(sys.stdin)
    if settings['operation'] == 'policy':
        validate_policy(settings.get('policy'))
        print(json.dumps({'valid': True}))
    elif settings['operation'] == 'routing':
        print(json.dumps(resolve_routing(settings)))
    elif settings['operation'] == 'derp-transports':
        print(json.dumps(resolve_derp_transports(settings)))
    else:
        raise ValueError('Unknown overlay configuration operation')


if __name__ == '__main__':
    try:
        main()
    except (KeyError, TypeError, ValueError) as error:
        # No policy contents, address inventory, keys or arbitrary exception values.
        print('Overlay settings rejected: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
