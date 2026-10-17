#!/usr/bin/env python3
"""Bounded external HTTP/DNS observations; does not inject any faults."""
import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import re
import subprocess
import time
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe_http(address, hostname):
    start = time.monotonic()
    result = {'kind': 'http', 'address': address, 'ok': False}
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request('http://' + address + '/ping', headers={'Host': hostname})
        with opener.open(request, timeout=2) as response:
            result['status'] = response.status
            result['ok'] = response.status == 200 and response.read(32).strip() == b'OK'
    except Exception as error:
        result['error'] = type(error).__name__
    result['elapsed_ms'] = round((time.monotonic() - start) * 1000, 1)
    return result


def probe_dns(address, hostname, tcp):
    start = time.monotonic()
    result = {'kind': 'dns-tcp' if tcp else 'dns-udp', 'address': address, 'ok': False}
    try:
        command = ['dig', '-4', '@' + address, hostname, 'A', '+norecurse', '+time=1', '+tries=1',
                   '+noall', '+comments', '+answer'] + (['+tcp'] if tcp else [])
        response = subprocess.run(command, capture_output=True, text=True, timeout=2)
        result['authoritative'] = bool(re.search(r';; flags:.*\baa\b', response.stdout))
        result['answers'] = sorted({line.split()[-1] for line in response.stdout.splitlines()
                                    if not line.startswith(';') and len(line.split()) == 5
                                    and line.split()[3] == 'A'})
        result['ok'] = (response.returncode == 0 and 'status: NOERROR' in response.stdout
                        and result['authoritative'] and bool(result['answers']))
    except Exception as error:
        result['error'] = type(error).__name__
    result['elapsed_ms'] = round((time.monotonic() - start) * 1000, 1)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', action='append', required=True, help='Public IPv4; repeat for each VPS')
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--duration', type=int, default=3600)
    parser.add_argument('--interval', type=float, default=2)
    args = parser.parse_args()
    if not 1 <= len(args.address) <= 4 or len(set(args.address)) != len(args.address):
        parser.error('Use one to four distinct IPv4 addresses')
    for address in args.address:
        if ipaddress.ip_address(address).version != 4:
            parser.error('IPv4 required')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]', args.hostname):
        parser.error('A DNS hostname is required')
    if not 1 <= args.duration <= 7200 or not 1 <= args.interval <= 30:
        parser.error('Duration must be 1..7200 seconds and interval 1..30 seconds')
    subprocess.run(['dig', '-v'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    finish = time.monotonic() + args.duration
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(args.address) * 3) as pool:
        while time.monotonic() < finish:
            start = time.monotonic()
            observed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            futures = []
            for address in args.address:
                futures.extend([pool.submit(probe_http, address, args.hostname),
                                pool.submit(probe_dns, address, args.hostname, False),
                                pool.submit(probe_dns, address, args.hostname, True)])
            print(json.dumps({'observed_at': observed_at, 'probes': [x.result() for x in futures]}), flush=True)
            time.sleep(max(0, min(finish - time.monotonic(), args.interval - (time.monotonic() - start))))


if __name__ == '__main__':
    main()
