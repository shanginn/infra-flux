#!/bin/sh
set -eu
# A bound socket does not prove all dynamic transfers completed. Require
# an authoritative SOA for every configured zone before public routing.
while IFS= read -r zone; do
    test -n "$zone" || continue
    answer="$(dig @127.0.0.1 -p 5353 "$zone" SOA +norecurse +time=1 +tries=1 +noall +comments +answer)" || exit 1
    printf '%s\n' "$answer" | grep -Eq 'status: NOERROR,' || exit 1
    printf '%s\n' "$answer" | grep -Eq 'flags: ([a-z]+ )*aa( |;)' || exit 1
    printf '%s\n' "$answer" | grep -Eq '[[:space:]]SOA[[:space:]]' || exit 1
done < /config/zones.txt
