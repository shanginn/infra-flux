#!/bin/sh
set -eu

fingerprint() {
    # Explicit files avoid hashing ConfigMap projection symlink names. No file
    # contents, key material or fingerprints are written to logs.
    sha256sum /config/named.conf /config/named.conf.zones \
        /run/transfer/named.conf.transfers /zones/* | sha256sum | cut -d ' ' -f 1
}

/usr/sbin/named-checkconf -z /config/named.conf >/dev/null
loaded_fingerprint="$(fingerprint)"
/usr/sbin/named -g -c /config/named.conf -n 2 &
named_pid=$!
watcher_pid=''
stop() {
    trap - TERM INT
    test -z "$watcher_pid" || kill -TERM "$watcher_pid" 2>/dev/null || true
    kill -TERM "$named_pid" 2>/dev/null || true
    wait "$named_pid" 2>/dev/null || true
    exit 0
}
trap stop TERM INT

(
    rejected_fingerprint=''
    while kill -0 "$named_pid" 2>/dev/null; do
        sleep 5
        next_fingerprint="$(fingerprint)" || continue
        test "$next_fingerprint" != "$loaded_fingerprint" || continue
        # Validate a stable projected generation before touching the running
        # server. Keep the old authority available if a new config is invalid.
        if ! /usr/sbin/named-checkconf -z /config/named.conf >/dev/null 2>&1; then
            if test "$next_fingerprint" != "$rejected_fingerprint"; then
                echo 'BIND reload skipped: projected configuration failed validation' >&2
                rejected_fingerprint="$next_fingerprint"
            fi
            continue
        fi
        test "$next_fingerprint" = "$(fingerprint)" || continue
        kill -HUP "$named_pid" || exit 0
        loaded_fingerprint="$next_fingerprint"
        rejected_fingerprint=''
        echo 'BIND configuration reload requested without replacing its process' >&2
    done
) &
watcher_pid=$!

set +e
wait "$named_pid"
status=$?
kill -TERM "$watcher_pid" 2>/dev/null || true
wait "$watcher_pid" 2>/dev/null || true
exit "$status"
