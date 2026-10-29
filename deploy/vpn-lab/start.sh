#!/bin/sh
set -eu
if [ "$1" = server ]; then ip address replace 10.181.0.1/32 dev lo; fi
/usr/lib/ipsec/charon &
child=$!
trap 'kill "$child"; wait "$child"' TERM INT
for i in 1 2 3 4 5 6 7 8 9 10; do
 if swanctl --stats >/dev/null 2>&1; then break; fi
 sleep 1
done
swanctl --load-all
wait "$child"
