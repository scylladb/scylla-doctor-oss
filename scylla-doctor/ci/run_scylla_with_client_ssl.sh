#!/usr/bin/env bash
# Copyright (C) 2021-present ScyllaDB
#
# Prepare client-to-node SSL, then exec the Scylla docker entrypoint.
# configure-cqlsh waits for docker-entrypoint.py to write ~/.cassandra/cqlshrc.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$DIR/enable_client_node_ssl.py" prepare

/docker-entrypoint.py "$@" &
entrypoint_pid=$!

python3 "$DIR/enable_client_node_ssl.py" configure-cqlsh
wait "${entrypoint_pid}"
