#!/usr/bin/env bash

set -euo pipefail

script_dir=$(realpath "$(dirname "$0")")

cd "$script_dir/.."

cargo build

"../../target/debug/cluelesshd" &

pid=$!

kill_server() {
    echo "Killing server"
    kill "$pid"
}

trap kill_server EXIT

for script in "$script_dir"/openssh-client/*.sh; do
    echo "-------------- Running $script"
    PORT=2223 HOST=localhost bash -euo pipefail "$script"
done
