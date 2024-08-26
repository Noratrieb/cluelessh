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

failures=()

export PORT=2223
export HOST=localhost

for script in "$script_dir"/openssh-client/*.sh; do

    echo "-------------- Running PORT=$PORT HOST=$HOST bash $script"

    set +e
    bash -euo pipefail "$script"
    result=$?
    set -e
    if [ "$result" -ne "0" ]; then
        echo "Test $script failed!"

        failures+=("$script")
    fi 
done

if (( ${#failures[@]} )); then
    echo "FAILED"
    for failure in "${failures[@]}"; do
        echo " failed: PORT=$PORT HOST=$HOST bash $failure"
    done
    exit 1
fi
