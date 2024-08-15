#!/usr/bin/env bash

set -euxo pipefail

cargo build -p fakesshd

cargo run -p fakesshd &

sleep 1

ssh -p 2222 localhost true
ssh -p 2222 -oCiphers=aes256-gcm@openssh.com \
    -oHostKeyAlgorithms=ecdsa-sha2-nistp256 \
    -oKexAlgorithms=ecdh-sha2-nistp256 127.0.0.1 true

pkill fakesshd
