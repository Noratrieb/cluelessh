#!/usr/bin/env bash

# KEX
ssh -oKexAlgorithms=curve25519-sha256 -p "$PORT" "$HOST" true
ssh -oKexAlgorithms=ecdh-sha2-nistp256 -p "$PORT" "$HOST" true

# Encryption
ssh -oCiphers=chacha20-poly1305@openssh.com -p "$PORT" "$HOST" true
ssh -oCiphers=aes256-gcm@openssh.com -p "$PORT" "$HOST" true

# Host Key
ssh -oHostKeyAlgorithms=ssh-ed25519 -p "$PORT" "$HOST" true
