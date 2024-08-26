#!/usr/bin/env bash

# KEX
printf $"exit\r" | ssh -oKexAlgorithms=curve25519-sha256 -p "$PORT" "$HOST"
printf $"exit\r" | ssh -oKexAlgorithms=ecdh-sha2-nistp256 -p "$PORT" "$HOST"

# Encryption
printf $"exit\r" | ssh -oCiphers=chacha20-poly1305@openssh.com -p "$PORT" "$HOST"
printf $"exit\r" | ssh -oCiphers=aes256-gcm@openssh.com -p "$PORT" "$HOST"

# Host Key
printf $"exit\r" | ssh -oHostKeyAlgorithms=ssh-ed25519 -p "$PORT" "$HOST"
