#!/usr/bin/env bash

printf $"exit\r" | ssh -oRequestTTY=force -p "$PORT" "$HOST"
