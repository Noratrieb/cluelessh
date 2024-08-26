#!/usr/bin/env bash

printf $"echo jdklfsjdöklfd" | ssh -p "$PORT" "$HOST" | grep jdklfsjdöklfd
