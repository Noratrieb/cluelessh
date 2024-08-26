#!/usr/bin/env bash

ssh -p "$PORT" "$HOST" echo jdklfsjdöklfd | grep "jdklfsjdöklfd"

# Important: redirect 2>&1 first before clobbering 1
ssh -p "$PORT" "$HOST" "echo jdklfsjdöklfd 1>&2" 2>&1 1>/dev/null | grep "jdklfsjdöklfd"
