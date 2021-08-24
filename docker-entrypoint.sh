#!/bin/sh
set -xe

# Due to: https://github.com/kubernetes/kubernetes/issues/57923 and https://github.com/istio/istio/issues/26882
# we need this workaround:
cp /cert/priv.pem /
chmod 600 /priv.pem

export TEKNOIR_USER=${1:-teknoir}
export DEVICE_PORT=${2:-49322}
export TERM=xterm-256color


python3 /app/named.py 