#!/bin/sh
set -e

# Workaround for K8s/Istio issues with mounting certs
# See: https://github.com/kubernetes/kubernetes/issues/57923
if [ -f /cert/priv.pem ]; then
    cp /cert/priv.pem /priv.pem
    chmod 600 /priv.pem
fi
export RSA_KEY_FILE=${RSA_KEY_FILE:-"/priv.pem"}

export DEADENDUSER=${DEADENDUSER:-"teknoir"}
export DEADENDHOST=${DEADENDHOST:-"deadend"}
export DEADENDPORT=${DEADENDPORT:-2222}

export REMOTE_USERNAME=${1:-${REMOTE_USERNAME:-"teknoir"}}
export REMOTE_ACCESS_PORT=${2:-${REMOTE_ACCESS_PORT:-49322}}
export PORT=${PORT:-8080}
export WEB_TERMINAL_SCRIPT_FILE=${3:-${WEB_TERMINAL_SCRIPT_FILE:-"/app/app/named.py"}}

export PROXY_CMD="ssh -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 -i ${RSA_KEY_FILE} -N -W %h:%p ${DEADENDUSER}@${DEADENDHOST} -p ${DEADENDPORT}"
exec python3 ${WEB_TERMINAL_SCRIPT_FILE}
