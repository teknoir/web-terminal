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
export DEADENDPORT=${DEADENDPORT:-22}

export REMOTE_USERNAME=${1:-${REMOTE_USERNAME:-"teknoir"}}
export REMOTE_ACCESS_PORT=${2:-${REMOTE_ACCESS_PORT:-49322}}
export PORT=${PORT:-8080}
export WEB_TERMINAL_SCRIPT_FILE=${3:-${WEB_TERMINAL_SCRIPT_FILE:-"/app/app/named.py"}}

# SSH_PROXY_MODE=deadend (default): reverse tunnel through deadend, as always.
# SSH_PROXY_MODE=wireguard: the per-terminal ssh command is built by app/wg_mode.py
# and reaches the device with wg-connect, so there is no PROXY_CMD.
export SSH_PROXY_MODE=${SSH_PROXY_MODE:-deadend}
case "${SSH_PROXY_MODE}" in
  deadend)
    export PROXY_CMD="ssh -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -o ServerAliveInterval=60 -i ${RSA_KEY_FILE} -N -W %h:%p ${DEADENDUSER}@${DEADENDHOST} -p ${DEADENDPORT}"
    ;;
  wireguard)
    for v in WG_HUB_URL WG_NAMESPACE WG_DEVICE WG_SA_TOKEN_FILE; do
        eval "val=\${$v:-}"
        if [ -z "${val}" ]; then
            echo "SSH_PROXY_MODE=wireguard requires ${v}" >&2
            exit 1
        fi
    done
    export WG_HUB_URL WG_NAMESPACE WG_DEVICE WG_SA_TOKEN_FILE
    ;;
  *)
    echo "Unsupported SSH_PROXY_MODE '${SSH_PROXY_MODE}' (expected deadend or wireguard)" >&2
    exit 1
    ;;
esac
exec python3 ${WEB_TERMINAL_SCRIPT_FILE}
