#!/usr/bin/env bash
set -eo pipefail

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -n|--namespace)
    NAMESPACE="$2"
    shift # past argument
    shift # past value
    ;;
    -d|--device)
    DEVICE="$2"
    shift # past argument
    shift # past value
    ;;
    -c|--context)
    CONTEXT=$2
    shift # past argument
    shift # past value
    ;;
    -k|--kubeflow)
    KUBEFLOW="true"
    shift # past argument
    ;;
    -h|--help|*)
    echo "$0 -c(--context) <context> -n(--namespace) <namespace> -d(--device) <device-name>"
    exit 0
    ;;
esac
done

if [[ -z "${KUBEFLOW}" ]]; then
  DEVICE_RESOURCE="device.teknoir.org"
else
  DEVICE_RESOURCE="device"
fi

if [[ -z "${CONTEXT}" ]]; then
  export DEVICE_MANIFEST="$(kubectl -n $NAMESPACE get $DEVICE_RESOURCE $DEVICE -o yaml)"
else
  export DEVICE_MANIFEST="$(kubectl --context ${CONTEXT} -n $NAMESPACE get $DEVICE_RESOURCE $DEVICE -o yaml)"
fi

export USERNAME=$(printf "%s\n" "${DEVICE_MANIFEST}" | yq e .spec.keys.data.username - | base64 --decode -i -)
export PASSWORD=$(printf "%s\n" "${DEVICE_MANIFEST}" | yq e .spec.keys.data.userpassword - | base64 --decode -i -)

export REMOTE_ACCESS_ACTIVE=$(printf "%s\n" "${DEVICE_MANIFEST}" | yq e .subresources.status.remote_access.active -)
export REMOTE_ACCESS_PORT=$(printf "%s\n" "${DEVICE_MANIFEST}" | yq e .subresources.status.remote_access.port -)

if ! [[ ${REMOTE_ACCESS_ACTIVE} == true ]] ; then
   echo "error: The device ${DEVICE}, has not enabled remote access, please go to the GUI and enable remote access for the device!" >&2
   exit 1
fi

export RSA_KEY_FILE=$(mktemp -t "$(basename $0)")
printf "%s\n" "${DEVICE_MANIFEST}" | yq e .spec.keys.data.rsa_private - | base64 --decode -i - | tee ${RSA_KEY_FILE} >/dev/null

trap "exit" INT TERM ERR
trap "kill 0" EXIT

mkdir -p /tmp/web-terminal-pids
port_forward() {
  kubectl --context=$CONTEXT port-forward -n "$4" svc/$1 $2:$3 2>&1 &
  child_pid=$!
  echo "$child_pid" > "/tmp/web-terminal-pids/$service.pid"
}

export -f port_forward

forward_and_catch() {
  service=$1
  port_from=$2
  prot_to=$3
  ns=$4
  echo "[$service] Starting port forwarding"
  has_error=true
  while [[ "${has_error}" == "true" ]]; do
    exec 3< <(port_forward ${service} ${port_from} ${prot_to} ${ns})
    has_error=false
    while IFS= read <&3 line && [[ "${has_error}" == "false" ]]
      do
        child_pid=$(cat "/tmp/web-terminal-pids/$service.pid")
        if [[ $line == *"broken pipe"* || $line == *"Timeout"* ]]; then
          echo "[$service] ERROR: $line"
          kill -9 "$child_pid"
          echo "[$service] Restarting port forwarding"
          has_error=true
          break
        else
          echo "[$service][$child_pid] $line"
        fi
      done
  done
  echo "[$service] Port forwarding has stopped"
}

forward_and_catch "deadend" 2222 2222 "$NAMESPACE" &

export DEADENDUSER='teknoir'
export DEADENDHOST="localhost"
export DEADENDPORT='2222'

echo "REMOTE_ACCESS_ACTIVE  = ${REMOTE_ACCESS_ACTIVE}"
echo "REMOTE_ACCESS_PORT    = ${REMOTE_ACCESS_PORT}"
echo "DEADENDHOST           = ${DEADENDHOST}"

./docker-entrypoint.sh ${USERNAME} ${REMOTE_ACCESS_PORT} app/named.py

rm ${RSA_KEY_FILE}