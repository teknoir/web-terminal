Demos
=====

requirements
------------

Install requirements to run these demos:

```sh
$ pip install -r requirements.txt
```

named.py:
---------

One shared terminal per URL endpoint

Plus a /new URL which will create a new terminal and redirect to it.

```sh
$ python3 app/named.py
```


single.py:
----------

A single common terminal for all websockets.

```sh
$ python3 app/single.py
```


unique.py:
----------

A separate terminal for every websocket opened.

```sh
$ python3 app/unique.py
```



## WireGuard mode (`SSH_PROXY_MODE=wireguard`)

Alternative to the deadend reverse tunnel, used by the per-device ZTNA web terminal. Default (`deadend`) behaviour is unchanged.

| Env | Meaning |
|---|---|
| `SSH_PROXY_MODE` | `deadend` (default) or `wireguard` |
| `WG_HUB_URL` | wg-hub broker URL, e.g. `http://wg-hub.teknoir-ztna.svc:8081` |
| `WG_NAMESPACE`, `WG_DEVICE` | teamspace and device to connect to |
| `WG_SA_TOKEN_FILE` | projected service account token (audience `teknoir-ztna`), read by `wg-connect` |
| `REMOTE_USERNAME` (arg 1), `RSA_KEY_FILE` | ssh login user and key, as in deadend mode |

`GET /` and `/new` require the `X-Auth-Request-Email` header (set by oauth2-proxy via ext_authz; only the ingress gateway may reach the pod), create a terminal with an unguessable name bound to that email (max 5 live per user) and redirect to it. Only the creator can open `/<name>` or its websocket; unknown names return 404. Each terminal runs `ssh` with a `wg-connect` ProxyCommand, `StrictHostKeyChecking=yes` and a per-terminal known_hosts file in a private temp dir that is removed when the terminal ends.

Tests: `pip install -r requirements-dev.txt && scripts/test.sh` (pytest on `tests/`; under a coding agent it prints only the totals and failures, the full log goes to `.test-logs/`).


## Inspect API (wireguard mode, port 8091)

A read-only second listener for the Backstage backend: it reads logs, events, the pod object and the installed helm release of the robot through the same `wg-connect` ssh path (one ssh ControlMaster per user, `sudo -n k3s kubectl`; with the device password when the backend sends it, see below). Fixed ops `pod`, `events`, `logs` and `release`, strict validation, capped output, Secret values of helm manifests hidden, no content in the logs. Contract: `plans/nextgen/inspect.md` section 3 (workspace).

| Env | Meaning |
|---|---|
| `INSPECT_PRINCIPALS` | comma list of `cluster.local/ns/<ns>/sa/<sa>`; the last `X-Forwarded-Client-Cert` element must carry one of them. Empty or unset: the listener is not started (kill switch) |
| `INSPECT_PORT` | listener port, default 8091 |

Limits worth knowing (the container has 256Mi): the decoded release JSON is capped at 8 MiB (the spec said 32 MiB; `json.loads` of small objects multiplies the size by about 30) and at 400000 objects plus arrays; at most 6 ssh masters (each has its own `wg-connect`); the release manifest (at most 2 MiB) is never parsed in the pod: it is sent on stdin of the fixed device command `sudo -n k3s kubectl --request-timeout=15s create --dry-run=client --validate=false -o json -f -` (Kubernetes' own decoder; no `-n`, which would make kubectl refuse objects that name another namespace, so an object that names none shows the kubeconfig default `default`, not the release namespace) and only the JSON objects that come back are returned as `objects[]` (a v1 List and an `items` array are flattened; a Secret keeps only apiVersion, kind, metadata (no managedFields or last-applied-configuration), a string type, a boolean immutable and the keys of data, stringData and binaryData with the value `<hidden>`; at most 2000 objects, kubectl's stdout at most 4 MiB and its objects at most 2 MiB as compact JSON (measured without building that text), nested at most 200 deep, an object nested over 64 deep is hidden; whatever kubectl could not decode becomes `hidden[]` with a fixed reason, and nothing decodable is the error `release_unparsable`), within an 8 s budget and at most 2 release jobs at a time; pod and events JSON are bounded and parsed on a worker thread. A request body over 4 KiB gets the JSON `invalid` answer up to 64 KiB (the listener's connection limit); above that tornado answers a bare 400.

### sudo with the device password (`sudoPassword`)

Most devices give the login user sudo through its password, so `sudo -n` alone answers `The device login user cannot run kubectl through sudo.` The pod never holds that password at rest (its Secret has the device key only, and it lives in the shared hub namespace). The Backstage backend, which already keeps the password behind its audited credentials gate, may send it with one request in the optional body field `sudoPassword`; the pod uses it for that op and forgets it.

- **No field: nothing changes.** The remote command (`sudo -n k3s kubectl ...`), its stdin and the answers are exactly what they were, so this image can run with a backend that never sends the field.
- **With the field** every device command of the op is the same argv inside one fixed wrapper, and the password is the first stdin line (never an argument, an environment variable, a file or a log line); the release manifest follows it on the same stdin:

  ```sh
  # the one argument of `sh -c` on the device
  IFS= read -r p; if ! sudo -n true 2>/dev/null; then [ -n "$p" ] || exit 96; printf '%s\n' "$p" | sudo -S -p '' -v 2>/dev/null || exit 97; fi; unset p; sudo -n k3s kubectl ...; exit $?
  ```

  The shell reads exactly one line, so the manifest never meets sudo's password reader and the password never reaches kubectl, whatever sudo decides on the device at that moment (a NOPASSWD rule, a login it still has, a prompt). `sudo -S -v` gets one line and then end of input: a wrong password is one failed attempt. The last `sudo -n` is deliberately **not** `exec` and not the last command: without a terminal sudo keys its login on the parent process, and with `exec` (or as the last command, which bash, dash and zsh exec) that parent is sshd, so sudo answers `a password is required` right after `-v` accepted the password (seen on sudo 1.8.21 to 1.9.16).
- **Validation:** a string of 1 to 512 UTF-8 bytes without a newline or NUL, else `invalid` (`Field sudoPassword is not valid.`, never the value).
- **A rejected password is remembered**, in memory only, for 10 minutes, under an HMAC of the password with a key that exists only in the process: it is not sent to the device again (the op runs as if no password had come, and answers the fixed sentence when the device needs one), so open pages do not add failed sudo attempts (at most 2 in any 15 minutes, below pam_faillock's default of 3). Another password is tried at once. A password sudo has not answered for yet is used by one op at a time, and at most 2 ops carry the password at once.
- **Answers:** `device_error` with one of three fixed sentences: sudo needs a password and none came (the sentence above); `sudo on the robot did not accept the device login the platform holds. Use Other ways.`; or the device keeps no sudo login between two commands (`timestamp_timeout=0`), which the wrapper cannot serve.
- **Log:** the audit line ends in `sudo=-` (no password came), `sudo=password` (it went to the wrapper) or `sudo=rejected` (it was not sent).

Code: `app/inspect_ops.py` (not `inspect.py`, which would shadow the standard library module). Tests: `tests/test_inspect.py` (a fake `ssh`, no network). `WT_SUDO_REAL=1 scripts/test.sh tests/test_sudo_real.py` runs the ops against a real sshd and a real sudo in a throwaway container (needs docker; `WT_SUDO_REAL_BASE=ubuntu:20.04` picks another device OS): password sudo with bash and zsh logins, NOPASSWD, a shared sudo login, a wrong password with a multi-line manifest behind it.
