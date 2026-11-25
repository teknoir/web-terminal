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

- **No field: nothing changes.** The remote command (`sudo -n k3s kubectl ...`), its stdin and the answers are exactly what they were, and nothing is answered from memory, so this image can run with a backend that never sends the field. One thing is added to an answer: when sudo asked for a password, the error carries `"sudo": "required"` next to the unchanged sentence. The backend sends the password only after it has seen that.
- **With the field, the password is used only when sudo asks for one.** The op first runs exactly as it runs without the field (`sudo -n`, no wrapper, no stdin). A device whose sudo needs no password for kubectl (a NOPASSWD rule, for everything or for `k3s` alone) answers there: the password stays in the pod and never reaches the device. Only sudo's `a password is required` (sudo-rs: `interactive authentication is required`) leads on. That first run is skipped while its answer is known: a plain run said within the last 8 minutes that sudo asks (normally the backend's own call a moment before), or this very password was accepted within the last 5 minutes.
- **Then** every device command of the op is the same argv inside one fixed wrapper, and the password is the first stdin line (never an argument, an environment variable, a file or a log line); the release manifest follows it on the same stdin:

  ```sh
  # the one argument of `sh -c` on the device (one line on the wire: _SUDO_WRAPPER in app/inspect_ops.py)
  IFS= read -r p; [ -n "$p" ] || exit 96
  u=$(id -un); l=; while IFS=: read -r n x; do [ "$n" = "$u" ] && l=1; done </etc/passwd
  k=; for c in /usr/sbin/unix_chkpwd /sbin/unix_chkpwd; do
    [ -n "$l" ] && [ -x "$c" ] || continue
    printf '%s\0' "$p" | "$c" "$u" nullok >/dev/null 2>&1; k=$?; break
  done
  [ "$k" != 7 ] || exit 97
  printf '%s\n' "$p" | LC_ALL=C sudo -S -p '' -v 2>/dev/null || { [ "$k" != 0 ] || exit 98; exit 97; }
  unset p; LC_ALL=C sudo -n k3s kubectl ...; exit $?
  ```

  - The shell reads exactly one line, so the manifest never meets sudo's password reader and the password never reaches kubectl. Nothing else reads the wrapper's stdin before kubectl, and no sudo in particular: with `Defaults log_input` sudo copies its stdin for the log, and a `sudo -n true` probe at this place took the whole manifest (0 of 2000 lines were left, sudo 1.9.16).
  - Before sudo sees the password, PAM's own helper checks it (`unix_chkpwd`, what `pam_unix` runs for a process that is not root). For a wrong password of an account in `/etc/passwd` it answers 7 and sudo is never asked (exit 97). Without a helper or a local account the decision is sudo's.
  - `sudo -S -v` gets the line and end of input; it reads it only if it needs a password. If it refuses a password the helper found right, the login is locked or expired, not wrong (exit 98).
  - The last `sudo -n` is deliberately **not** `exec` and not the last command: without a terminal sudo keys its login on the parent process, and with `exec` (or as the last command, which bash, dash and zsh exec) that parent is sshd, so sudo answers `a password is required` right after `-v` accepted the password (seen on sudo 1.8.21 to 1.9.16).
  - `LC_ALL=C` keeps sudo's messages in the one language the pod reads.
- **Validation:** a string of 1 to 512 UTF-8 bytes without a newline or NUL, else `invalid` (`Field sudoPassword is not valid.`, never the value).
- **A rejected password is never sent again** by this pod: it is remembered for the life of the process, in memory only, under an HMAC of the password with a key that exists only in the process. Another password is tried at once. Commands that carry the password run one at a time in the whole pod (`SUDO_MAX_PARALLEL = 1`), so when the device's password stops matching while pages are open, one command carries the wrong one and none after it. A device that needs no password is still read: the plain run comes first again once nothing is known.
- **What a wrong password costs on the device.** With the helper (every Debian, Ubuntu and L4T has it): nothing that counts. The helper writes one line to the auth log (`unix_chkpwd: password check failed for user`), sudo is not asked, and `pam_faillock`, where a device has it set up, counts no failed login. Without the helper, or for an account that is not in `/etc/passwd`, the password goes to sudo: one line in sudo's log (`1 incorrect password attempt`), but 2 failed logins for `pam_faillock` (sudo asks PAM again when its input has ended, and that is counted too; 1 with sudo-rs). faillock's defaults lock the account at 3 within 15 minutes, which stops `sudo` for the login user for faillock's unlock time (10 minutes by default) and does not touch the device's connection to the platform. That case is what the two rules above are for: one pod sends a wrong password in one command, ever. A new pod (the Shell turned off and on, a restart) has forgotten the rejection and tries once more. Measured with faillock's default limit on Debian 12 and 13, Ubuntu 18.04 to 26.04 and sudo-rs 0.2.13 (`tests/test_sudo_real.py`).
- **Answers:** `device_error` with one of four fixed sentences: sudo needs a password and none (or no usable one) came (the sentence above, with `"sudo": "required"`); `sudo on the robot did not accept the device login the platform holds. Use Other ways.` (`"sudo": "rejected"`); the login is locked or expired although its password is right (not remembered: the next read tries again); or the device keeps no sudo login between two commands (`timestamp_timeout=0`), which the wrapper cannot serve.
- **Log:** the audit line ends in `sudo=-` (no password came), `sudo=unused` (one came and the device asked for none: it stayed in the pod), `sudo=password` (it went to the wrapper on the device) or `sudo=rejected` (it was not sent: the device has refused this one).

Known limits:

- **sudo 1.9.9 (Ubuntu 22.04) with `pam_faillock`:** there even a refused `sudo -n` is a failed login for faillock (later and earlier sudo versions do not ask PAM for it). That is how every read of such a device has always counted, with or without this field: three reads without a password inside 15 minutes lock the login. A read with the password adds nothing to it and clears the count when sudo accepts the password. If the login is locked when the password arrives, the answer is the "locked or expired" sentence, not a rejection.
- A device whose sudo speaks another language than English is not recognised as asking for a password (the plain run is today's command, in the device's locale): it is read as before, without the password.
- Each command in the wrapper leaves one 56-byte record in sudo's timestamp file (`/run/sudo/ts/<uid>`, a tmpfs) that sudo reuses only for the same parent process, so the file grows until the device reboots: about 1 MiB per 19000 wrapped commands. `sudo -K` would clear it, and with it the sudo login of a person in the Shell, so the pod leaves it.
- Whatever runs as the device login user can read the password on its way to sudo (a shell start file runs before the wrapper; a `sudo` earlier in `PATH`). That is why the backend sends it only for callers who may fetch the device login anyway, and never for the computer of a TeknoirBot. With `timestamp_type=global` every process of the login user also has sudo without a password for sudo's timeout (15 minutes by default) after a read.

Code: `app/inspect_ops.py` (not `inspect.py`, which would shadow the standard library module). Tests: `tests/test_inspect.py` (a fake `ssh`, no network). `WT_SUDO_REAL=1 scripts/test.sh tests/test_sudo_real.py` runs the ops against a real sshd and a real sudo in a throwaway container (needs docker; it is not part of CI): password sudo with bash and zsh logins, NOPASSWD for everything and for `k3s` alone, a shared sudo login, sudo input logging (`log_input`), a wrong password with a multi-line manifest behind it, a device without PAM's helper, and `pam_faillock` with its default limit: a wrong password, a login that is locked already, and a password that is changed on the device under open pages. `WT_SUDO_REAL_BASE=ubuntu:20.04` picks another device OS and `WT_SUDO_REAL_SUDO=sudo-rs` (with `ubuntu:26.04`) another sudo.
