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

Tests: `pip install -r requirements-dev.txt && python -m pytest tests`.


## Inspect API (wireguard mode, port 8091)

A read-only second listener for the Backstage backend: it reads logs, events, the pod object and the installed helm release of the robot through the same `wg-connect` ssh path (one ssh ControlMaster per user, `sudo -n k3s kubectl`). Fixed ops `pod`, `events`, `logs` and `release`, strict validation, capped output, Secret values of helm manifests hidden, no content in the logs. Contract: `plans/nextgen/inspect.md` section 3 (workspace).

| Env | Meaning |
|---|---|
| `INSPECT_PRINCIPALS` | comma list of `cluster.local/ns/<ns>/sa/<sa>`; the last `X-Forwarded-Client-Cert` element must carry one of them. Empty or unset: the listener is not started (kill switch) |
| `INSPECT_PORT` | listener port, default 8091 |

Limits worth knowing (the container has 256Mi): the decoded release JSON is capped at 8 MiB (the spec said 32 MiB; `json.loads` of small objects multiplies the size by about 30) and at 400000 objects plus arrays; at most 6 ssh masters (each has its own `wg-connect`); release manifests (at most 2 MiB) are redacted in constant memory and fail closed (YAML events decide; only a plain mapping of one string kind is shown, Secret documents up to 256 KiB are loaded with their values hidden, and any document with an alias, anchor, merge key, tag, nested list, top-level `items` or List kind is hidden whole) within an 8 s budget and at most 2 release jobs at a time; pod and events JSON are bounded and parsed on a worker thread. A request body over 4 KiB gets the JSON `invalid` answer up to 64 KiB (the listener's connection limit); above that tornado answers a bare 400.

Code: `app/inspect_ops.py` (not `inspect.py`, which would shadow the standard library module). Tests: `tests/test_inspect.py` (a fake `ssh`, no network).
