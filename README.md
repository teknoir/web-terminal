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
| `WG_HUB_URL` | wg-hub broker URL, e.g. `http://wg-hub.teknoir-ztna.svc:8080` |
| `WG_NAMESPACE`, `WG_DEVICE` | teamspace and device to connect to |
| `WG_SA_TOKEN_FILE` | projected service account token (audience `teknoir-ztna`), read by `wg-connect` |
| `REMOTE_USERNAME` (arg 1), `RSA_KEY_FILE` | ssh login user and key, as in deadend mode |

`GET /` and `/new` require the `X-Auth-Request-Email` header (set by oauth2-proxy via ext_authz; only the ingress gateway may reach the pod), create a terminal with an unguessable name bound to that email (max 5 live per user) and redirect to it. Only the creator can open `/<name>` or its websocket; unknown names return 404. Each terminal runs `ssh` with a `wg-connect` ProxyCommand, `StrictHostKeyChecking=yes` and a per-terminal known_hosts file in a private temp dir that is removed when the terminal ends.

Tests: `pip install -r requirements-dev.txt && python -m pytest tests`.
