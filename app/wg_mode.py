"""SSH_PROXY_MODE=wireguard: per-user terminals that reach the device through wg-connect.

The default (deadend) mode in named.py is untouched. In this mode:

* every terminal is created for one authenticated user (the email that the
  ingress gateway's ext_authz put in X-Auth-Request-Email), gets an unguessable
  name and can only be attached by that user;
* a user may hold a limited number of live terminals;
* unknown terminal names never create a terminal;
* each terminal runs ssh with a wg-connect ProxyCommand. wg-connect reads the
  pod's projected service account token file itself and asks the hub to act on
  behalf of the user, so no token is ever in argv or in the environment;
* each terminal has a private 0700 temp dir for its known_hosts file, removed
  when the terminal ends or is culled.
"""
import datetime
import logging
import ipaddress
import os
import re
import secrets
import shlex
import shutil
import tempfile
import time
from urllib.parse import urlsplit

import tornado.web
from terminado import TermSocket, NamedTermManager
from terminado.management import MaxTerminalsReached

logger = logging.getLogger(__name__)

EMAIL_HEADER = 'X-Auth-Request-Email'
MAX_TERMINALS_PER_USER = 5

# Terminal names are secrets.token_urlsafe(16): 22 characters of [A-Za-z0-9_-].
TERM_NAME_PATTERN = r'[A-Za-z0-9_-]+'

# Deliberately strict: no shell metacharacters, no '%' (ssh expands it in
# ProxyCommand), no whitespace, no quotes.
EMAIL_RE = re.compile(r'^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')
_HOST_URL_RE = re.compile(r'^https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]*)?$')
_K8S_NAME_RE = re.compile(r'^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$')
_PATH_RE = re.compile(r'^/[A-Za-z0-9._/-]+$')
_USER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9._-]{0,63}$')


class ConfigError(Exception):
    pass


class TooManyTerminals(Exception):
    pass


def normalize_email(raw):
    """Return the lowercased email if it passes the strict check, else None."""
    if raw is None:
        return None
    raw = raw.strip()
    if not raw or not EMAIL_RE.match(raw):
        return None
    return raw.lower()


def request_email(handler):
    return normalize_email(handler.request.headers.get(EMAIL_HEADER))


def require_email(handler):
    email = request_email(handler)
    if email is None:
        raise tornado.web.HTTPError(403, reason='Forbidden: missing or invalid user identity')
    return email


class WireGuardConfig:
    """What the per-terminal ssh command needs. Built once from the environment."""

    def __init__(self, hub_url, namespace, device, sa_token_file, remote_username, rsa_key_file):
        checks = (
            ('WG_HUB_URL', hub_url, _HOST_URL_RE),
            ('WG_NAMESPACE', namespace, _K8S_NAME_RE),
            ('WG_DEVICE', device, _K8S_NAME_RE),
            ('WG_SA_TOKEN_FILE', sa_token_file, _PATH_RE),
            ('REMOTE_USERNAME', remote_username, _USER_RE),
            ('RSA_KEY_FILE', rsa_key_file, _PATH_RE),
        )
        for name, value, pattern in checks:
            if not value or not pattern.match(value):
                raise ConfigError('%s is missing or has an unsupported value' % name)
        self.hub_url = hub_url
        self.namespace = namespace
        self.device = device
        self.sa_token_file = sa_token_file
        self.remote_username = remote_username
        self.rsa_key_file = rsa_key_file

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        return cls(
            hub_url=env.get('WG_HUB_URL', ''),
            namespace=env.get('WG_NAMESPACE', ''),
            device=env.get('WG_DEVICE', ''),
            sa_token_file=env.get('WG_SA_TOKEN_FILE', ''),
            remote_username=env.get('REMOTE_USERNAME', 'teknoir'),
            rsa_key_file=env.get('RSA_KEY_FILE', '/priv.pem'),
        )

    @property
    def host_key_alias(self):
        # api.KnownHostsAlias(namespace, device) in github.com/teknoir/wg-tunnel/pkg/api
        return '%s.%s.ztna.teknoir' % (self.device, self.namespace)

    @property
    def destination(self):
        return '%s@%s' % (self.remote_username, self.device)

    def ssh_options(self, email, known_hosts_file):
        """ssh options between `ssh` and the destination. The email must already be validated."""
        if normalize_email(email) is None:
            raise ValueError('invalid email')
        proxy_argv = [
            'wg-connect',
            '--hub-url', self.hub_url,
            '--namespace', self.namespace,
            '--device', self.device,
            '--port', '22',
            '--direct',
            '--sa-token-file', self.sa_token_file,
            '--on-behalf-of', email,
            '--known-hosts-file', known_hosts_file,
        ]
        # ssh runs ProxyCommand through the shell and expands '%' tokens in it.
        proxy_command = ' '.join(shlex.quote(a) for a in proxy_argv).replace('%', '%%')
        return [
            '-o', 'LogLevel=ERROR',
            '-o', 'ProxyCommand=' + proxy_command,
            '-o', 'UserKnownHostsFile=' + known_hosts_file,
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'HostKeyAlias=' + self.host_key_alias,
            '-o', 'ServerAliveInterval=30',
            '-i', self.rsa_key_file,
        ]

    def build_command(self, email, known_hosts_file):
        """argv for one terminal. The email must already be validated."""
        return ['ssh'] + self.ssh_options(email, known_hosts_file) + [self.destination]


# Keeps the terminal open after ssh ends, so the user sees why (wg-connect prints
# the hub's denial reason, e.g. device_offline or device_revoked) instead of the
# page turning into a 404 when the process exits at once. The ssh argv is passed
# as positional parameters ("$@"), never interpolated into the script.
HOLD_SCRIPT = (
    '"$@"; rc=$?; '
    'printf \'\\r\\n[WireGuard session ended (exit %s). Open /new to reconnect.]\\r\\n\' "$rc"; '
    'read -t 120 _ || true'
)


def hold_open(command):
    """Wrap a terminal argv so the terminal stays readable after it exits."""
    return ['/bin/sh', '-c', HOLD_SCRIPT, 'wgterm'] + list(command)


class WireGuardTermManager(NamedTermManager):
    """NamedTermManager whose terminals are owned by one user each."""

    def __init__(self, config, max_per_user=MAX_TERMINALS_PER_USER, tmp_root=None, **kwargs):
        # shell_command is always given per terminal; there is no default.
        super().__init__(shell_command=[], **kwargs)
        self.config = config
        self.max_per_user = max_per_user
        self.tmp_root = tmp_root
        self.creators = {}
        self.workdirs = {}

    def owner_of(self, name):
        if name not in self.terminals:
            return None
        return self.creators.get(name)

    def live_count(self, email):
        return sum(1 for n, c in self.creators.items() if c == email and n in self.terminals)

    def authorize(self, name, email):
        """Raise 404 for unknown names and 403 for somebody else's terminal."""
        owner = self.owner_of(name)
        if owner is None:
            raise tornado.web.HTTPError(404)
        if owner != email:
            raise tornado.web.HTTPError(403, reason='Forbidden: not your terminal')

    def get_terminal(self, term_name):
        # Never auto-create (NamedTermManager does).
        try:
            return self.terminals[term_name]
        except KeyError:
            raise tornado.web.HTTPError(404)

    def create_terminal(self, email):
        if self.live_count(email) >= self.max_per_user:
            raise TooManyTerminals(email)
        if self.max_terminals and len(self.terminals) >= self.max_terminals:
            raise MaxTerminalsReached(self.max_terminals)
        name = secrets.token_urlsafe(16)
        while name in self.terminals:
            name = secrets.token_urlsafe(16)
        workdir = tempfile.mkdtemp(prefix='wgterm-', dir=self.tmp_root)  # mode 0700
        os.chmod(workdir, 0o700)
        try:
            command = self.config.build_command(email, os.path.join(workdir, 'known_hosts'))
            name, term = self.new_named_terminal(name=name, shell_command=hold_open(command))
        except BaseException:
            shutil.rmtree(workdir, ignore_errors=True)
            raise
        self.creators[name] = email
        self.workdirs[name] = workdir
        return name, term

    def forget(self, name):
        """Drop the creator mapping and the temp files of a terminal."""
        self.creators.pop(name, None)
        workdir = self.workdirs.pop(name, None)
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    def on_eof(self, ptywclients):
        name = ptywclients.term_name
        super().on_eof(ptywclients)
        self.forget(name)

    async def terminate(self, name, force=False):
        term = self.terminals.get(name)
        try:
            await super().terminate(name, force=force)
        finally:
            if term is not None and not term.ptyproc.isalive():
                self.forget(name)

    async def kill_all(self):
        await super().kill_all()
        for name in list(self.workdirs):
            self.forget(name)
        self.creators.clear()


class WGTerminalSocket(TermSocket):
    """Websocket for /<name>/websocket; only the creator may attach."""

    def prepare(self):
        # Runs before the handshake, so failures are plain HTTP errors.
        email = require_email(self)
        self.term_manager.authorize(self.path_args[0], email)

    def on_message(self, message):
        self.application.settings['last_used_time'] = int(time.time())
        super().on_message(message)
        if self.term_name in self.term_manager.terminals:
            self.term_manager.terminals[self.term_name].last_activity = datetime.datetime.now()


class WGTerminalPageHandler(tornado.web.RequestHandler):
    """Render /<name> for the creator only."""

    def get(self, term_name):
        manager = self.application.settings['term_manager']
        manager.authorize(term_name, require_email(self))
        self.set_header('Cache-Control', 'no-store')
        return self.render('termpage.html', static=self.static_url, ws_url_path='/websocket')


def _hostname(netloc):
    """Lower-case hostname of a Host header or URL netloc, without the port."""
    try:
        parts = urlsplit('//' + netloc)
        parts.port  # raises ValueError for a malformed port such as '8080.evil.example'
        return (parts.hostname or '').lower()
    except ValueError:
        return ''


def _same_site(host, other):
    """other is this host, its parent domain, or another host under the parent
    domain (the terminal hosts sit one label below the platform domain).
    IP addresses only match themselves."""
    host, other = _hostname(host), _hostname(other)
    if not host or not other:
        return False
    if other == host:
        return True
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    if host.count('.') < 2:
        return False
    parent = host.split('.', 1)[1]
    return other == parent or other.endswith('.' + parent)


def require_same_site(handler):
    """CSRF guard for the state-changing GETs (/ and /new).

    Allowed: a same-origin or same-site request (Backstage on the parent domain
    links here), a typed URL or bookmark (Sec-Fetch-Site: none), and any
    user-activated top-level navigation (a click on a link: Sec-Fetch-Mode
    navigate, Sec-Fetch-Dest document, Sec-Fetch-User ?1). Refused: requests a
    foreign page can trigger on its own (img, iframe, fetch, script-driven
    redirects), so it cannot burn the user's terminal cap. Without Sec-Fetch
    headers (old clients, curl) the Origin or Referer must be same-site.
    """
    h = handler.request.headers
    host = (h.get('Host') or '').strip().lower()
    fetch_site = h.get('Sec-Fetch-Site')
    if fetch_site is not None:
        if fetch_site.strip().lower() in ('same-origin', 'same-site', 'none'):
            return
        if (h.get('Sec-Fetch-Mode', '').lower() == 'navigate'
                and h.get('Sec-Fetch-Dest', '').lower() == 'document'
                and h.get('Sec-Fetch-User', '') == '?1'):
            return
        raise tornado.web.HTTPError(403, reason='Cross-site request refused')
    for name in ('Origin', 'Referer'):
        value = h.get(name)
        if value:
            origin_host = urlsplit(value).netloc or ''
            if host and origin_host and _same_site(host, origin_host):
                return
            raise tornado.web.HTTPError(403, reason='Cross-site request refused')
    raise tornado.web.HTTPError(403, reason='Cross-site request refused')
    raise tornado.web.HTTPError(403, reason='Cross-site request refused')


class WGNewTerminalHandler(tornado.web.RequestHandler):
    """Create a terminal for the requesting user and redirect to it."""

    def get(self):
        email = require_email(self)
        require_same_site(self)
        manager = self.application.settings['term_manager']
        try:
            name, terminal = manager.create_terminal(email)
        except TooManyTerminals:
            raise tornado.web.HTTPError(
                429, reason='Too many terminals: close one (max %d per user)' % manager.max_per_user)
        except MaxTerminalsReached:
            raise tornado.web.HTTPError(503, reason='Too many terminals')
        logger.info('New terminal created: %s', name)
        terminal.last_activity = datetime.datetime.now()
        self.set_header('Cache-Control', 'no-store')
        self.redirect('/' + name)


def make_handlers(term_manager, activity_handler, static_handler_args):
    """Route table, same shape as the default mode but with the stricter name regex."""
    return [
        (r'/static/(.*)', tornado.web.StaticFileHandler, static_handler_args),
        (r'/activity', activity_handler),
        (r'/(%s)/websocket' % TERM_NAME_PATTERN, WGTerminalSocket, {'term_manager': term_manager}),
        (r'/new/?', WGNewTerminalHandler),
        (r'/', WGNewTerminalHandler),
        (r'/(%s)/?' % TERM_NAME_PATTERN, WGTerminalPageHandler),
    ]
