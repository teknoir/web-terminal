import asyncio
import os
import re
import stat
import sys

import tornado.httpclient
import tornado.web
import tornado.websocket
from tornado.testing import AsyncHTTPTestCase, gen_test

import named
import wg_mode
from common_demo_stuff import TEMPLATE_DIR, STATIC_DIR

ALICE = 'alice@example.com'
BOB = 'bob@example.com'
HDR = wg_mode.EMAIL_HEADER


class FakeConfig(wg_mode.WireGuardConfig):
    """Real argv construction, but terminals run `cat` so no ssh/wg-connect is needed."""

    def build_command(self, email, known_hosts_file):
        super().build_command(email, known_hosts_file)  # keep validation
        return ['cat']


def make_config(cls=wg_mode.WireGuardConfig):
    return cls(hub_url='http://wg-hub.teknoir-ztna.svc:8080', namespace='teknoir-demo',
               device='cam-1', sa_token_file='/var/run/secrets/ztna/token',
               remote_username='teknoir', rsa_key_file='/priv.pem')


class WGTestBase(AsyncHTTPTestCase):
    def get_app(self):
        self.manager = wg_mode.WireGuardTermManager(make_config(FakeConfig), max_terminals=100)
        return tornado.web.Application(
            wg_mode.make_handlers(self.manager, named.ActivityHandler, {'path': STATIC_DIR}),
            template_path=TEMPLATE_DIR, term_manager=self.manager, last_used_time=0)

    def tearDown(self):
        self.io_loop.run_sync(self.manager.kill_all)
        super().tearDown()

    def fetch_as(self, path, email=None, **kw):
        headers = kw.pop('headers', {})
        if email is not None:
            headers[HDR] = email
        return self.fetch(path, headers=headers, follow_redirects=False, **kw)

    def new_terminal(self, email):
        resp = self.fetch_as('/new', email)
        self.assertEqual(resp.code, 302)
        return resp.headers['Location'].lstrip('/')

    def ws_url(self, name):
        return 'ws://127.0.0.1:%d/%s/websocket' % (self.get_http_port(), name)

    def ws_request(self, name, email=None):
        headers = {HDR: email} if email else {}
        return tornado.httpclient.HTTPRequest(self.ws_url(name), headers=headers)


class TestAccess(WGTestBase):
    def test_missing_email_is_403(self):
        for path in ('/', '/new'):
            self.assertEqual(self.fetch_as(path).code, 403)
        self.assertEqual(self.manager.terminals, {})

    def test_empty_and_malformed_email_is_403(self):
        for bad in ('', '  ', 'not-an-email', 'a b@example.com', 'a@b.c; rm -rf /',
                    'a"b@example.com', 'a%h@example.com', "a'b@example.com",
                    'a@example.com, b@example.com', 'a@example.com\\x'):
            self.assertEqual(self.fetch_as('/new', bad).code, 403, bad)
        self.assertEqual(self.manager.terminals, {})

    def test_root_and_new_create_and_redirect(self):
        for path in ('/', '/new', '/new/'):
            resp = self.fetch_as(path, ALICE)
            self.assertEqual(resp.code, 302, path)
            name = resp.headers['Location'].lstrip('/')
            self.assertIn(name, self.manager.terminals)
            self.assertEqual(self.manager.owner_of(name), ALICE)

    def test_names_unguessable_and_match_route(self):
        names = {self.new_terminal(ALICE) for _ in range(3)}
        names |= {self.new_terminal(BOB) for _ in range(3)}
        self.assertEqual(len(names), 6)
        for n in names:
            self.assertRegex(n, r'^[A-Za-z0-9_-]{22}$')  # token_urlsafe(16): 128 bits
            self.assertFalse(n.isdigit())

    def test_cap_per_user(self):
        for _ in range(wg_mode.MAX_TERMINALS_PER_USER):
            self.new_terminal(ALICE)
        resp = self.fetch_as('/new', ALICE)
        self.assertEqual(resp.code, 429)
        self.assertEqual(self.manager.live_count(ALICE), 5)
        # other users are unaffected
        self.assertEqual(self.fetch_as('/new', BOB).code, 302)
        # email comparison is case-insensitive: same user
        self.assertEqual(self.fetch_as('/new', ALICE.upper()).code, 429)

    def test_cap_frees_after_terminal_ends(self):
        names = [self.new_terminal(ALICE) for _ in range(5)]
        self.assertEqual(self.fetch_as('/new', ALICE).code, 429)
        self.io_loop.run_sync(lambda: self.manager.terminate(names[0], force=True))
        # wait for the EOF to be processed
        async def settle():
            for _ in range(50):
                if names[0] not in self.manager.terminals:
                    return
                await asyncio.sleep(0.05)
        self.io_loop.run_sync(settle)
        self.assertEqual(self.fetch_as('/new', ALICE).code, 302)

    def test_page_creator_only(self):
        name = self.new_terminal(ALICE)
        self.assertEqual(self.fetch_as('/' + name, ALICE).code, 200)
        self.assertEqual(self.fetch_as('/' + name + '/', ALICE).code, 200)
        self.assertEqual(self.fetch_as('/' + name, BOB).code, 403)
        self.assertEqual(self.fetch_as('/' + name).code, 403)

    def test_unknown_name_is_404_and_creates_nothing(self):
        for path in ('/doesnotexist', '/doesnotexist/', '/AAAAAAAAAAAAAAAAAAAAAA'):
            self.assertEqual(self.fetch_as(path, ALICE).code, 404, path)
        self.assertEqual(self.manager.terminals, {})
        # websocket for an unknown name: refused at the handshake, nothing created
        with self.assertRaises(tornado.httpclient.HTTPClientError) as cm:
            self.io_loop.run_sync(lambda: tornado.websocket.websocket_connect(
                self.ws_request('doesnotexist', ALICE)))
        self.assertEqual(cm.exception.code, 404)
        self.assertEqual(self.manager.terminals, {})
        self.assertEqual(self.manager.creators, {})

    def test_manager_does_not_autocreate(self):
        with self.assertRaises(tornado.web.HTTPError) as cm:
            self.manager.get_terminal('whatever')
        self.assertEqual(cm.exception.status_code, 404)
        self.assertEqual(self.manager.terminals, {})

    @gen_test
    async def test_websocket_creator_only(self):
        name, _ = self.manager.create_terminal(ALICE)
        for who, code in ((None, 403), (BOB, 403)):
            with self.assertRaises(tornado.httpclient.HTTPClientError) as cm:
                await tornado.websocket.websocket_connect(self.ws_request(name, who))
            self.assertEqual(cm.exception.code, code)
        ws = await tornado.websocket.websocket_connect(self.ws_request(name, ALICE))
        self.assertIn('setup', await ws.read_message())
        await ws.write_message('["stdin", "hello\\n"]')
        seen = ''
        for _ in range(20):
            msg = await ws.read_message()
            seen += msg
            if 'hello' in seen:
                break
        self.assertIn('hello', seen)
        ws.close()


class TestCleanup(WGTestBase):
    def test_workdir_private_and_removed_on_terminate(self):
        name = self.new_terminal(ALICE)
        workdir = self.manager.workdirs[name]
        self.assertTrue(os.path.isdir(workdir))
        self.assertEqual(stat.S_IMODE(os.stat(workdir).st_mode), 0o700)
        self.io_loop.run_sync(lambda: self.manager.terminate(name, force=True))
        self.assertFalse(os.path.exists(workdir))
        self.assertNotIn(name, self.manager.creators)
        self.assertEqual(self.fetch_as('/' + name, ALICE).code, 404)

    def test_culler_removes_mapping_and_files(self):
        import datetime
        name = self.new_terminal(ALICE)
        workdir = self.manager.workdirs[name]
        self.manager.terminals[name].last_activity = datetime.datetime.now() - datetime.timedelta(hours=2)
        self.io_loop.run_sync(lambda: named.cull_inactive_terminals(self.manager, 3600))
        self.assertNotIn(name, self.manager.creators)
        self.assertFalse(os.path.exists(workdir))

    def test_kill_all_cleans_everything(self):
        names = [self.new_terminal(ALICE), self.new_terminal(BOB)]
        dirs = [self.manager.workdirs[n] for n in names]
        self.io_loop.run_sync(self.manager.kill_all)
        self.assertEqual(self.manager.creators, {})
        self.assertEqual(self.manager.workdirs, {})
        for d in dirs:
            self.assertFalse(os.path.exists(d))

    def test_spawn_failure_leaves_no_workdir(self):
        class Broken(wg_mode.WireGuardConfig):
            def build_command(self, email, known_hosts_file):
                return ['/nonexistent/definitely-not-here']
        manager = wg_mode.WireGuardTermManager(make_config(Broken))
        before = set(os.listdir(manager.tmp_root or '/tmp'))
        with self.assertRaises(Exception):
            manager.create_terminal(ALICE)
        after = set(os.listdir(manager.tmp_root or '/tmp'))
        self.assertEqual({d for d in after - before if d.startswith('wgterm-')}, set())
        self.assertEqual(manager.creators, {})


class TestCommand(AsyncHTTPTestCase):
    def get_app(self):
        return tornado.web.Application([])

    def test_exact_argv(self):
        cfg = make_config()
        kh = '/tmp/wgterm-x/known_hosts'
        argv = cfg.build_command(ALICE, kh)
        proxy = ("wg-connect --hub-url http://wg-hub.teknoir-ztna.svc:8080 --namespace teknoir-demo "
                 "--device cam-1 --port 22 --direct --sa-token-file /var/run/secrets/ztna/token "
                 "--on-behalf-of alice@example.com --known-hosts-file " + kh)
        self.assertEqual(argv, [
            'ssh',
            '-o', 'LogLevel=ERROR',
            '-o', 'ProxyCommand=' + proxy,
            '-o', 'UserKnownHostsFile=' + kh,
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'HostKeyAlias=cam-1.teknoir-demo.ztna.teknoir',
            '-o', 'ServerAliveInterval=30',
            '-i', '/priv.pem',
            'teknoir@cam-1',
        ])

    def test_no_token_and_no_shell_metacharacters(self):
        cfg = make_config()
        argv = cfg.build_command('a.b+c@example.co.uk', '/tmp/wgterm-x/known_hosts')
        joined = ' '.join(argv)
        self.assertNotIn('Bearer', joined)
        self.assertNotIn('--token ', joined)
        self.assertIn('--sa-token-file /var/run/secrets/ztna/token', joined)
        self.assertIn('--on-behalf-of a.b+c@example.co.uk', joined)

    def test_invalid_email_rejected(self):
        cfg = make_config()
        for bad in ('x@y.z; reboot', '$(id)@example.com', 'a b@example.com', '', 'a@b\nc'):
            with self.assertRaises(ValueError):
                cfg.build_command(bad, '/tmp/k')

    def test_config_validation(self):
        base = dict(hub_url='http://h:8080', namespace='ns', device='d',
                    sa_token_file='/t', remote_username='teknoir', rsa_key_file='/k')
        wg_mode.WireGuardConfig(**base)
        for key, bad in (('hub_url', 'http://h; id'), ('hub_url', ''), ('namespace', 'NS x'),
                         ('device', '$(id)'), ('sa_token_file', 'relative/token'),
                         ('remote_username', 'a b'), ('rsa_key_file', '/k k')):
            with self.assertRaises(wg_mode.ConfigError, msg=key):
                wg_mode.WireGuardConfig(**{**base, key: bad})

    def test_from_env(self):
        cfg = wg_mode.WireGuardConfig.from_env({
            'WG_HUB_URL': 'http://wg-hub:8080', 'WG_NAMESPACE': 'ns', 'WG_DEVICE': 'd',
            'WG_SA_TOKEN_FILE': '/t'})
        self.assertEqual((cfg.remote_username, cfg.rsa_key_file), ('teknoir', '/priv.pem'))
        with self.assertRaises(wg_mode.ConfigError):
            wg_mode.WireGuardConfig.from_env({})

    def test_percent_escaped_in_proxy_command(self):
        cfg = make_config()
        cfg.sa_token_file = '/tmp/a%h/token'  # bypasses validation on purpose
        proxy = cfg.build_command(ALICE, '/tmp/k')[4]
        self.assertIn('/tmp/a%%h/token', proxy)


class TestDefaultModeUnchanged(AsyncHTTPTestCase):
    ENV = {
        'PROXY_CMD': 'ssh -N -W %h:%p teknoir@deadend -p 22',
        'RSA_KEY_FILE': '/priv.pem',
        'REMOTE_USERNAME': 'teknoir',
        'REMOTE_ACCESS_PORT': '49322',
    }

    def get_app(self):
        return tornado.web.Application([])

    def test_default_shell_command_same_as_before(self):
        self.assertEqual(named.default_shell_command(self.ENV), [
            'ssh',
            '-o', 'LogLevel=ERROR',
            '-o', 'ProxyCommand=ssh -N -W %h:%p teknoir@deadend -p 22',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ServerAliveInterval=60',
            '-i', '/priv.pem',
            'teknoir@127.0.0.1',
            '-p', '49322',
        ])

    def test_default_defaults(self):
        cmd = named.default_shell_command({})
        self.assertIn('ProxyCommand=None', cmd)
        self.assertEqual(cmd[-4:], ['/priv.pem', 'teknoir@127.0.0.1', '-p', '49322'])

    def test_default_manager_unchanged(self):
        # the default NamedTermManager keeps auto-creating on attach and uses numeric names
        from terminado import NamedTermManager
        m = NamedTermManager(shell_command=['cat'], max_terminals=10)
        self.assertEqual(m._next_available_name(), '1')

    def test_default_routes_unchanged(self):
        src = open(named.__file__).read()
        self.assertIn(r'(r"/(\w+)/websocket", TerminalSocket', src)
        self.assertIn(r'(r"/(\w+)/?", TerminalPageHandler)', src)
