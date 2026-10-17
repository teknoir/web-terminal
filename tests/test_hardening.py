import logging
import os

import tornado.web
import tornado.websocket
from tornado.testing import AsyncHTTPTestCase, gen_test

import named
import security
from common_demo_stuff import TEMPLATE_DIR


def test_idle_timeout_default():
    assert named.idle_timeout_from_env({}) == 3600
    assert named.idle_timeout_from_env({'TERMINAL_IDLE_TIMEOUT_SEC': ''}) == 3600


def test_idle_timeout_valid():
    assert named.idle_timeout_from_env({'TERMINAL_IDLE_TIMEOUT_SEC': '120'}) == 120
    assert named.idle_timeout_from_env({'TERMINAL_IDLE_TIMEOUT_SEC': ' 7 '}) == 7


def test_idle_timeout_invalid_warns(caplog):
    for bad in ('abc', '0', '-5', '1.5', '10s'):
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            assert named.idle_timeout_from_env({'TERMINAL_IDLE_TIMEOUT_SEC': bad}) == 3600
        assert 'TERMINAL_IDLE_TIMEOUT_SEC' in caplog.text


def test_merge_csp():
    assert security.merge_csp([]) == ["frame-ancestors 'none'"]
    assert security.merge_csp(["default-src 'self'"]) == ["default-src 'self'; frame-ancestors 'none'"]
    assert security.merge_csp(["default-src 'self'; frame-ancestors *"]) == \
        ["default-src 'self'; frame-ancestors 'none'"]
    assert security.merge_csp(["a 'self'", "b 'self'"]) == \
        ["a 'self'; frame-ancestors 'none'", "b 'self'; frame-ancestors 'none'"]


class Page(tornado.web.RequestHandler):
    def get(self):
        self.set_header('Content-Security-Policy', "default-src 'self'; frame-ancestors https://x.example")
        self.write('ok')


class Plain(tornado.web.RequestHandler):
    def get(self):
        self.write('ok')


class FramingHeaders(AsyncHTTPTestCase):
    def get_app(self):
        return named.make_application([(r'/page', Page), (r'/plain', Plain)], template_path=TEMPLATE_DIR)

    def check(self, path, expect_status, existing=None):
        r = self.fetch(path)
        assert r.code == expect_status
        assert r.headers['X-Frame-Options'] == 'DENY'
        return r.headers.get_list('Content-Security-Policy')

    def test_plain(self):
        assert self.check('/plain', 200) == ["frame-ancestors 'none'"]

    def test_existing_csp_merged(self):
        assert self.check('/page', 200) == ["default-src 'self'; frame-ancestors 'none'"]

    def test_error_response(self):
        assert self.check('/missing', 404) == ["frame-ancestors 'none'"]


class Echo(tornado.websocket.WebSocketHandler):
    pass


class WebsocketHandshake(AsyncHTTPTestCase):
    def get_app(self):
        return named.make_application([(r'/ws', Echo)])

    @gen_test
    async def test_handshake_headers(self):
        conn = await tornado.websocket.websocket_connect(
            'ws://127.0.0.1:%d/ws' % self.get_http_port())
        assert conn.headers['X-Frame-Options'] == 'DENY'
        assert conn.headers['Content-Security-Policy'] == "frame-ancestors 'none'"
        conn.close()


class FakeManager:
    def __init__(self, ages):
        import datetime, types
        now = datetime.datetime.now()
        self.terminals = {n: types.SimpleNamespace(last_activity=now - datetime.timedelta(seconds=a))
                          for n, a in ages.items()}
        self.terminated = []

    async def terminate(self, name, force=False):
        self.terminated.append(name)
        del self.terminals[name]


def test_culler_uses_idle_timeout_from_env():
    import asyncio
    mgr = FakeManager({'old': 100, 'fresh': 1})
    culler, timeout = named.make_culler(mgr, {'TERMINAL_IDLE_TIMEOUT_SEC': '50'})
    assert timeout == 50
    asyncio.run(culler())
    assert mgr.terminated == ['old']
    # invalid value falls back to the 3600 s default, so nothing is culled
    mgr = FakeManager({'old': 100})
    culler, timeout = named.make_culler(mgr, {'TERMINAL_IDLE_TIMEOUT_SEC': 'x'})
    assert timeout == 3600
    asyncio.run(culler())
    assert mgr.terminated == []


class SingleAppFraming(AsyncHTTPTestCase):
    def get_app(self):
        import single
        return single.make_app(object())

    def test_headers(self):
        for path in ('/', '/activity'):
            r = self.fetch(path)
            assert r.code == 200
            assert r.headers['X-Frame-Options'] == 'DENY'
            assert "frame-ancestors 'none'" in r.headers['Content-Security-Policy']


class UniqueAppFraming(AsyncHTTPTestCase):
    def get_app(self):
        import unique
        return unique.make_app(object())

    def test_headers(self):
        for path in ('/', '/activity'):
            r = self.fetch(path)
            assert r.code == 200
            assert r.headers['X-Frame-Options'] == 'DENY'
            assert "frame-ancestors 'none'" in r.headers['Content-Security-Policy']
