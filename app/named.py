"""One shared terminal per URL endpoint

Plus a /new URL which will create a new terminal and redirect to it.
"""
import datetime
import json
import logging
import os
import time

import tornado.web
import tornado.ioloop
from tornado.ioloop import PeriodicCallback

from terminado import TermSocket, NamedTermManager
from common_demo_stuff import TEMPLATE_DIR, STATIC_DIR
import wg_mode

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ActivityHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Content-Type", 'application/json')
        last_used_time = self.application.settings.get('last_used_time')
        self.write(json.dumps({'last_used_time': last_used_time}))


class TerminalSocket(TermSocket):
    def on_message(self, message):
        self.application.settings['last_used_time'] = int(time.time())
        super().on_message(message)
        if self.term_name in self.term_manager.terminals:
            self.term_manager.terminals[self.term_name].last_activity = datetime.datetime.now()

class TerminalPageHandler(tornado.web.RequestHandler):
    """Render the /ttyX pages"""
    def get(self, term_name):
        return self.render("termpage.html", static=self.static_url,
                           ws_url_path="/websocket")

class NewTerminalHandler(tornado.web.RequestHandler):
    """Redirect to an unused terminal name"""
    def get(self):
        name, terminal = self.application.settings['term_manager'].new_named_terminal()
        logger.info('New terminal created: %s', name)
        terminal.last_activity = datetime.datetime.now()
        self.redirect("/" + name)


async def cull_inactive_terminals(manager, timeout_sec):
    for name in list(manager.terminals):
        try:
            term = manager.terminals[name]
        except KeyError:
            continue
        
        if hasattr(term, 'last_activity'):
            seconds_inactive = (datetime.datetime.now() - term.last_activity).total_seconds()
            if seconds_inactive > timeout_sec:
                logger.warning("Culling terminal '%s' due to %d seconds of inactivity.", name, int(seconds_inactive))
                await manager.terminate(name, force=True)

def default_shell_command(environ=None):
    """The deadend-mode ssh command, built from the environment (PROXY_CMD from the entrypoint)."""
    env = os.environ if environ is None else environ
    proxy_cmd = env.get('PROXY_CMD')
    rsa_key_file = env.get('RSA_KEY_FILE', '/priv.pem')
    remote_username = env.get('REMOTE_USERNAME', 'teknoir')
    remote_access_port = env.get('REMOTE_ACCESS_PORT', '49322')
    return [
        'ssh',
        '-o', 'LogLevel=ERROR',
        '-o', f'ProxyCommand={proxy_cmd}',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'ServerAliveInterval=60',
        '-i', rsa_key_file,
        f"{remote_username}@127.0.0.1",
        '-p', remote_access_port
    ]


def main():
    proxy_mode = os.environ.get('SSH_PROXY_MODE') or 'deadend'
    if proxy_mode not in ('deadend', 'wireguard'):
        raise SystemExit(f"Unsupported SSH_PROXY_MODE '{proxy_mode}' (expected 'deadend' or 'wireguard')")
    wireguard = proxy_mode == 'wireguard'

    if wireguard:
        try:
            wg_config = wg_mode.WireGuardConfig.from_env()
        except wg_mode.ConfigError as e:
            raise SystemExit(f"SSH_PROXY_MODE=wireguard: {e}")
        term_manager = wg_mode.WireGuardTermManager(wg_config, max_terminals=10000)
        logger.info("SSH proxy mode: wireguard (device %s/%s via %s)",
                    wg_config.namespace, wg_config.device, wg_config.hub_url)
    else:
        term_manager = NamedTermManager(shell_command=default_shell_command(), max_terminals=10000)
    
    terminal_timeout_sec = 60 * 60
    async def culler():
        await cull_inactive_terminals(term_manager, terminal_timeout_sec)
    
    culler_period_sec = 10
    logger.info("Starting terminal culler (interval=%ds, timeout=%ds)", culler_period_sec, terminal_timeout_sec)
    PeriodicCallback(culler, 1000 * culler_period_sec).start()

    if wireguard:
        handlers = wg_mode.make_handlers(term_manager, ActivityHandler, {"path": STATIC_DIR})
    else:
        handlers = [
            (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": STATIC_DIR}),
            (r"/activity", ActivityHandler),
            (r"/(\w+)/websocket", TerminalSocket, {'term_manager': term_manager}),
            (r"/new/?", NewTerminalHandler),
            (r"/", NewTerminalHandler),
            (r"/(\w+)/?", TerminalPageHandler)
        ]
    
    application = tornado.web.Application(
        handlers,
        template_path=TEMPLATE_DIR,
        term_manager=term_manager,
        last_used_time=int(time.time())
    )

    server_port = int(os.environ.get('PORT', 8080))
    application.listen(server_port, address='0.0.0.0')
    logger.info("Server listening on 0.0.0.0:%d", server_port)
    loop = tornado.ioloop.IOLoop.current()
    try:
        loop.start()
    except KeyboardInterrupt:
        logger.info("Shutting down on SIGINT")
    finally:
        term_manager.shutdown()
        if wireguard:
            for name in list(term_manager.workdirs):
                term_manager.forget(name)
        loop.close()

if __name__ == "__main__":
    main()
