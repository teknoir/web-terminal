"""A separate terminal for every websocket opened.
"""
import json
import logging
import os
import time

import tornado.web
import tornado.ioloop

from terminado import TermSocket, UniqueTermManager
from common_demo_stuff import TEMPLATE_DIR, STATIC_DIR

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ActivityHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Content-Type", 'application/json')
        last_used_time = self.application.settings.get('last_used_time')
        self.write(json.dumps({'last_used_time': last_used_time}))

class ExtendedTermSocket(TermSocket):
    def on_message(self, message):
        self.application.settings['last_used_time'] = int(time.time())
        super().on_message(message)

class TerminalPageHandler(tornado.web.RequestHandler):
    def get(self):
        return self.render("termpage.html", static=self.static_url,
                           ws_url_path="/websocket")


def main():
    proxy_cmd = os.environ.get('PROXY_CMD')
    rsa_key_file = os.environ.get('RSA_KEY_FILE', '/priv.pem')
    remote_username = os.environ.get('REMOTE_USERNAME', 'teknoir')
    remote_access_port = os.environ.get('REMOTE_ACCESS_PORT', '49322')
    shell_command = [
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
    
    term_manager = UniqueTermManager(shell_command=shell_command)
    handlers = [
        (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": STATIC_DIR}),
        (r"/activity", ActivityHandler),
        (r"/websocket", ExtendedTermSocket, {'term_manager': term_manager}),
        (r"/", TerminalPageHandler),
    ]
    app = tornado.web.Application(
        handlers,
        template_path=TEMPLATE_DIR,
        last_used_time=int(time.time())
    )
    
    server_port = int(os.environ.get('PORT', 8080))
    app.listen(server_port, address='0.0.0.0')
    logger.info("Server listening on 0.0.0.0:%d", server_port)
    
    loop = tornado.ioloop.IOLoop.current()
    try:
        loop.start()
    except KeyboardInterrupt:
        logger.info("Shutting down on SIGINT")
    finally:
        term_manager.shutdown()
        loop.close()

if __name__ == '__main__':
    main()