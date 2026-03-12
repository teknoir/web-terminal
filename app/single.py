"""A single common terminal for all websockets.
"""
import json
import logging
import os
import time

import tornado.web
import tornado.ioloop

from terminado import TermSocket, SingleTermManager
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
    term_manager = SingleTermManager(shell_command=['bash'])
    handlers = [
        (r"/websocket", ExtendedTermSocket, {'term_manager': term_manager}),
        (r"/activity", ActivityHandler),
        (r"/", TerminalPageHandler)
    ]
    app = tornado.web.Application(
        handlers,
        static_path=STATIC_DIR,
        template_path=TEMPLATE_DIR,
        last_used_time=int(time.time())
    )
    
    port = int(os.environ.get('PORT', 8080))
    app.listen(port, address='0.0.0.0')
    logger.info("Server listening on 0.0.0.0:%d", port)
    
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