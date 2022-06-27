"""A single common terminal for all websockets.
"""
from glob import glob
import json
import tornado.web
# This demo requires tornado_xstatic and XStatic-term.js
import tornado_xstatic
import time
from terminado import TermSocket, SingleTermManager
from common_demo_stuff import run_and_show_browser, STATIC_DIR, TEMPLATE_DIR

last_used_time = None

class TerminalPageHandler(tornado.web.RequestHandler):
    def get(self):
        return self.render("termpage.html", static=self.static_url,
                           xstatic=self.application.settings['xstatic_url'],
                           ws_url_path="/websocket")

class ExtendedTermSocket(TermSocket):
    def on_message(self, message):
        global last_used_time
        last_used_time = int(time.time())
        TermSocket.on_message(self, message)

class ActivityHandler(tornado.web.RequestHandler):
    def get(self):
        self.set_header("Content-Type", 'application/json')
        r = json.dumps({'last_used_time': last_used_time})
        self.write(r)

def main(argv):
    term_manager = SingleTermManager(shell_command=['bash'])
    handlers = [
                (r"/websocket", ExtendedTermSocket,
                     {'term_manager': term_manager}),
                (r"/activity", ActivityHandler, {}),
                (r"/", TerminalPageHandler),
                (r"/xstatic/(.*)", tornado_xstatic.XStaticFileHandler,
                     {'allowed_modules': ['termjs']})
               ]
    app = tornado.web.Application(handlers, static_path=STATIC_DIR,
                      template_path=TEMPLATE_DIR,
                      xstatic_url = tornado_xstatic.url_maker('/xstatic/'))
    app.listen(8765, 'localhost')
    run_and_show_browser("http://localhost:8765/", term_manager)

if __name__ == '__main__':
    main([])