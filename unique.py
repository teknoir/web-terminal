"""A separate terminal for every websocket opened.
"""
import json
import tornado.web
# This demo requires tornado_xstatic and XStatic-term.js
import tornado_xstatic
import os

from terminado import TermSocket, UniqueTermManager
from common_demo_stuff import run_and_show_browser, TEMPLATE_DIR




class TerminalPageHandler(tornado.web.RequestHandler):
    def get(self):
        return self.render("termpage.html", static=self.static_url,
                           xstatic=self.application.settings['xstatic_url'],
                           ws_url_path="/websocket")

last_used_time = None

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
    tunneluser = os.environ['TEKNOIR_USER']
    port = os.environ['DEVICE_PORT']
    shell_command=['ssh', '-F', '/app/ssh_config', '-i', '/priv.pem', f"{tunneluser}@127.0.0.1", '-p' f"{port}" ]
    term_manager = UniqueTermManager(shell_command = shell_command)
    handlers = [
                (r"/static/(.*)", tornado.web.StaticFileHandler, {"path": 'static'}),
                (r"/activity", ActivityHandler, {}),
                (r"/websocket", ExtendedTermSocket,
                     {'term_manager': term_manager}),
                (r"/", TerminalPageHandler),
                (r"/xstatic/(.*)", tornado_xstatic.XStaticFileHandler,
                     {'allowed_modules': ['termjs']}),
               ]
    app = tornado.web.Application(handlers,
                      template_path=TEMPLATE_DIR,
                      xstatic_url = tornado_xstatic.url_maker('/xstatic/'))
    app.listen(8080, 'localhost')
    run_and_show_browser("http://localhost:8080/", term_manager)

if __name__ == '__main__':
    main([])