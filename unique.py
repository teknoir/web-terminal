"""A separate terminal for every websocket opened.
"""
import tornado.web
# This demo requires tornado_xstatic and XStatic-term.js
import tornado_xstatic
import os

from terminado import TermSocket, UniqueTermManager
from common_demo_stuff import run_and_show_browser, STATIC_DIR, TEMPLATE_DIR

class TerminalPageHandler(tornado.web.RequestHandler):
    def get(self):
        return self.render("termpage.html", static=self.static_url,
                           xstatic=self.application.settings['xstatic_url'],
                           ws_url_path="/websocket")

def main(argv):
    tunneluser = os.environ['TEKNOIR_USER']
    port = os.environ['DEVICE_PORT']
    shell_command=['ssh', '-F', '/app/ssh_config', '-i', '/priv.pem', f"{tunneluser}@127.0.0.1", '-p' f"{port}" ]
    term_manager = UniqueTermManager(shell_command = shell_command)
    handlers = [
                (r"/websocket", TermSocket,
                     {'term_manager': term_manager}),
                (r"/", TerminalPageHandler),
                (r"/xstatic/(.*)", tornado_xstatic.XStaticFileHandler,
                     {'allowed_modules': ['termjs']})
               ]
    app = tornado.web.Application(handlers, static_path=STATIC_DIR,
                      template_path=TEMPLATE_DIR,
                      xstatic_url = tornado_xstatic.url_maker('/xstatic/'))
    app.listen(8080, 'localhost')
    run_and_show_browser("http://localhost:8080/", term_manager)

if __name__ == '__main__':
    main([])