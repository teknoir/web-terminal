"""One shared terminal per URL endpoint

Plus a /new URL which will create a new terminal and redirect to it.
"""
from __future__ import print_function, absolute_import
import logging
import os.path
import sys
import datetime
import logging as log

import tornado.web
# This demo requires tornado_xstatic and XStatic-term.js
import tornado_xstatic
from tornado.ioloop import IOLoop, PeriodicCallback

from terminado import TermSocket, NamedTermManager
from common_demo_stuff import run_and_show_browser, STATIC_DIR, TEMPLATE_DIR

AUTH_TYPES = ("none", "login")
logging.basicConfig(level=logging.INFO)

class TerminalSocket(TermSocket):
    def on_message(self, message):
        super().on_message(message)
        if self.term_name in self.term_manager.terminals:
            self.term_manager.terminals[self.term_name].last_activity = datetime.datetime.now()

class TerminalPageHandler(tornado.web.RequestHandler):
    """Render the /ttyX pages"""
    def get(self, term_name):
        return self.render("termpage.html", static=self.static_url,
                           xstatic=self.application.settings['xstatic_url'],
                           ws_url_path="/websocket")

class NewTerminalHandler(tornado.web.RequestHandler):
    """Redirect to an unused terminal name"""
    def get(self):
        name, terminal = self.application.settings['term_manager'].new_named_terminal()
        log.info('new terminal created')
        terminal.last_activity = datetime.datetime.now()
        self.redirect("/" + name)

async def cull_inactive_terminal(manager, timeout_sec):
    for name in list(manager.terminals):
        try:
            term = manager.terminals[name]
        except KeyError:
            return  # KeyErrors are somewhat expected since the terminal can be terminated as the culling check is made.
        log.info(f"terminal name={name}, last_activity={term.last_activity}")
        if hasattr(term, 'last_activity'):
            seconds_now = datetime.datetime.now().timestamp()
            seconds_inactive = seconds_now - term.last_activity.timestamp()
            # Compute idle properties
            is_time = seconds_inactive > timeout_sec
            # Cull the kernel if all three criteria are met
            if (is_time):
                inactivity = int(seconds_inactive)
                log.warning(f"Culling terminal '{name}' due to {inactivity} seconds of inactivity.")
                await manager.terminate(name, force=True)

def main():
    # shell_command = ['bash']
    tunneluser = os.environ['TEKNOIR_USER']
    port = os.environ['DEVICE_PORT']
    shell_command = ['ssh', '-F', '/app/ssh_config', '-i', '/priv.pem', f"{tunneluser}@127.0.0.1", '-p' f"{port}" ]

    term_manager = NamedTermManager(shell_command = shell_command,
                                     max_terminals=10000)
    terminal_timout_sec = 60 * 60
    async def culler():
            # kill terminals with 1 hour of inactivity
            await cull_inactive_terminal(term_manager, terminal_timout_sec)
    culler_period_sec = 10
    log.info(f"starting terminal culler with interval of {culler_period_sec} seconds, with terminal timeout {terminal_timout_sec} seconds")
    culler = PeriodicCallback( culler, 1000 * culler_period_sec)            
    culler.start()

    handlers = [
                (r"/(\w+)/websocket", TerminalSocket,
                     {'term_manager': term_manager}),
                (r"/new/?", NewTerminalHandler),
                (r"/", NewTerminalHandler),
                (r"/(\w+)/?", TerminalPageHandler),
                (r"/xstatic/(.*)", tornado_xstatic.XStaticFileHandler)
               ]
    application = tornado.web.Application(handlers, static_path=STATIC_DIR,
                              template_path=TEMPLATE_DIR,
                              xstatic_url=tornado_xstatic.url_maker('/xstatic/'),
                              term_manager=term_manager)

    application.listen(8080)
    loop = tornado.ioloop.IOLoop.instance()
    try:
        loop.start()
    except KeyboardInterrupt:
        print(" Shutting down on SIGINT")
    finally:
        term_manager.shutdown()
        loop.close()

if __name__ == "__main__":
    main()
