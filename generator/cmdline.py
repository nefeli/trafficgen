import errno
import os
import pprint
import sys
import tempfile
import threading
import time

import pybess.bess as bess
import cli
from pybess.module import *

import commands as bess_commands
import generator.generator_commands as generator_commands
from generator.common import *


class TGENCLI(cli.CLI):

    def __init__(self, bess, cmd_db, **kwargs):
        self.bess = bess
        self.bess_lock = threading.Lock()
        self.cmd_db = cmd_db
        self.__running = dict()
        self.__running_lock = threading.Lock()
        self.this_dir = bess_path = os.getenv('BESS_PATH') + '/bessctl'

        super(TGENCLI, self).__init__(self.cmd_db.cmdlist, **kwargs)

    def port_is_running(self, port):
        with self.__running_lock:
            ret = port in self.__running
        return ret

    def ports(self):
        with self.__running_lock:
            ret = list(self.__running.keys())
        return ret

    def add_session(self, sess):
        """
        Add session to set.  Note that its monitor thread is not started or stopped here.
        """
        with self.__running_lock:
            self.__running[str(sess.port())] = sess

    def remove_session(self, port):
        """
        Remove session from set, and return it.  Note that its monitor thread
        is not yet stopped, if currently running.
        """
        with self.__running_lock:
            ret = self.__running.pop(port, None)
        return ret

    def get_session(self, port):
        with self.__running_lock:
            ret = self.__running.get(str(port), None)
        return ret

    def get_var_attrs(self, var_token, partial_word):
        return self.cmd_db.get_var_attrs(self, var_token, partial_word)

    def split_var(self, var_type, line):
        try:
            return self.cmd_db.split_var(self, var_type, line)
        except self.InternalError:
            return super(TGENCLI, self).split_var(var_type, line)

    def bind_var(self, var_type, line):
        try:
            return self.cmd_db.bind_var(self, var_type, line)
        except self.InternalError:
            return super(TGENCLI, self).bind_var(var_type, line)

    def print_banner(self):
        self.fout.write('Type "help" for more information.\n')

    def get_default_args(self):
        return [self]

    def _handle_broken_connection(self):
        host = self.bess.peer[0]
        if host == 'localhost' or self.bess.peer[0].startswith('127.'):
            self._print_crashlog()
        self.bess.disconnect()

    def call_func(self, func, args):
        try:
            super(TGENCLI, self).call_func(func, args)

        except self.bess.APIError as e:
            self.err(e)
            raise self.HandledError()

        except self.bess.RPCError as e:
            self.err('RPC failed to {}:{} - {}'.format(
                self.bess.peer[0], self.bess.peer[1], e.message))

            self._handle_broken_connection()
            raise self.HandledError()

        except self.bess.Error as e:
            self.err(e)
            self.ferr.write('  BESS daemon response - %s\n' % (e,))
            raise self.HandledError()

    def _print_crashlog(self):
        try:
            log_path = tempfile.gettempdir() + '/bessd_crash.log'
            log = open(log_path).read()
            ctime = time.ctime(os.path.getmtime(log_path))
            self.ferr.write('From {} ({}):\n{}'.format(log_path, ctime, log))
        except Exception as e:
            self.ferr.write('%s is not available: %s' % (log_path, str(e)))

    def loop(self):
        super(TGENCLI, self).loop()
        print('Stopping ports...')
        for port in self.ports():
            generator_commands._stop(self, port)
        print('Killing BESS...')
        bess_commands._do_stop(self)

    def get_prompt(self):
        if self.bess.is_connected():
            return '{} $ '.format(self.bess.peer)

        if self.bess.is_connection_broken():
            self._handle_broken_connection()

        return '<disconnected> $ '


class ColorizedOutput(object):

    def __init__(self, orig_out, color):
        self.orig_out = orig_out
        self.color = color

    def __getattr__(self, attr):
        def_color = '\033[0;0m'  # resets all terminal attributes

        if attr == 'write':
            return lambda x: self.orig_out.write(self.color + x + def_color)
        else:
            return getattr(self.orig_out, attr)


def run_cli():
    interactive = sys.stdin.isatty() and sys.stdout.isatty()

    # Colorize output to standard error
    if interactive and sys.stderr.isatty():
        stderr = ColorizedOutput(sys.stderr, '\033[31m')  # red (not bright)
    else:
        stderr = sys.stderr

    try:
        hist_file = os.path.expanduser('~/.trafficgen_history')
        open(hist_file, 'a+').close()
    except:
        print('Error: Cannot open ~/.trafficgen_history', file=sys.stderr)
        hist_file = None
        raise

    s = bess.BESS()
    cli = TGENCLI(s, generator_commands, ferr=stderr, interactive=interactive,
                  history_file=hist_file)
    print('Starting BESS...')
    bess_commands._do_start(cli, '-k')
    cli.loop()


def run_cmds(instream):
    try:
        s = bess.BESS()
        s.connect()
    except bess.BESS.APIError:
        # show no error msg, since user might be about to launch the daemon
        pass

    cli = TGENCLI(s, generator_commands, fin=instream, ferr=sys.stderr,
                  interactive=False)
    print('Starting BESS...')
    bess_commands._do_start(cli, '-k')
    cli.loop()

    # end of loop due to error?
    if cli.stop_loop:
        if cli.last_cmd:
            cli.ferr.write('  Command failed: %s\n' % cli.last_cmd)
        sys.exit(1)
