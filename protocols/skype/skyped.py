#!/usr/bin/env python
#
#   skyped.py
#
#   Copyright (c) 2007-2013 by Miklos Vajna <vmiklos@vmiklos.hu>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
#   USA.
#
from __future__ import print_function

from ConfigParser import ConfigParser, NoOptionError
from traceback import print_exception
from fcntl import fcntl, F_SETFD, FD_CLOEXEC
from collections import deque
from os.path import join, exists, expanduser
import os, sys, logging, socket, ssl, hashlib

import gobject
import Skype4Py

__version__ = 'gobject-1'


class SkypeProxy(object):

	io_loop = None

	interval_ping_client = 60
	interval_ping_skype = 2

	# Client (only single one allowed) connection / address
	conn = conn_addr = conn_buff = None
	# State is one of: None, 'auth', 'ok', 'close'
	# 'auth' state is monolithic to prevent username guessing
	conn_state = None
	conn_auth_user = None

	class SetupError(Exception): pass


	def __init__(self, options):
		self.opts = options
		self.skype_api = SkypeAPI(options, self.dispatch)
		self.log = logging.getLogger('skyped.loop')


	def get_socket_info(self):
		'Return best-match (address-family, address, port) for configuration.'
		addrinfo = socket.getaddrinfo(
			self.opts.host, self.opts.port, 0, 0, socket.SOL_TCP)

		if not addrinfo:
			self.log.fatal('Failed to match host to a socket address: {}'.format(self.opts.host))
			raise SetupError

		ai_af, ai_addr = set(), list()
		for family, _, _, hostname, addr in addrinfo:
			ai_af.add(family)
			ai_addr.append((addr[0], family))

		if len(ai_af) > 1:
			af_names = dict((v, k) for k,v in vars(socket).viewitems() if k.startswith('AF_'))
			ai_af_names = list(af_names.get(af, str(af)) for af in ai_af)
			if socket.AF_INET not in ai_af:
				self.log.fatal(
					( 'Ambiguous socket host specification (matches address famlies: {}),'
						' refusing to pick one at random - please specify one of the'
						' following addresses directlly instead: {}' )
					.format(', '.join(ai_af_names), ', '.join(ai_addr)) )
				raise SetupError
			self.log.warn( 'Specified host matches more than'
				' one address family ({}), using it as IPv4 (AF_INET).'.format(ai_af_names) )
			af = socket.AF_INET
		else: af = list(ai_af)[0]

		for addr, family in ai_addr:
			if family == af: break
		else: raise SetupError
		if len(ai_addr) > 1:
			self.log.warn( 'Specified host matches more than'
				' one address ({}), using first one: {}'.format(ai_addr, addr) )

		return af, addr, self.opts.port


	def bind(self):
		'Initialize listening socket and I/O loop.'
		assert not self.io_loop
		# TODO: abstract gobject.* methods in this class
		#  and make bind() dispatch to gobject/select paths

		# Create raw listening socket
		sock_af, sock_addr, sock_port = self.get_socket_info()
		sock_raw = socket.socket(sock_af)
		sock_raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		fcntl(sock_raw, F_SETFD, FD_CLOEXEC);
		sock_raw.bind((sock_addr, sock_port))
		sock_raw.listen(1)

		# TLSv1 allows downgrade to broken and vulnerable SSLv3,
		#  as cpython ssl module doesn't allow to specify OP_NO_SSLv3
		# TODO: fix that requiring PyOpenSSL or in some ad-hoc way
		try:
			self.sock = ssl.wrap_socket(
				sock_raw,
				server_side=True,
				do_handshake_on_connect=True,
				certfile=self.opts.config.sslcert,
				keyfile=self.opts.config.sslkey,
				ssl_version=ssl.PROTOCOL_TLSv1 )
		except ssl.SSLError as err:
			self.log.warn('TLS socket wrapping failed (did you create your certificate?)')

		gobject.io_add_watch(self.sock, gobject.IO_IN, self.handle_connect)
		gobject.timeout_add_seconds(self.interval_ping_skype, self.dispatch_skype_ping)

		self.io_loop = gobject.MainLoop()


	def run(self):
		'Run infinite I/O loop. Does not return until stop() is called.'
		self.io_loop.run()

	def stop(self):
		'Stop loop, close api.'
		self.conn_drop()
		self.io_loop.quit()
		self.skype_api.stop()


	def handle_connect(self, sock, event):
		self.log.debug('Handling new connection')
		assert sock is self.sock, sock
		try: conn, addr = self.sock.accept()
		except (ssl.SSLError, socket.error) as err:
			self.log.warn('Error during TLS handshake, dropping connection: {}'.format(err))
		else:
			if self.conn:
				self.log.info( 'Ignoring connection attempt'
					' from {}: another client already connected.'.format(addr) )
				err = True
			else: err = False
		if err:
			conn.close()
			return True

		events_recv = gobject.IO_IN | gobject.IO_ERR | gobject.IO_HUP
		gobject.io_add_watch(conn, events_recv, self.handle_recv)
		gobject.timeout_add_seconds(self.interval_ping_client, self.dispatch_client_ping, conn)

		self.conn_state = 'auth' # send/recv auth data, when available
		self.conn, self.conn_addr = conn, addr
		self.conn_buff = deque()

		return True

	def conn_drop(self):
		if self.conn:
			self.log.info('Closing connection to client: {}'.format(self.conn_addr))
			self.conn.close()
		self.conn = self.conn_addr = None
		self.conn_state = self.conn_auth_user = self.conn_buff = None
		return False


	def handle_recv(self, conn, event):
		# TODO: use O_NOBLOCK here, not to hang gobject loop on recv/send
		# Check if client was disconnected
		if conn is not self.conn: return False

		if event & gobject.IO_IN:
			try: buff = conn.recv(1024) # TODO: hangs the loop
			except (socket.error, AssertionError) as err:
				self.log.error( 'Error while receiving data from'
					' {}, closing connection: {}'.format(self.conn_addr, err) )
				return self.conn_drop()

			assert self.conn_state in ['auth', 'ok', 'close']
			if self.conn_state == 'auth':
				return self.handle_client_auth(buff)
			elif self.conn_state == 'ok':
				for line in buff.splitlines():
					line = line.strip()
					if line: self.skype_api.send(line) # TODO: blocking?
			elif self.conn_state == 'close':
				return False

		if event & (gobject.IO_ERR | gobject.IO_HUP):
			self.log.error( 'Error state on connection'
				' from {}, closing it: {}'.format(self.conn_addr, err) )
			return self.conn_drop()

		return True

	def handle_send(self, conn, event):
		# TODO: use O_NOBLOCK here, not to hang gobject loop on recv/send
		# Check if client was disconnected
		if conn is not self.conn: return False
		if not self.conn_buff: return False

		buff = self.conn_buff.popleft()

		if event & gobject.IO_OUT:
			try: conn.sendall(buff) # TODO: hangs the loop
			except socket.error as err:
				self.log.error( 'Error while sending data to'
					' {}, closing connection: {}'.format(self.conn_addr, err) )
				return self.conn_drop()

		if event & (gobject.IO_ERR | gobject.IO_HUP):
			self.log.error( 'Error state on connection'
				' from {}, closing it: {}'.format(self.conn_addr, err) )
			return self.conn_drop()

		if not self.conn_buff:
			if self.conn_state == 'close': return self.conn_drop()
			return False
		return True


	def handle_client_auth(self, buff):
		# Assume skype.so plugin sends exactly two chunks with len=1024 with auth data
		# This auth has timing side-channel due to "==" string comparisons
		# TODO: drop this authentication if favor of TLS auth
		if not self.conn_auth_user:
			self.conn_auth_user = buff
			return True
		else:
			pw_hash = hashlib.sha1(buff.split(' ', 2)[1].strip()).hexdigest()
			if not all([
					self.conn_auth_user.startswith('USERNAME')\
						and self.conn_auth_user.split(' ', 2)[1].strip() == self.opts.config.username,
					buff.startswith('PASSWORD') and pw_hash == self.opts.config.password ]):
				self.log.error('Client authentication FAILED.')
				self.conn_state = 'close'
				self.dispatch('PASSWORD KO\n')
				return True
			self.log.info('Client authentication successful.')
			self.conn_state = 'ok'
			self.dispatch('PASSWORD OK\n')
			return True


	def dispatch(self, *buff):
		if not self.conn or not self.conn_state:
			self.log.warn('Dropping message(s) - no client relay: {}'.format(buff))
			return False
		if not self.conn_buff:
			gobject.io_add_watch(self.conn, gobject.IO_OUT, self.handle_send)
		self.conn_buff.extend(buff)
		return self.conn_state != 'close'

	def dispatch_client_ping(self, conn):
		# Check if client was disconnected since last ping
		if conn is not self.conn: return False
		return self.dispatch('PING\n')

	def dispatch_skype_ping(self):
		self.skype_api.ping()
		return True


class MockedSkype(object):
	'''Mock class for Skype4Py.Skype(), in case the -m option is used.'''

	def __init__(self, mock):
		sock = open(mock)
		self.lines = sock.readlines()

	def SendCommand(self, c):
		pass

	def Command(self, msg, Block):
		if msg == 'PING':
			return ['PONG']
		line = self.lines[0].strip()
		if not line.startswith('>> '):
			raise Exception('Corrupted mock input')
		line = line[3:]
		if line != msg:
			raise Exception('"%s" != "%s"' % (line, msg))
		self.lines = self.lines[1:] # drop the expected incoming line
		ret = []
		while True:
			# and now send back all the following lines, up to the next expected incoming line
			if len(self.lines) == 0:
				break
			if self.lines[0].startswith('>> '):
				break
			if not self.lines[0].startswith('<< '):
				raise Exception('Corrupted mock input')
			ret.append(self.lines[0][3:].strip())
			self.lines = self.lines[1:]
		return ret


class SkypeAPI(object):

	def __init__(self, options, relay):
		if not options.mock:
			self.skype = Skype4Py.Skype()
			self.skype.OnNotify = self.recv
			if not options.dont_start_skype: self.skype.Client.Start()
		else: self.skype = MockedSkype(options.mock)
		self.opts = options
		self.relay = relay
		self.log = logging.getLogger('skyped.api')

	def encode(self, msg):
		if isinstance(msg, bytes): return msg
		return msg.encode('utf-8', 'backslashreplace')

	def recv(self, msg_text):
		if msg_text == 'PONG': return
		if '\n' in msg_text:
			# crappy skype prefixes only the first line for
			# multiline messages so we need to do so for the other
			# lines, too. this is something like:
			# 'CHATMESSAGE id BODY first line\nsecond line' ->
			# 'CHATMESSAGE id BODY first line\nCHATMESSAGE id BODY second line'
			prefix = ' '.join(msg_text.split(' ', 3)[:3])
			msg_text = ['{} {}'.format(prefix, v) for v in ' '.join(msg_text.split(' ')[3:]).split('\n')]
		else:
			msg_text = [msg_text]
		for line in msg_text:
			line = self.encode(line)
			self.log.debug('<< ' + line)
			self.relay(line + '\n')

	def send(self, msg_text):
		if not msg_text or msg_text == 'PONG': return
		line = self.encode(msg_text)
		self.log.debug('>> ' + line)
		try:
			cmd = self.skype.Command(line, Block=True)
			self.skype.SendCommand(cmd)
			if hasattr(cmd, 'Reply'): self.recv(cmd.Reply) # Skype4Py answer
			else:
				for line in cmd: self.recv(line) # mock can return multiple iterable answers
		except (Skype4Py.SkypeAPIError, Skype4Py.SkypeError) as err:
			self.log.warn('Command failed: {}'.format(line))

	def ping(self):
		try: self.skype.SendCommand(self.skype.Command('PING', Block=True))
		except (Skype4Py.SkypeAPIError, AttributeError) as err:
			self.log.warn('Failed sending ping: {}'.format(err))

	def stop(self):
		if not self.opts.mock and not self.opts.dont_start_skype:
			self.skype.Client.Shutdown()


def main(args=None):
	cfgpath = join(os.environ['HOME'], '.skyped', 'skyped.conf')
	syscfgpath = '/usr/local/etc/skyped/skyped.conf'
	if not exists(cfgpath) and exists(syscfgpath):
		cfgpath = syscfgpath # fall back to system-wide settings
	port = 2727

	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--config',
		metavar='path', default=cfgpath,
		help='path to configuration file (default: %(default)s)')
	parser.add_argument('-H', '--host', default='0.0.0.0',
		help='set the tcp host, supports IPv4 and IPv6 (default: %(default)s)')
	parser.add_argument('-p', '--port', type=int,
		help='set the tcp port (default: %(default)s)')
	parser.add_argument('-l', '--log', metavar='path',
		help='set the log file in background mode (default: none)')
	parser.add_argument('-v', '--version', action='store_true', help='display version information')
	parser.add_argument('-n', '--nofork',
		action='store_true', help="don't run as daemon in the background")
	parser.add_argument('-s', '--dont-start-skype', action='store_true',
		help="assume that skype is running independently, don't try to start/stop it")
	parser.add_argument('-m', '--mock', help='fake interactions with skype (only useful for tests)')
	parser.add_argument('-d', '--debug', action='store_true', help='enable debug messages')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.INFO)
	log = logging.getLogger('skyped.main')

	if opts.version:
		print('skyped {}'.format(__version__))
		return

	cfgpath = opts.config
	if not exists(cfgpath):
		parser.error(( 'Unable to find configuration file at {!r}.'
			' Use the -c option to specify an alternate one.' ).format(cfgpath))

	conf = opts.config = ConfigParser()
	conf.read(cfgpath)
	conf.username = conf.get('skyped', 'username').split('#', 1)[0]
	conf.password = conf.get('skyped', 'password').split('#', 1)[0]
	conf.sslkey = expanduser(conf.get('skyped', 'key').split('#', 1)[0])
	conf.sslcert = expanduser(conf.get('skyped', 'cert').split('#', 1)[0])

	try:
		conf.port = int(conf.get('skyped', 'port').split('#', 1)[0])
		if not opts.port: opts.port = conf.port
	except NoOptionError: pass
	if not opts.port: opts.port = port

	log.debug(
		'Processed config file ({}), username: {}'\
		.format(cfgpath, conf.username) )

	if not opts.nofork:
		# TODO: proper forking - wait for child to start listening
		pid = os.fork()
		if not pid:
			nullin = open(os.devnull, 'r')
			nullout = open(os.devnull, 'w')
			os.dup2(nullin.fileno(), sys.stdin.fileno())
			os.dup2(nullout.fileno(), sys.stdout.fileno())
			os.dup2(nullout.fileno(), sys.stderr.fileno())
		else:
			log.info('skyped is started on port {}, pid: {}'.format(opts.port, pid)) # no it's not
			return

	try:
		server = SkypeProxy(opts)
		server.bind()
	except SkypeProxy.SetupError: return

	def excepthook(exc_type, exc_value, exc_tb):
		if exc_type != KeyboardInterrupt:
			print_exception(exc_type, exc_value, exc_tb)
			code = 1
		else: code = 0
		server.stop()
		sys.exit(code)

	sys.excepthook = excepthook

	log.info('skyped is started on port {}'.format(opts.port))
	server.run()


if __name__ == '__main__': main()
