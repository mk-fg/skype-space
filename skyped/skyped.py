#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
from threading import RLock
from os.path import join, exists, expanduser
import os, sys, socket, errno
import logging, ssl, hashlib, re

import gobject
import Skype4Py
import lya

__version__ = 'gobject-3'


def force_bytes(bytes_or_unicode, encoding='utf-8', errors='backslashreplace'):
	if isinstance(bytes_or_unicode, bytes): return bytes_or_unicode
	return bytes_or_unicode.encode(encoding, errors)

def force_unicode(bytes_or_unicode, encoding='utf-8', errors='replace'):
	if isinstance(bytes_or_unicode, unicode): return bytes_or_unicode
	return bytes_or_unicode.decode(encoding, errors)


class SkypeProxy(object):

	interval_ping_client = 60
	interval_ping_skype = 2
	# Thresholds can be unset to take no action
	ping_thresholds = dict(skype=20, client=120)

	io_loop = sock = None
	events = dict(timers=deque())

	# Client (only single one allowed) connection, address, buffers.
	conn = conn_addr = None
	conn_rx = conn_tx = None

	# Possible states:
	#  - None - no client.
	#  - auth - authentication required. All rx traffic passed to handle_client_auth().
	#  - ok - authenticated user. All rx traffic passed to skype.
	#  - close - send whatever's left in tx buffer and close connection. rx ignored.
	conn_state = None
	conn_auth_user = None # 'auth' state is monolithic to prevent username guessing
	conn_pings = None # used to generate warnings if there are no PONGs

	dispatch_lock = RLock()

	class SetupError(Exception): pass
	class OperationalError(Exception): pass


	def __init__(self, conf, **api_opts):
		self.conf = conf
		self.events = self.events.copy()
		self.skype_api = SkypeAPI(self.dispatch, **api_opts)
		self.log = logging.getLogger('skyped.loop')


	def trace(self, msg, *args, **kw):
		if not self.conf.logging.net_debug: return
		# There can be any kind of binary data in there, so not to confuse the logger...
		msg = force_unicode(msg.format(*args, **kw))
		self.log.debug(u'conn[{}] {}'.format(self.conn_state, msg))

	def get_socket_info(self):
		'''Return best-match tuple of (address-family, address, port) for configuration.
			Raises SetupError if no reasonably unambiguous settings can be resolved.'''
		addrinfo = socket.getaddrinfo(
			self.conf.listen.host, self.conf.listen.port, 0, 0, socket.SOL_TCP)

		if not addrinfo:
			self.log.fatal( 'Failed to match host to'
				' a socket address: {}'.format(self.conf.listen.host) )
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

		return af, addr, self.conf.listen.port


	## Event controls

	ev_in = gobject.IO_IN
	ev_out = gobject.IO_OUT
	ev_err = gobject.IO_ERR | gobject.IO_HUP

	def unbind_ev(self, ev, handle=None):
		if ev in self.events: handle = self.events.pop(ev)
		if isinstance(handle, (int, long)): # gobject event id
			gobject.source_remove(handle)
		return False

	def bind_rx(self, hander, sock=None, ev='rx'):
		self.unbind_ev(ev)
		if sock is None: sock = self.conn
		self.events[ev] = gobject.io_add_watch(sock, self.ev_in | self.ev_err, hander)
		return self.events[ev]

	def bind_tx(self, handler, sock=None):
		self.unbind_ev('tx')
		if sock is None: sock = self.conn
		self.events['tx'] = gobject.io_add_watch(sock, self.ev_out | self.ev_err, handler)
		return self.events['tx']

	def bind_timer(self, ev, interval, handler, *args, **kwargs):
		self.unbind_ev(ev)
		self.events[ev] = gobject.timeout_add_seconds(interval, handler, *args, **kwargs)

	def bind_loop(self):
		self.bind_rx(self.handle_connect, sock=self.sock, ev='accept')
		return gobject.MainLoop()


	## Bind / release listening socket

	def bind(self):
		'Initialize listening socket and I/O loop.'
		assert not self.io_loop
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
				certfile=self.conf.listen.cert,
				keyfile=self.conf.listen.key,
				ssl_version=ssl.PROTOCOL_TLSv1 )
		except ssl.SSLError as err:
			self.log.warn('TLS socket wrapping failed (did you create your certificate?)')
		self.sock.setblocking(0)

		self.io_loop = self.bind_loop()
		self.log.debug('Bound socket, initialized main I/O loop')

	def unbind(self):
		self.io_loop = None
		self.conn_drop()
		if self.sock:
			self.sock.close()
			self.sock = None
		self.log.debug('Released socket, unplugged events')


	## Main loop controls

	def run_loop(self):
		self.io_loop.run()

	def run(self):
		'Run infinite I/O loop. Does not return until stop() is called.'
		if not self.sock: self.bind()
		self.run_loop()

	def stop_loop(self):
		self.io_loop.quit()

	def stop(self):
		'Stop loop, close api.'
		if self.io_loop: self.stop_loop()
		self.unbind()
		self.skype_api.stop()


	## Client handlers / dispatchers

	def handle_connect(self, sock, event):
		'Accepts new connection and sets up initial states/handlers for it.'
		self.log.debug('Handling new connection')
		assert sock is self.sock, sock
		conn = None
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
			if conn: conn.close()
			return True

		self.bind_rx(self.handle_rx, conn)

		self.conn_state = 'auth' # send/recv auth data, when available
		self.conn, self.conn_addr = conn, addr
		self.conn_rx, self.conn_tx = '', ''
		self.conn_pings = dict()

		return True

	def conn_drop(self):
		'Close client connection and flush all related state.'
		if self.conn:
			self.log.info('Closing connection to client: {}'.format(self.conn_addr))
			self.conn.close()
		for ev, handle in self.events.items():
			if ev != 'accept': self.unbind_ev(ev, handle) # hopefully there're no other such events
		self.conn = self.conn_addr = None
		self.conn_state = self.conn_auth_user = self.conn_pings = None
		self.conn_rx = self.conn_tx = None
		return False


	## I/O handlers

	def handle_rx(self, conn, event):
		'''Handle new bytes on client connection.
			Should be called by eventloop when data is available.'''
		if conn is not self.conn: return self.unbind_ev('rx')

		if event & self.ev_in:
			try:
				buff = conn.recv(1024)
				assert buff, 'No data received'
			except AssertionError: return self.conn_drop() # was closed
			except socket.error as err:
				if getattr(err, 'errno', None) != errno.EAGAIN:
					self.log.error( 'Error while receiving data from'
						' {}, closing connection: {}'.format(self.conn_addr, err) )
					return self.conn_drop()
			else: self.conn_rx += buff

			self.trace('<< {!r}', self.conn_rx)
			if '\n' in self.conn_rx: # handle complete lines
				lines = self.conn_rx.split('\n')
				self.conn_rx = lines.pop()

				lines = self.handle_pongs('client', lines)
				if not lines: return True

				assert self.conn_state in ['auth', 'ok', 'close']
				if self.conn_state == 'auth':
					self.handle_client_auth(lines)
				elif self.conn_state == 'ok':
					for line in lines:
						line = line.strip()
						if line: self.skype_api.send(line)
				elif self.conn_state == 'close':
					return self.unbind_ev('rx')

		if event & self.ev_err:
			self.log.error( 'Error state on connection'
				' from {}, closing it'.format(self.conn_addr) )
			return self.conn_drop()

		return True

	def handle_tx(self, conn, event):
		'''Handle sending of buffered data to client.
			Should be called by eventloop when more data can be sent.'''
		with self.dispatch_lock:
			if conn is not self.conn: return self.unbind_ev('tx')
			if not self.conn_tx: return self.unbind_ev('tx') # nothing to send anyway

			if event & self.ev_out:
				try: bs = conn.send(self.conn_tx)
				except socket.error as err:
					if err.errno != errno.EAGAIN:
						self.log.error( 'Error while sending data to'
							' {}, closing connection: {}'.format(self.conn_addr, err) )
						return self.conn_drop()
				else:
					self.trace('>> {!r}', self.conn_tx[:bs])
					self.conn_tx = self.conn_tx[bs:]

			if event & self.ev_err:
				self.log.error( 'Error state on connection'
					' from {}, closing it'.format(self.conn_addr) )
				return self.conn_drop()

			if not self.conn_tx: # sent everything
				if self.conn_state == 'close': return self.conn_drop()
				return self.unbind_ev('tx')
			return True


	def handle_client_auth(self, lines):
		'Only used in "auth" state to check received auth data against config.'
		# This auth has timing side-channel due to "==" string comparisons and py
		# TODO: drop this authentication if favor of TLS auth
		if not self.conn_auth_user:
			self.conn_auth_user, lines = lines[0], lines[1:]
			if not lines: return
		if self.conn_auth_user:
			pw_hash = hashlib.sha1(lines[0].split(' ', 2)[1].strip()).hexdigest()
			auth_checks = [
				self.conn_auth_user.startswith('USERNAME'),
				self.conn_auth_user.startswith('USERNAME')\
					and self.conn_auth_user.split(' ', 2)[1].strip() == self.conf.auth.username,
				lines[0].startswith('PASSWORD'),
				lines[0].startswith('PASSWORD') and pw_hash == self.conf.auth.password ]
			if not all(auth_checks):
				# self.log.debug('Auth checks: {}'.format(auth_checks))
				self.log.error('Client authentication FAILED.')
				self.conn_state = 'close'
				self.dispatch('PASSWORD KO\n')
				return
			self.log.info('Client authentication successful.')
			self.conn_state = 'ok'
			self.dispatch('PASSWORD OK\n')
			if lines[1:]: self.log.warn('Garbage data after auth: {}'.format(lines[1:]))
			# Establish some basic keepalive pings
			self.bind_timer('ping_client', self.interval_ping_client, self.dispatch_client_ping)
			self.bind_timer('ping_skype', self.interval_ping_skype, self.dispatch_skype_ping)

	def dispatch(self, *buff):
		'Buffer raw data lines to be sent to client.'
		with self.dispatch_lock:
			buff = self.handle_pongs('skype', buff)
			if not buff: return True
			self.trace('+>> {!r}', buff)
			if not self.conn or not self.conn_state:
				self.log.warn('Dropping message(s) - no client relay: {!r}'.format(buff))
				return False
			self.conn_tx += ''.join(buff)
			if not self.events.get('tx'): self.bind_tx(self.handle_tx)
			return self.conn_state != 'close'

	def dispatch_client_ping(self):
		'Disconnect client after too many ping fails in a row.'
		if not self.conn: return False
		with self.dispatch_lock:
			self.ping_check( 'client',
				lambda msg: [self.log.error(msg + ', disconnecting client'), self.conn_drop()] )
			return self.dispatch('PING\n')

	def dispatch_skype_ping(self):
		'Crash daemon after failing to ping skype for too long.'
		with self.dispatch_lock:
			self.ping_check('skype', self.fail)
			self.skype_api.send('PING')
			return True


	## Helpers

	def ping_check(self, name, fail_callback):
		'Check if response to specified ping was received.'
		if self.conn_pings is None: return
		err = self.conn_pings.get(name) is False
		if err:
			self.log.warn('Failed to get response to ping ({})'.format(name))
			timeout, ev = self.ping_thresholds.get(name), 'ping_fail_{}'.format(name)
			if timeout and not self.events.get(ev):
				self.bind_timer( ev, timeout, fail_callback,
					'Failed to receive ping ({}) response for {}s'.format(name, timeout) )
		else: self.conn_pings[name] = False
		return err

	def handle_pongs(self, name, lines):
		'Filter out "PONG" responses, acking their presence.'
		if self.conn_pings is None: return lines
		lines_out = list()
		for line in lines:
			if line.strip() == 'PONG':
				self.conn_pings[name] = True
				self.unbind_ev('ping_fail_{}'.format(name))
				continue
			lines_out.append(line)
		return lines_out

	def fail(self, message='unspecified error'):
		self.log.fatal(message)
		raise self.OperationalError(message)


class MockedSkype(object):
	'''Mock class for Skype4Py.Skype(), in case the -m option is used.'''

	def __init__(self, mock):
		self.lines = open(mock).readlines()

	def SendCommand(self, c):
		pass

	def Command(self, msg):
		if not self.lines: return None # finished
		if msg == 'PING': return ['PONG']
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

	# Relayed max length minus the "CHATMESSAGE <id> BODY " prefix
	# Messages are split by unicode words, but length is measured *in bytes*
	# IRC allows 400+ byte messages (512 - len('PRIVMSG chan-name :\r\n'))
	message_max_length = 120

	def __init__(self, relay, mock=False, dont_start_skype=False):
		if not mock:
			self.skype = Skype4Py.Skype()
			self.skype.RegisterEventHandler('Notify', self.recv)
			self.skype.RegisterEventHandler('Reply', self.recv)
			if not dont_start_skype: self.skype.Client.Start()
		else: self.skype = MockedSkype(mock)
		self.mock, self.dont_start_skype = mock, dont_start_skype
		self.relay = relay
		self.log = logging.getLogger('skyped.api')

	def message_split(self, line, max_length, cont_mark=u'.. '):
		'''Split single-line message by-word to conform to message_max_length,
			preserving indents and original inter-word spaces.'''
		cont, line = u'', force_unicode(line)
		match = re.search(r'^\s+', line) # find if there's some indent
		line_indent = match.group(0) if match else u''
		match, line = None, line[len(line_indent):]
		while True:
			if match is None: line_split = list() # first line or line was appended
			match = re.search(ur'(?u)(\S+)(\s+)?', line) # split by-word, preserving spaces
			if not match:
				assert not line.strip(), line # make sure nothing is left there
				if line_split: yield force_bytes(line_indent + cont + u''.join(line_split))
				break
			else: line = line[len(match.group(0)):]
			line_split.append(match.group(1)) # append word
			line_part = force_bytes(line_indent + cont + u''.join(line_split)) # encode with indent
			if len(line_part) > max_length: # length of encoded msg in bytes
				if len(line_split) < 2: # single word exceeds length as it is
					yield line_part
					cont, match = cont_mark, None
				else:
					if len(line_split) > 2: line_split.pop() # trailing spaces
					yield force_bytes(line_indent + cont + u''.join(line_split[:-1]))
					cont, line_split = cont_mark, [match.group(1), match.group(2) or u''] # last word+spaces
			else: line_split.append(match.group(2) or u'') # append spaces as well

	def recv(self, msg):
		if isinstance(msg, Skype4Py.api.Command):
			msg = msg.Reply
		msg = force_bytes(msg)
		match = re.search(r'^(?s)(CHATMESSAGE\s+\d+\s+BODY\s)(.*)$', msg)
		if match:
			msg, (prefix, line) = list(), match.groups()
			for line in (line or '').split('\n'):
				if len(line) < self.message_max_length:
					msg.append(prefix + line)
				else: # split long lines into several shorter ones
					for line in self.message_split(line, self.message_max_length):
						msg.append(prefix + line)
		else: msg = [msg]
		for line in msg:
			if not line: continue
			if line != 'PONG': self.log.debug('<< ' + force_unicode(line)) # too much idle noise
			self.relay(line + '\n')

	def send(self, msg_text):
		if not msg_text: return
		line = force_bytes(msg_text)
		if not line: return
		if line != 'PING': self.log.debug('>> ' + force_unicode(line)) # too much idle noise
		try:
			cmd = self.skype.Command(line)
			if self.mock and cmd is None: return
			self.skype.SendCommand(cmd)
			if self.mock: # mock provides immediate replies
				for line in cmd: self.recv(line)
		except (Skype4Py.SkypeAPIError, Skype4Py.SkypeError) as err:
			self.log.warn(u'Command failed: {}'.format(force_unicode(line)))

	def stop(self):
		if not self.mock and not self.dont_start_skype:
			self.skype.Client.Shutdown()


def main(args=None):
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--config',
		action='append', metavar='path', default=list(),
		help='Configuration files to process.'
			' Can be specified more than once.'
			' Values from the latter ones override values in the former.'
			' Available CLI options override the values in any config.')
	parser.add_argument('-H', '--host',
		help='set the tcp host, supports IPv4 and IPv6 (default: %(default)s)')
	parser.add_argument('-p', '--port', type=int, help='set the tcp port')
	parser.add_argument('-v', '--version', action='store_true', help='display version information')
	parser.add_argument('-s', '--dont-start-skype', action='store_true',
		help="assume that skype is running independently, don't try to start/stop it")
	parser.add_argument('-m', '--mock', help='fake interactions with skype (only useful for tests)')
	parser.add_argument('-d', '--debug', action='store_true', help='enable debug messages')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	if opts.version:
		print('skyped {}'.format(__version__))
		return

	## Read configuration
	cfg = lya.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in opts.config: cfg.update_yaml(k)
	if cfg: cfg.update_dict(cfg)

	## Logging
	lya.configure_logging( cfg.logging,
		logging.DEBUG if opts.debug else logging.WARNING )
	log = logging.getLogger('skyped.main')

	## Process CLI overrides
	if opts.host: cfg.listen.host = opts.host
	if opts.port: cfg.listen.port = opts.port

	## Start the thing
	try:
		server = SkypeProxy( cfg,
			mock=opts.mock, dont_start_skype=opts.dont_start_skype )
		server.bind()
	except SkypeProxy.SetupError: return

	def excepthook(exc_type, exc_value, exc_tb):
		if exc_type != KeyboardInterrupt:
			try: log.fatal('skyped crashed ({}): {}'.format(exc_type, exc_value))
			except: pass
			print_exception(exc_type, exc_value, exc_tb, limit=30)
			code = 1
		else: code = 0
		server.stop()
		sys.exit(code)
	sys.excepthook = excepthook

	log.info('skyped is started')
	server.run()


if __name__ == '__main__': main()
