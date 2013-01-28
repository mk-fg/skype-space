#!/usr/bin/env python
#
#   skyped.py
#
#   Copyright (c) 2007, 2008, 2009, 2010, 2011 by Miklos Vajna <vmiklos@frugalware.org>
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

import sys
import os
import signal
import locale
import time
import socket
import getopt
import Skype4Py
import hashlib
from ConfigParser import ConfigParser, NoOptionError
from traceback import print_exception
from fcntl import fcntl, F_SETFD, FD_CLOEXEC
import ssl

__version__ = "0.1.1"

try:
	import gobject
	hasgobject = True
except ImportError:
	import select
	import threading
	hasgobject = False

def eh(type, value, tb):
	global options

	if type != KeyboardInterrupt:
		print_exception(type, value, tb)
	if hasgobject:
		gobject.MainLoop().quit()
	if options.conn:
		options.conn.close()
	# shut down client if it's running
	try:
		skype.skype.Client.Shutdown()
	except NameError:
		pass
	sys.exit("Exiting.")

sys.excepthook = eh

def wait_for_lock(lock, timeout_to_print, timeout, msg):
	start = time.time()
	locked = lock.acquire(0)
	while not(locked):
		time.sleep(0.5)
		if timeout_to_print and (time.time() - timeout_to_print > start):
			dprint("%s: Waited %f seconds" % \
					(msg, time.time() - start))
			timeout_to_print = False
		if timeout and (time.time() - timeout > start):
			dprint("%s: Waited %f seconds, giving up" % \
					(msg, time.time() - start))
			return False
		locked = lock.acquire(0)
	return True

def input_handler(fd, io_condition = None):
	global options
	global skype
	if options.buf:
		for i in options.buf:
			skype.send(i.strip())
		options.buf = None
		if not hasgobject:
			return True
	else:
		if not hasgobject:
			close_socket = False
			if wait_for_lock(options.lock, 3, 10, "input_handler"):
				try:
						input = fd.recv(1024)
						options.lock.release()
				except Exception, s:
					dprint("Warning, receiving 1024 bytes failed (%s)." % s)
					fd.close()
					options.conn = False
					options.lock.release()
					return False
				for i in input.split("\n"):
					if i.strip() == "SET USERSTATUS OFFLINE":
						close_socket = True
					skype.send(i.strip())
			return not(close_socket)
		try:
			input = fd.recv(1024)
		except Exception, s:
			dprint("Warning, receiving 1024 bytes failed (%s)." % s)
			fd.close()
			return False
		for i in input.split("\n"):
			skype.send(i.strip())
		return True

def skype_idle_handler(skype):
	try:
		c = skype.skype.Command("PING", Block=True)
		skype.skype.SendCommand(c)
	except (Skype4Py.SkypeAPIError, AttributeError), s:
		dprint("Warning, pinging Skype failed (%s)." % (s))
		time.sleep(1)
	return True

def send(txt, tries=10):
	global options
	if hasgobject:
		if not options.conn: return
		try:
			options.conn.sendall(txt)
		except Exception, s:
			dprint("Warning, sending '%s' failed (%s)." % (txt, s))
			options.conn.close()
			options.conn = False
	else:
		for attempt in xrange(1, tries+1):
			if not options.conn: break
			if wait_for_lock(options.lock, 3, 10, "socket send"):
				try:
					 if options.conn: options.conn.sendall(txt)
					 options.lock.release()
				except Exception, s:
					options.lock.release()
					dprint("Warning, sending '%s' failed (%s). count=%d" % (txt, s, count))
					time.sleep(1)
				else:
					break
		else:
			if options.conn:
				options.conn.close()
			options.conn = False
		return done

def bitlbee_idle_handler(skype):
	global options
	done = False
	if options.conn:
		try:
			e = "PING"
			done = send("%s\n" % e)
		except Exception, s:
			dprint("Warning, sending '%s' failed (%s)." % (e, s))
			if hasgobject:
				options.conn.close()
			else:
				if options.conn: options.conn.close()
				options.conn = False
				done = False
	if hasgobject:
		return True
	else:
		return done
	return True

def server(host, port, skype = None):
	global options
	if ":" in host:
		sock = socket.socket(socket.AF_INET6)
	else:
		sock = socket.socket()
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	fcntl(sock, F_SETFD, FD_CLOEXEC);
	sock.bind((host, port))
	sock.listen(1)

	if hasgobject:
		gobject.io_add_watch(sock, gobject.IO_IN, listener)
	else:
		dprint("Waiting for connection...")
		listener(sock, skype)

def listener(sock, skype):
	global options
	if not hasgobject:
		if not(wait_for_lock(options.lock, 3, 10, "listener")): return False
	rawsock, addr = sock.accept()
	try:
		options.conn = ssl.wrap_socket(rawsock,
			server_side=True,
			certfile=options.config.sslcert,
			keyfile=options.config.sslkey,
			ssl_version=ssl.PROTOCOL_TLSv1)
	except (ssl.SSLError, socket.error) as err:
		if isinstance(err, ssl.SSLError):
			dprint("Warning, SSL init failed, did you create your certificate?")
			return False
		else:
			dprint('Warning, SSL init failed')
			return True
	if hasattr(options.conn, 'handshake'):
		try:
			options.conn.handshake()
		except Exception:
			if not hasgobject:
				options.lock.release()
			dprint("Warning, handshake failed, closing connection.")
			return False
	ret = 0
	try:
		line = options.conn.recv(1024)
		if line.startswith("USERNAME") and line.split(' ')[1].strip() == options.config.username:
			ret += 1
		line = options.conn.recv(1024)
		if line.startswith("PASSWORD") and hashlib.sha1(line.split(' ')[1].strip()).hexdigest() == options.config.password:
			ret += 1
	except Exception, s:
		dprint("Warning, receiving 1024 bytes failed (%s)." % s)
		options.conn.close()
		if not hasgobject:
			options.conn = False
			options.lock.release()
		return False
	if ret == 2:
		dprint("Username and password OK.")
		send("PASSWORD OK\n")
		if hasgobject:
			gobject.io_add_watch(options.conn, gobject.IO_IN, input_handler)
		else:
			options.lock.release()
			serverloop(options, skype)
		return True
	else:
		dprint("Username and/or password WRONG.")
		send("PASSWORD KO\n")
		if not hasgobject:
			options.conn.close()
			options.conn = False
			options.lock.release()
		return False

def dprint(msg):
	from time import strftime
	global options

	now = strftime("%Y-%m-%d %H:%M:%S")

	if options.debug:
		try:
			print now + ": " + msg
		except Exception, s:
			try:
				sanitized = msg.encode("ascii", "backslashreplace")
			except Error, s:
				try:
					sanitized = "hex [" + msg.encode("hex") + "]"
				except Error, s:
					sanitized = "[unable to print debug message]"
			print now + "~=" + sanitized
		sys.stdout.flush()
	if options.log:
		sock = open(options.log, "a")
		sock.write("%s: %s\n" % (now, msg))
		sock.close()

class SkypeApi:
	def __init__(self):
		global options
		self.skype = Skype4Py.Skype()
		self.skype.OnNotify = self.recv
		if not options.dont_start_skype:
			self.skype.Client.Start()


	def recv(self, msg_text):
		global options
		if msg_text == "PONG":
			return
		if "\n" in msg_text:
			# crappy skype prefixes only the first line for
			# multiline messages so we need to do so for the other
			# lines, too. this is something like:
			# 'CHATMESSAGE id BODY first line\nsecond line' ->
			# 'CHATMESSAGE id BODY first line\nCHATMESSAGE id BODY second line'
			prefix = " ".join(msg_text.split(" ")[:3])
			msg_text = ["%s %s" % (prefix, i) for i in " ".join(msg_text.split(" ")[3:]).split("\n")]
		else:
			msg_text = [msg_text]
		for i in msg_text:
			try:
				# Internally, BitlBee always uses UTF-8 and encodes/decodes as
				# necessary to communicate with the IRC client; thus send the
				# UTF-8 it expects
				e = i.encode('UTF-8')
			except:
				# Should never happen, but it's better to send difficult to
				# read data than crash because some message couldn't be encoded
				e = i.encode('ascii', 'backslashreplace')
			if options.conn:
				dprint('<< ' + e)
				try:
					send(e + "\n")
				except Exception, s:
					dprint("Warning, sending '%s' failed (%s)." % (e, s))
					if options.conn: options.conn.close()
					options.conn = False
			else:
				dprint('-- ' + e)

	def send(self, msg_text):
		if not len(msg_text) or msg_text == "PONG":
			if msg_text == "PONG":
				options.last_bitlbee_pong = time.time()
			return
		try:
			# Internally, BitlBee always uses UTF-8 and encodes/decodes as
			# necessary to communicate with the IRC client; thus decode the
			# UTF-8 it sent us
			e = msg_text.decode('UTF-8')
		except:
			# Should never happen, but it's better to send difficult to read
			# data to Skype than to crash
			e = msg_text.decode('ascii', 'backslashreplace')
		dprint('>> ' + e)
		try:
			c = self.skype.Command(e, Block=True)
			self.skype.SendCommand(c)
			self.recv(c.Reply)
		except Skype4Py.SkypeError:
			pass
		except Skype4Py.SkypeAPIError, s:
			dprint("Warning, sending '%s' failed (%s)." % (e, s))


def serverloop(options, skype):
	timeout = 1; # in seconds
	skype_ping_period = 5
	bitlbee_ping_period = 10
	bitlbee_pong_timeout = 30
	now = time.time()
	skype_ping_start_time = now
	bitlbee_ping_start_time = now
	options.last_bitlbee_pong = now
	in_error = []
	handler_ok = True
	while (len(in_error) == 0) and handler_ok and options.conn:
		ready_to_read, ready_to_write, in_error = \
			select.select([options.conn], [], [options.conn], \
				timeout)
		now = time.time()
		handler_ok = len(in_error) == 0
		if (len(ready_to_read) == 1) and handler_ok:
			handler_ok = input_handler(ready_to_read.pop())
			# don't ping bitlbee/skype if they already received data
			now = time.time() # allow for the input_handler to take some time
			bitlbee_ping_start_time = now
			skype_ping_start_time = now
			options.last_bitlbee_pong = now
		if (now - skype_ping_period > skype_ping_start_time) and handler_ok:
			handler_ok = skype_idle_handler(skype)
			skype_ping_start_time = now
		if now - bitlbee_ping_period > bitlbee_ping_start_time:
			handler_ok = bitlbee_idle_handler(skype)
			bitlbee_ping_start_time = now
			if options.last_bitlbee_pong:
				if (now - options.last_bitlbee_pong) > bitlbee_pong_timeout:
					dprint("Bitlbee pong timeout")
					# TODO is following line necessary? Should there be a options.conn.unwrap() somewhere?
					# options.conn.shutdown()
					if options.conn:
						options.conn.close()
					options.conn = False
			else:
				options.last_bitlbee_pong = now


def main(args=None):
	global options
	global skype

	cfgpath = os.path.join(os.environ['HOME'], ".skyped", "skyped.conf")
	syscfgpath = "/usr/local/etc/skyped/skyped.conf"
	if not os.path.exists(cfgpath) and os.path.exists(syscfgpath):
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
	parser.add_argument('-s', '--dont-start-skype',
		action='store_true', help="assume that skype is running, don't try to start it")
	parser.add_argument('-d', '--debug', action='store_true', help='enable debug messages')
	options = parser.parse_args(sys.argv[1:] if args is None else args)

	# well, this is a bit hackish. we store the socket of the last connected client
	# here and notify it. maybe later notify all connected clients?
	options.conn = None
	# this will be read first by the input handler
	options.buf = None

	if not os.path.exists(options.config):
		parser.error(( "Can't find configuration file at '%s'."
			"Use the -c option to specify an alternate one." )% options.config)

	cfgpath = options.config
	options.config = ConfigParser()
	options.config.read(cfgpath)
	options.config.username = options.config.get('skyped', 'username').split('#', 1)[0]
	options.config.password = options.config.get('skyped', 'password').split('#', 1)[0]
	options.config.sslkey = os.path.expanduser(options.config.get('skyped', 'key').split('#', 1)[0])
	options.config.sslcert = os.path.expanduser(options.config.get('skyped', 'cert').split('#', 1)[0])

	# hack: we have to parse the parameters first to locate the
	# config file but the -p option should overwrite the value from
	# the config file
	try:
		options.config.port = int(options.config.get('skyped', 'port').split('#', 1)[0])
		if not options.port:
			options.port = options.config.port
	except NoOptionError:
		pass
	if not options.port:
		options.port = port
	dprint("Parsing config file '%s' done, username is '%s'." % (options.config, options.config.username))
	if not options.nofork:
		pid = os.fork()
		if pid == 0:
			nullin = file(os.devnull, 'r')
			nullout = file(os.devnull, 'w')
			os.dup2(nullin.fileno(), sys.stdin.fileno())
			os.dup2(nullout.fileno(), sys.stdout.fileno())
			os.dup2(nullout.fileno(), sys.stderr.fileno())
		else:
			print 'skyped is started on port %s, pid: %d' % (options.port, pid)
			sys.exit(0)
	else:
		dprint('skyped is started on port %s' % options.port)
	if hasgobject:
		server(options.host, options.port)
	try:
		skype = SkypeApi()
	except Skype4Py.SkypeAPIError, s:
		sys.exit("%s. Are you sure you have started Skype?" % s)
	if hasgobject:
		gobject.timeout_add(2000, skype_idle_handler, skype)
		gobject.timeout_add(60000, bitlbee_idle_handler, skype)
		gobject.MainLoop().run()
	else:
		while 1:
			options.conn = False
			options.lock = threading.Lock()
			server(options.host, options.port, skype)


if __name__ == '__main__': main()
