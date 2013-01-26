#!/usr/bin/ppy
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function


import itertools as it, operator as op, functools as ft
from time import time, sleep
import os, sys, logging, errno


from cffi import FFI
import capng

# Try to work around insane "write_table" operations (which assume that
#  they can just write lextab.py and yacctab.py in current dir), used by default.
Lexer = LRGeneratedTable = None
try: from ply.lex import Lexer
except ImportError: pass
try: from pycparser.ply.lex import Lexer
except ImportError: pass
try: from ply.yacc import LRGeneratedTable
except ImportError: pass
try: from pycparser.ply.yacc import LRGeneratedTable
except ImportError: pass
if Lexer: Lexer.writetab = lambda s,*a,**k: None
if LRGeneratedTable: LRGeneratedTable.write_table = lambda s,*a,**k: None


class NSControl(object):

	def __init__(self, callback):
		self.ffi = FFI()
		self.ffi.cdef('int ns_clone(int (*fn)(void *));')

		self.libc = self.ffi.verify('''
			#include <sched.h>
			#include <signal.h>

			static char stack[{stack_size}];

			static int ns_clone(int (*fn)(void *)) {{
				int child_pid = clone( fn,
					stack + {stack_size},
					CLONE_NEWNS | SIGCHLD, NULL );
				return child_pid;
			}}
		'''.format(stack_size=1 * 2**20)) # 1 MiB

		self.callback = callback

	def child_func(self, null_p):
		self.callback()
		return 0

	def clone(self):
		child_pid = self.libc.ns_clone(
			self.ffi.callback('int(void *)', self.child_func) )
		if child_pid < 0:
			err = self.ffi.errno
			err, err_msg = (errno.errorcode[err], os.strerror(err))\
				if err else ('none', 'errno was set to 0')
			raise OSError('Failed to fork child process: [{}] {}'.format(err, err_msg))
		return child_pid


def ns_main():
	print('TODO: chroot, proper ns list, etc')

	# Just exec skype
	# os.execl('/skype', '--resources=/')

def main(argz=None):
	import argparse
	parser = argparse.ArgumentParser(description='collectd configuration file updater.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args(argz or sys.argv[1:])

	global log
	logging.basicConfig(level=logging.DEBUG if optz.debug else logging.INFO)
	log = logging.getLogger()

	nsc = NSControl(ns_main)

	# iddqd, idkfa
	try:
		assert not capng.capng_get_caps_process()
		assert not capng.capng_update(
			capng.CAPNG_ADD,
			capng.CAPNG_EFFECTIVE,
			capng.CAP_SYS_ADMIN )
		assert not capng.capng_apply(capng.CAPNG_SELECT_CAPS)
	except (OSError, AssertionError) as err:
		raise OSError('Failed to enable necessary capabilities: {}'.format(err))
	else:
		log.debug('Capabilities enabled: {}'.format(
			capng.capng_print_caps_text(
				capng.CAPNG_PRINT_BUFFER, capng.CAPNG_EFFECTIVE ) ))

	# Start the namespaced skype
	os.waitpid(nsc.clone(), 0)
	log.debug('Finished')


if __name__ == '__main__': main()
