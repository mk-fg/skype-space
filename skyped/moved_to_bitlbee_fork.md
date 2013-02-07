Moved to bitlbee tree
----------------------------------------

I ended up rewriting skyped component after all, and for to be at least of some
use to upstream, I've moved the thing into bitlbee tree.

But as I'd hate to make someone else maintain my code upstream, the thing will
probably end up being stuck there forever.


Relevant links
----------------------------------------

Rewritten (proper gobject loop with non-blocking sockets) skyped:

	https://github.com/mk-fg/bitlbee/blob/master/protocols/skype/skyped.py

Plugin with some bugfixes (which I hope will make it upstream) wrt sockets
handling:

	https://github.com/mk-fg/bitlbee/blob/master/protocols/skype/skype.c
