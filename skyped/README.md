skyped
--------------------

This is a rewrite of skyped python daemon, compatible with bitlbee skype.c
plugin, with the goals to provide better logging and more robust implementation.

Unfortunately, that thing being a rewrite, it's takes some work to merge it
upstream, even though vmiklos isn't opposed to an idea (see
[vmiklos/bitlbee#7](https://github.com/vmiklos/bitlbee/issues/7)).

A bit more details might be found
[here](http://blog.fraggod.net/2013/02/08/headless-skype-to-irc-gateway-part-4-skyped-bikeshed.html)
(and in related posts).

TODO: rebase it on top of bitlbee python bindings in the future, so it'd be an
independent skype plugin alternative.


Usage
--------------------

Pretty much everything from
[bitlbee skype docs](http://code.bitlbee.org/lh/bitlbee/view/head:/protocols/skype/README)
applies, except replace skyped from bitlbee dir (or installed into
/usr/bin/skyped) with this one.

See `skyped --help` for details on cli (intentionally similar to original
skyped) and `skyped.yaml` file for more configuration options.

See also notes and general caveats of setting up skype with bitlbee
[on the official wiki](http://wiki.bitlbee.org/HowtoSkype).
