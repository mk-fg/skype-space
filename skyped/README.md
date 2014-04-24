### skyped

This is a rewrite of skyped python daemon, compatible with bitlbee skype.c
plugin, with the goals to provide better logging and more robust implementation.

Unfortunately, that thing being a rewrite, it's takes some work to merge it
upstream, even though vmiklos isn't opposed to an idea (see
[vmiklos/bitlbee#7](https://github.com/vmiklos/bitlbee/issues/7)).

A bit more details might be found
[here](http://blog.fraggod.net/2013/02/08/headless-skype-to-irc-gateway-part-4-skyped-bikeshed.html)
(and in related posts).

TODO: rebase it on top of (currently in early development) bitlbee python
bindings in the future, so it'd be an independent skype plugin alternative.
