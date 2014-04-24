Skype-space
--------------------

Configuration of my local skype setup, based around Xvfb server and "systemd
--user" session to run im-to-irc [bitlbee](http://bitlbee.org/) (located on
different machine from skype) gateway on a headless server(s) as a regular
daemon.

More gory details [can be found
here](http://blog.fraggod.net/2013/01/27/skype-to-irc-gateway-on-a-headless-server-as-a-systemd-user-session-daemon.html)
and
[here](http://blog.fraggod.net/2013/01/28/headless-skype-to-irc-gateway-part-3-bitlbee-skyped.html).


### skyped

[skyped](https://github.com/mk-fg/skype-space/tree/master/skyped) contains a
rewrite of skyped.py daemon, compatible with bitlbee skype.c plugin I'm using.

See README file there for more details.
