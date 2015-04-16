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

**Update 2015-04-16:**

I've stopped using bitlbee+skype a while (about a year by now) ago, so not sure
if this stuff still works.

I have to use standalone skype occasionally though, and build_skype_env.bash
script worked for me in that (new) use-case, as described in
[this blog post](http://blog.fraggod.net/2015/04/11/skype-setup-on-amd64-without-multilibmultiarchchroot.html).

### skyped

[skyped](https://github.com/mk-fg/skype-space/tree/master/skyped) contains a
rewrite of skyped.py daemon, compatible with bitlbee skype.c plugin I'm using.

See README file there for more details.


### systemd

A set of units to do this:

	# systemctl status user@skype
	● user@skype.service - User Manager for UID skype
	   Loaded: loaded (/usr/lib/systemd/system/user@.service; enabled)
	  Drop-In: /etc/systemd/system/user@skype.service.d
	           └─early_start.conf, env.conf
	   Active: active (running) since Thu 2014-04-17 14:45:48 YEKT; 1 months 29 days ago
	 Main PID: 852 (systemd)
	   Status: "Startup finished in 2.398s."
	   CGroup: /user.slice/user-skype.slice/user@skype.service
	           ├─852 /usr/lib64/systemd/systemd --user
	           ├─854 (sd-pam)
	           ├─dbus.service
	           │ └─992 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation
	           ├─fluxbox.service
	           │ └─961 /usr/bin/fluxbox
	           ├─Xvfb.service
	           │ └─895 /usr/bin/Xvfb :1 -screen 0 800x600x16
	           ├─skyped.service
	           │ └─894 python /home/skype/skyped/skyped -s
	           └─skype.service
	             └─893 /home/skype/skype_env/skype --resources=/home/skype/skype_env


### other stuff

AppArmor profile, configs and a script to pull skype and all the 32-bit libs out
from an Ubuntu vm (so that there's no need to have multilib on amd64).
