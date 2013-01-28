#include <tunables/global>

/home/skype/skype_env/skype {

	#include <abstractions/base>
	#include <abstractions/user-tmp>
	#include <abstractions/user-download>
	#include <abstractions/nameservice>
	#include <abstractions/ssl_certs>
	#include <abstractions/fonts>
	#include <abstractions/site/base>
	#include <abstractions/site/de>

	@{HOME}/skype_env/skype pix,
	@{HOME}/skype_env/ r,
	@{HOME}/skype_env/** kmr,
	@{HOME}/asound.conf r,
	/usr/share/fonts/X11/** m,

	@{PROC}/*/net/arp r,
	@{PROC}/sys/kernel/ostype r,
	@{PROC}/sys/kernel/osrelease r,

	/dev/ r,
	/dev/tty rw,
	/dev/pts/* rw,

	owner @{HOME}/.Skype/ rw,
	owner @{HOME}/.Skype/** krw,
	owner @{HOME}/.config/Skype/ rw,
	owner @{HOME}/.config/Skype/** krw,

	# Skype locks files
	owner @{HOME}/[dD]ownload{,s}/** k,

	deny @{HOME}/.mozilla/ r, # no idea what it needs there
	deny @{PROC}/[0-9]*/fd/ r,
	deny @{PROC}/[0-9]*/task/ r,
	deny @{PROC}/[0-9]*/task/** r,
	deny /dev/video* mrw,
	deny /sys/devices/pci*/*/usb*/*/*/idVendor r, # scan for usb mics?
	deny /{,usr/,usr/local/}lib{,32,64,x32}/ r, # all deps should be bundled in env-dir

	network,

}
