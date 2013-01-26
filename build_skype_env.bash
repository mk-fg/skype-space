#!/bin/bash
set -e

dir=skype_env

## CLI
usage() {
	echo >&2 "Usage: $0 [ --debug ]"
	exit 0
}
[[ "$#" -gt 1 || ( -n "$1" && "$1" != '--debug' ) ]] && usage
[[ -n "$1" ]] && debug=true || debug=

echo "Building skype-env in: $dir"
echo " - cleanup"
rm -rf "$dir"
echo " - copying skype"
cp -R /opt/skype "$dir"

echo " - copying dependency libs"
lib="$dir"
cp_deps() {
	ldd "$1" |
	awk '$3 {print $3; next} match($1,/^\//) {print $1}' |
	while read dep
	do
		[[ -e "$lib"/"$(basename "$dep")" ]] && continue
		cp_deps "$dep"
		cp "$dep" "$lib"/
	done
}
cp_deps "$dir"/skype

# Special ldd to use x86 ld.so
sed 's|^RTLDLIST=.*|RTLDLIST=./ld-linux.so.2|' /usr/bin/ldd >"$dir"/ldd
chmod +x "$dir"/ldd

echo " - finished, du: $(du -hs "$dir" | cut -f1)"
