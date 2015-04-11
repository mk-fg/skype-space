#!/bin/bash
set -e

dir=skype_env

## CLI
usage() {
	echo >&2 "Usage: $0 [ --debug ] [ /path/to/skype-from-tarball ]"
	exit 0
}

[[ "$1" = --debug ]] && { set -x; shift; }
[[ "$#" -gt 1 ]] && usage
[[ -n "$1" ]] && skype_src=$1 || {
	skype_src=/opt/skype
	[[ -e "$skype_src" ]] || skype_src=/usr/share/skype
	[[ -e "$skype_src" ]] || { echo >&2 'Failed to find skype root'; exit 1; }
}

skype_bin="$skype_src"/skype
file --brief --mime-type "${skype_bin}" |
	grep -q -e x-executable -e x-sharedlib\
		|| skype_bin=/usr/bin/skype
file --brief --mime-type "${skype_bin}" |
	grep -q -e x-executable -e x-sharedlib\
		|| { echo >&2 'Failed to find skype binary'; exit 1; }

echo "Building skype-env in: $dir"

echo " - cleanup"
rm -rf "$dir"

echo " - copying skype"
cp -R "${skype_src}" "$dir"

[[ -d "$dir"/skype ]] && { echo >&2 "WTF: ${dir}/skype"; exit 1; }
cp "${skype_bin}" "$dir"/skype


echo " - copying dependency libs"
lib="$dir"
cp_deps() {
	ldd "$1" |
	awk '/linux-gate/ {next}
		$3 {print $3; next}
		match($1,/^\//) {print $1}' |
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
