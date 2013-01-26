#!/bin/bash
set -e

dir=skype_env

echo "Building skype-env in: $dir"

echo " - cleanup"
rm -rf "$dir"

echo " - copying skype"
cp -R /opt/skype "$dir"

echo " - copying dependency libs"
cp_deps() {
	ldd "$1" |
	awk '$3 {print $3}' |
	while read dep
	do
		[[ -e "$dir"/lib/"$(basename "$dep")" ]] && continue
		cp_deps "$dep"
		cp "$dep" "$dir"/lib/
	done
}
mkdir "$dir"/lib
cp_deps "$dir"/skype

echo " - finished,"\
	"bin: $(du -hs "$dir"/skype | cut -f1)"\
	"libs: $(du -hs "$dir"/lib | cut -f1)"\
	"total: $(du -hs "$dir" | cut -f1)"
