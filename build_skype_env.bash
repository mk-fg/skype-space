#!/bin/bash
set -e

dir=skype_env

echo "Building skype-env in: $dir"

echo " - cleanup"
rm -rf "$dir"

echo " - copying skype"
cp -R /opt/skype "$dir"

echo " - copying dependency libs"
mkdir "$dir"/lib
ldd "$dir"/skype |
awk '$3 {print $3}' |
while read dep
do cp "$dep" "$dir"/lib/
done

echo " - finished,"\
	"bin: $(du -hs "$dir"/skype | cut -f1)"\
	"libs: $(du -hs "$dir"/lib | cut -f1)"\
	"total: $(du -hs "$dir" | cut -f1)"
