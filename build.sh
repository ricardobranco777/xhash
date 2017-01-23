#!/bin/bash -e

gcc -o tools/sslv tools/sslv.c -ldl

libdir=$(dirname $(tools/sslv | sort -k3 -n | awk 'END { print $1 }'))

if [[ $libdir =~ /usr/local/ssl ]] ; then	
	includedir="/usr/local/ssl/include"
else
	includedir="/usr/include"
fi

get_files()
{
	if [ $(id -u) -eq 0 ] ; then
		GOPATH=${GOPATH:-"/go"}
	else
		GOPATH=${GOPATH:-${HOME}/go}
	fi
	echo xhash.go $(find ${GOPATH}/src/github.com/ricardobranco777/dgst -name \*.go ! -name \*_test.go)
}

sed -ri "s%(^#cgo CFLAGS:) -I/usr/include%\1 -I${includedir}%" $(get_files)
sed -ri "s%(^#cgo LDFLAGS: -lcrypto) -L/usr/lib%\1 -L${libdir}%" $(get_files)

go build
