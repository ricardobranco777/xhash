#!/bin/bash -e

gcc -o sslv sslv.c -ldl

libdir=$(dirname $(./sslv | sort -k3 -n | awk 'END { print $1 }'))

if [[ $libdir =~ /usr/local/ssl ]] ; then	
	includedir="/usr/local/ssl/include"
else
	includedir="/usr/include"
fi

get_files()
{
	if [ $(id -u) -eq 0 ] ; then
		GOROOT=${GOROOT:-"/go"}
	else
		GOROOT=${GOROOT:-${HOME}/go}
	fi
	echo xhash.go $(find ${GOROOT}/src/github.com/ricardobranco777/dgst -name \*.go ! -name \*_test.go)
}

sed -ri "s%(^#cgo CFLAGS:) -I/usr/include%\1 -I${includedir}%" $(get_files)
sed -ri "s%(^#cgo LDFLAGS: -lcrypto) -L/usr/lib%\1 -L${libdir}%" $(get_files)

go build xhash.go
