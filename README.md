# xhash
This Go program uses goroutines to calculate multiple hashes on strings, files and directories.  By default it reads from standard input.  You may select algorithms by groups of digest size, digest family or specific algorithms.  Use the _*-all*_ option to (de)select all algorithms.

# Usage

Usage: xhash [OPTIONS] [-ossl] [-s STRING...]|[FILE... DIRECTORY...]

# Blake2

Install the Blake2.net library (libb2-dev package on Debian/Ubuntu systems) for faster hashing.

# OpenSSL

The _*-ossl*_ flag is used to call the OpenSSL (and Blake2.net) bindings for faster hashing.

You can compare the performance of each hash algorithm individually:

`file="/usr/bin/docker" ; hashes="-blake2b512 -blake2s256 -md4 -md5 -ripemd160 -sha1 -sha224 -sha256 -sha384 -sha512" ; for h in $hashes ; do echo ${h^^} ; time ./xhash $h $file >/dev/null ; echo ; echo OpenSSL ; time ./xhash -ossl $h $file >/dev/null ; echo ; done`

The same but concurrently:

`file="/usr/bin/docker" ; hashes="-blake2b512 -md4 -md5 -ripemd160 -sha1 -sha224 -sha256 -sha384 -sha512" ; time ./xhash $hashes $file >/dev/null ; echo ; echo OpenSSL ; time ./xhash -ossl $hashes $file >/dev/null ; echo`

# Examples:

* To hash the string "abc" with all algorithms

`xhash -s "abc" -all`

* To hash every file in your home directory using both SHA-512 and SHA-256

`xhash -sha512 -sha256 $HOME`

* The same as above but using the OpenSSL library

`xhash -ssl -sha512 -sha256 $HOME`

* To hash /etc/password with all algorithms except those of 128 & 160 bits

`xhash -all -128 -160 /etc/passwd`

# Options

* `-128`
    	all 128 bits algorithms
* `-160`
    	all 160 bits algorithms
* `-224`
    	all 224 bits algorithms
* `-256`
    	all 256 bits algorithms
* `-384`
    	all 384 bits algorithms
* `-512`
    	all 512 bits algorithms
* `-all`
    	all algorithms
* `-blake2`
    	all BLAKE2 algorithms
* `-blake2b256`
    	BLAKE2b256 algorithm
* `-blake2b384`
    	BLAKE2b384 algorithm
* `-blake2b512`
    	BLAKE2b512 algorithm
* `-blake2s256`
    	BLAKE2s256 algorithm
* `-md4`
    	MD4 algorithm
* `-md5`
    	MD5 algorithm
* `-ripemd160`
    	RIPEMD160 algorithm
* `-sha1`
    	SHA1 algorithm
* `-sha2`
    	all SHA-2 algorithms
* `-sha224`
    	SHA224 algorithm
* `-sha256`
    	SHA256 algorithm
* `-sha3`
    	all SHA-3 algorithms
* `-sha3-224`
    	SHA3-224 algorithm
* `-sha3-256`
    	SHA3-256 algorithm
* `-sha3-384`
    	SHA3-384 algorithm
* `-sha3-512`
    	SHA3-512 algorithm
* `-sha384`
    	SHA384 algorithm
* `-sha512`
    	SHA512 algorithm
* `-sha512-224`
    	SHA512-224 algorithm
* `-sha512-256`
    	SHA512-256 algorithm

# TO DO
* Support HMAC
* Read list of filenames to hash from file
* Support -c option like md5sum(1)
* Use different output formats for display
