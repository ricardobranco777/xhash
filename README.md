# xhash
This Go program uses goroutines to calculate multiple hashes on strings, files and directories.  By default it reads from standard input.  You may select algorithms by groups of digest size, digest family or specific algorithms.  Use the _*-all*_ option to (de)select all algorithms.

# Usage

Usage: xhash [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]

# Blake2

Install the Blake2.net library (libb2-dev package on Ubuntu >= 16.04 systems) for faster hashing of Blake2 algorithms.

# OpenSSL

Install OpenSSL for faster hashing for multiple algorithms.

# Examples:

* To hash the string "abc" with all algorithms

`xhash -s "abc" -all`

* To hash every file in your home directory using both SHA-512 and SHA-256

`xhash -sha512 -sha256 $HOME`

* To hash /etc/password with all algorithms except those of 128 & 160 bits

`xhash -all -128 -160 /etc/passwd`

# Output format

The output format is the same as OpenSSL's *dgst* command.  It may be changed with the _*-bsd*_ option to support the format used by FreeBSD's *md5*, *sha1*, et al; NetBSD's *digest*, or the _*-gnu*_ option to support the format used by *md5sum* and friends.

# Options

* `-0`
    	lines are terminated by a null character (with the -i option)
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
* `-bsd`
    	output hashes in the format used by \*BSD
* `-blake2b256`
    	BLAKE2b256 algorithm
* `-blake2b384`
    	BLAKE2b384 algorithm
* `-blake2b512`
    	BLAKE2b512 algorithm
* `-blake2s256`
    	BLAKE2s256 algorithm
* `-c value`
    	read checksums from file (use _*-c ""*_ to read from standard input)
* `-gnu`
    	output hashes in the format used by \*sum
* `-i value`
    	read pathnames from file (use _*-i ""*_ to read from standard input)
* `-key value`
    	key for HMAC (in hexadecimal). If key starts with '/' read key from specified pathname
* `-md4`
    	MD4 algorithm
* `-md5`
    	MD5 algorithm
* `-quiet`
    	don't print OK for each successfully verified file
* `-ripemd160`
    	RIPEMD160 algorithm
* `-sha1`
    	SHA1 algorithm
* `-sha224`
    	SHA224 algorithm
* `-sha256`
    	SHA256 algorithm
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
* `-status`
    	don't output anything, status code shows success
* `-version`
    	show version and exit
* `-whirlpool`
    	whirlpool algorithm
