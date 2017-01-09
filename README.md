# xhash
This Go program uses goroutines to calculate multiple hashes on strings, files and directories.  By default it reads from standard input.  You may select algorithms by groups of digest size, digest family or specific algorithms.  Use the _*-all*_ option to (de)select all algorithms.

# Usage

Usage: xhash [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]

# Blake2

Install the Blake2.net library (libb2-dev package on Debian/Ubuntu systems) for faster hashing of Blake2 algorithms.

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

The output format is the same as OpenSSL's *dgst* command.  It may be changed with the _*-format*_ option.  The default is:

_*{{.Name}}({{.File}}) = {{.Digest}}*_

To support the format used by the \*BSD commands add a space before the opening parenthesis like this:

_*{{.Name}} ({{.File}}) = {{.Digest}}*_

To support the format used by md5sum:

`xhash -md5 -format '{{.Digest}}  {{.File}}' /etc/passwd`

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
* `-blake2b256`
    	BLAKE2b256 algorithm
* `-blake2b384`
    	BLAKE2b384 algorithm
* `-blake2b512`
    	BLAKE2b512 algorithm
* `-blake2s256`
    	BLAKE2s256 algorithm
* `-i value`
    	read pathnames from file (use _*-i ""*_ to read from standard input)
* `-format string`
    	output format (default "{{.Name}}({{.File}}) = {{.Digest}}")
* `-key value`
    	key for HMAC (in hexadecimal)
* `-md4`
    	MD4 algorithm
* `-md5`
    	MD5 algorithm
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
* `-version`
    	show version and exit

# TO DO
* Support -c option like md5sum(1)
