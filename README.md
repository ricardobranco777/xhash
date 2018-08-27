# xhash
This Go program uses goroutines to calculate multiple hashes on strings, files and directories.  By default it reads from standard input.

# Usage

Usage: xhash [OPTIONS] [-s STRING...]|[FILE... DIRECTORY...]

# OpenSSL

Install OpenSSL 1.1.X for faster hashing for multiple algorithms.

# Examples:

* To hash every file in your home directory using both SHA-512 and SHA-256

`xhash -r -sha512 -sha256 $HOME`

* To hash the /etc/passwd file with all algorithms _except_ MD4 and MD5

`xhash -all -md4 -md5 /etc/passwd`

* To hash the string "abc" with all algorithms

`xhash -all -s "abc"`

* To check the hashes in /tmp/hashes.md5

`xhash -c /tmp/hashes.md5`

* To hash all files specified in /tmp/files.list

`xhash -i /tmp/files.list`

# Output format

The output format is the same as OpenSSL's **dgst** command.  It may be changed with the **-bsd** option to support the format used by FreeBSD's **md5**, **sha1**, _et al_; NetBSD's **digest**, or the **-gnu** option to support the format used by **md5sum** and friends.

# Options

* `-0`
    	lines are terminated by a null character (with the -i option)
* `-all`
    	all algorithms (except others specified, if any)
* `-bsd`
    	output hashes in the format used by \*BSD
* `-blake2b256`
    	BLAKE2b256 algorithm
* `-blake2b384`
    	BLAKE2b384 algorithm
* `-blake2b512`
    	BLAKE2b512 algorithm
* `-c value`
    	read checksums from file (use **-c ""** to read from standard input)
* `-gnu`
    	output hashes in the format used by \*sum
* `-i value`
    	read pathnames from file (use **-i ""** to read from standard input)
* `-key value`
    	key for HMAC (in hexadecimal). If key starts with '/' read key from specified pathname
* `-md4`
    	MD4 algorithm
* `-md5`
    	MD5 algorithm
* `-quiet`
    	don't print OK for each successfully verified file
* `-r`
	recurse into directories
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
* `-v`
	verbose operation (currently useful with the -c option)
* `-version`
    	show version and exit
