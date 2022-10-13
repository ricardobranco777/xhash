# xhash
This Go program uses goroutines to calculate multiple hashes on strings, files and directories.  By default it reads from standard input.

## Examples:

* To hash every file in your home directory using both SHA-512 and SHA-256

`xhash -r -sha512 -sha256 $HOME`

* To hash the /etc/passwd file with all algorithms _except_ MD5 and SHA-1

`xhash -all -md5 -sha1 /etc/passwd`

* To hash the string "abc" with all algorithms

`xhash -all -s "abc"`

* To check the hashes in /tmp/hashes.md5

`xhash -c /tmp/hashes.md5`

* To hash all files specified in /tmp/files.list

`xhash -i /tmp/files.list`

## Output format

The output format is the same as OpenSSL's **dgst** command.  It may be changed with the `--bsd` option to support the format used by FreeBSD's **md5**, **sha1**, etc; NetBSD's **digest**, or the `---gnu` option to support the format used by **md5sum** and friends.

## Usage

```
Usage: xhash [OPTIONS] [-s STRING...]|[-c FILE]|[-i FILE]|[FILE...]|[-r FILE... DIRECTORY...]

  -a, --all              all algorithms (except others specified, if any)
      --blake2b-256      BLAKE2b-256 algorithm
      --blake2b-512      BLAKE2b-512 algorithm
      --bsd              output hashes in the format used by *BSD
  -c, --check string     read checksums from file (use "" for stdin) (default "\x00")
  -f, --format string    output format (default "{{range .}}{{.Name}}({{.File}}) = {{.Sum}}\n{{end}}")
      --gnu              output hashes in the format used by *sum
  -H, --hmac string      key for HMAC (in hexadecimal) or read from specified pathname (default "\x00")
      --ignore-missing   don't fail or report status for missing files
  -i, --input string     read pathnames from file (use "" for stdin) (default "\x00")
      --md5              MD5 algorithm
  -q, --quiet            don't print OK for each successfully verified file
  -r, --recursive        recurse into directories
      --sha1             SHA-1 algorithm
      --sha256           SHA-256 algorithm
      --sha3-256         SHA3-256 algorithm
      --sha3-512         SHA3-512 algorithm
      --sha512           SHA-512 algorithm
      --sha512-256       SHA-512/256 algorithm
      --size             output size
  -S, --status           don't output anything, status code shows success
      --strict           exit non-zero for improperly formatted checksum lines
  -s, --string           treat arguments as strings
  -L, --symlinks         don't follow symbolic links with the -r option
  -v, --verbose          verbose operation
  -V, --version          show version and exit
  -w, --warn             warn about improperly formatted checksum lines
``` 
