![Build Status](https://github.com/ricardobranco777/xhash/actions/workflows/ci.yml/badge.svg)

# xhash
This Go program uses goroutines to calculate multiple hashes on strings, files and directories.  By default it reads from standard input.  It can be used as a drop-in replacement for the GNU **coreutils** when hard-linked as **md5sum**, etc. and it actually supports the `--zero` option with `--check`.  The output format is fully configurable.

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

The output format is the same as the BSD commands.  Use `--gnu` to use the format used by **md5sum**.

To use the format used by **hashdeep** use `--size -f '{{range .}}{{.Sum}},{{end}}{{(index . 0).File}}\n'`

## Usage

```
Usage: xhash [OPTIONS] [-s STRING...]|[-c FILE]|[-i FILE]|[FILE...]|[-r FILE... DIRECTORY...]
  -a, --all              all algorithms (except others specified, if any)
      --blake2b-256      BLAKE2b-256 algorithm
      --blake2b-384      BLAKE2b-384 algorithm
      --blake2b-512      BLAKE2b-512 algorithm
      --blake3           BLAKE3 algorithm
  -c, --check string     read checksums from file (use "" for stdin) (default "\x00")
  -f, --format string    output format (default "{{range .}}{{.Name}} ({{.File}}) = {{.Sum }}\n{{end}}")
      --gnu              output hashes in the format used by md5sum
  -H, --hmac string      key for HMAC (in hexadecimal) or read from specified pathname (default "\x00")
      --ignore-missing   don't fail or report status for missing files
  -i, --input string     read pathnames from file (use "" for stdin) (default "\x00")
      --md5              MD5 algorithm
  -M, --mmap             use mmap - EXPERIMENTAL
  -q, --quiet            don't print OK for each successfully verified file
  -r, --recursive        recurse into directories
      --sha1             SHA1 algorithm
      --sha224           SHA224 algorithm
      --sha256           SHA256 algorithm
      --sha3-224         SHA3-224 algorithm
      --sha3-256         SHA3-256 algorithm
      --sha3-384         SHA3-384 algorithm
      --sha3-512         SHA3-512 algorithm
      --sha384           SHA384 algorithm
      --sha512           SHA512 algorithm
      --sha512-224       SHA512-224 algorithm
      --sha512-256       SHA512-256 algorithm
      --size             output size
  -S, --status           don't output anything, status code shows success
      --strict           exit non-zero for improperly formatted checksum lines
  -s, --string           treat arguments as strings
  -L, --symlinks         don't follow symbolic links with the -r option
  -v, --verbose          verbose operation
      --version          show version and exit
  -w, --warn             warn about improperly formatted checksum lines
  -z, --zero             consider NUL instead as EOL and disable file name escaping
``` 
