/*
 * (c) 2006,2017 by Ricardo Branco
 * MIT License
 *
 * Compile with:
 *   cc -o sslv sslv.c [-ldl]
 *
 * Note:
 *   + Linking "-ldl" is mandatory on some systems (i.e, Linux & SunOS)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <dlfcn.h>
#include <sys/param.h>

#define SSLEAY_VERSION	0

static const char *trylibs[] = {
	"/lib/libcrypto.so",
	"/usr/lib/libcrypto.so",
	"/usr/pkg/lib/libcrypto.so",
	"/usr/sfw/lib/libcrypto.so",
	"/usr/local/lib/libcrypto.so",
	"/usr/local/ssl/lib/libcrypto.so",
	"/usr/lib/x86_64-linux-gnu/libcrypto.so",
	"/usr/lib/i686-linux-gnu/libcrypto.so",
	"/usr/lib/i386-linux-gnu/libcrypto.so",
	"/lib/x86_64-linux-gnu/libcrypto.so",
	"/lib/i686-linux-gnu/libcrypto.so",
	"/lib/i386-linux-gnu/libcrypto.so",
	NULL
};

static char pathname[PATH_MAX+1];

static void scan_libs(void);
static int print_info(const char *sopath);

#define file_exists(file)	!access((file), F_OK)

static void scan_libs(void)
{
	int i;

	for (i = 0; trylibs[i] != NULL; i++)
	if (file_exists(trylibs[i]))
		print_info(trylibs[i]);
}

static int print_info(const char *sopath)
{
	const char *(*sslv)(int);	/* const char *SSLeay_version(int); */
	const char *error;
	char *path;
	void *dlh;

	dlh = dlopen(sopath, RTLD_LAZY | RTLD_LOCAL);
	if (dlh == NULL) {
		fprintf(stderr, "sslv: dlopen(%s): %s\n", sopath, dlerror());
		return -1;
	}

	(void) dlerror();
	sslv = dlsym(dlh, "SSLeay_version");
	if (sslv == NULL) {
		sslv = dlsym(dlh, "OpenSSL_version");
	}
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "sslv: dlsym(%s, \"SSLeay_version\"): %s\n", sopath, error);
		goto bad;
	}

	path = realpath(sopath, pathname);
	if (path != NULL && strcmp(path, sopath) && file_exists(path))
		printf("%s [%s]:\n", sopath, path);
	else
		printf("%s:\n", sopath);

	printf("\tVersion:\t%s\n", sslv(SSLEAY_VERSION));

	(void) dlclose(dlh);
	return 0;

bad:
	(void) dlclose(dlh);
	return -1;
}

int main(int argc, char *argv[])
{
	if (*++argv == NULL) {
		scan_libs();
	}
	else {
		do {
			print_info(*argv);
		} while (*++argv != NULL);
	}

	exit(0);
}

