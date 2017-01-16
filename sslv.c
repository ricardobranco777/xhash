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
#include <unistd.h>
#include <dlfcn.h>

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

static void scan_libs(void);
static void print_info(const char *path);

#define file_exists(file)	!access((file), F_OK)

static void scan_libs(void)
{
	int i;

	for (i = 0; trylibs[i] != NULL; i++)
	if (file_exists(trylibs[i]))
		print_info(trylibs[i]);
}

static void print_info(const char *path)
{
	const char *(*sslv)(int);	/* const char *SSLeay_version(int); */
	const char *error;
	void *dlh;

	dlh = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
	if (dlh == NULL) {
		/*fprintf(stderr, "sslv: dlopen(%s): %s\n", path, dlerror());*/
		return;
	}

	(void) dlerror();
	sslv = dlsym(dlh, "SSLeay_version");
	if (sslv == NULL) {
		/* SSLeay_version() was renamed to OpenSSL_version() on OpenSSL 1.1.0 */
		sslv = dlsym(dlh, "OpenSSL_version");
	}
	if ((error = dlerror()) != NULL) {
		/*fprintf(stderr, "sslv: dlsym(%s, \"SSLeay_version\"): %s\n", path, error);*/
		goto go;
	}

	printf("%s ", path);

	printf("%s\n", sslv(SSLEAY_VERSION));

go:
	(void) dlclose(dlh);
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

