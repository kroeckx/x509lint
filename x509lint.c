/*
 * Copyright (c) 2025 McCoy L Stevens
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <openssl/x509.h>
#include "checks.h"
#include "messages.h"

static int LoadCert(const char *filename, unsigned char **buffer, size_t *buflen)
{
	long size;
	FILE *f;

	f = fopen(filename, "rb");
	if (f == NULL)
	{
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0)
	{
		return -1;
	}
	size = ftell(f);
	if (size == -1)
	{
		return -1;
	}
	*buffer = malloc(size);
	if (fseek(f, 0, SEEK_SET) != 0)
	{
		free(*buffer);
		*buffer = NULL;
		return -1;
	}
	if (fread(*buffer, 1, size, f) != size)
	{
		free(*buffer);
		*buffer = NULL;
		return -1;
	}
	fclose(f);

	*buflen = size;

	return 0;
}


int main(int argc, char *argv[])
{
	unsigned char *buffer;
	size_t buflen;

	if (argc != 2)
	{
		printf("Usage: x509lint file\n");
		exit(1);
	}

	if (LoadCert(argv[1], &buffer, &buflen) != 0)
	{
		fprintf(stderr, "Unable to read certificate\n");
		exit(1);
	}
	X509 *x509 = GetCert(buffer, buflen, PEM);
	if (x509 == NULL)
	{
		printf("E: Unable to parse certificate\n");
		return 1;
	}

	check_init();
	
	check(buffer, buflen, PEM, GetType(x509));

	char *m = get_messages();
	printf("%s", m);
	free(m);

	free(buffer);
	X509_free(x509);

	check_finish();

	return 0;
}

