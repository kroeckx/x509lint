/*
 * Copyright (c) 2016 Kurt Roeckx <kurt@roeckx.be>
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
#include <string.h>
#include "checks.h"

static const char *error_strings[] =
{
	"E: Error parsing certificate\n",
	"E: Issuer without organization name\n",
	"E: Issuer without country name\n",
	"E: Subject without OrganizationName but with StreetAddress\n",
	"E: Subject with OrganizationName but without StateOrProvince or LocalityName\n",
	"E: Subject without OrganizationName but with StateOrProvince or LocalityName\n",
	"E: Fails decoding the characterset\n",
	"E: Contains a null character in the distinguished name\n",
	"E: Distinguished name contains invalid DirectoryString type\n",
	"E: The distinguished name contains non-printable control characters\n",
	"E: Subject with OrganizationName but without country name\n",
	"E: Domain validated certificate but with organization name or address\n",
	"E: Identity validated certificate but without organization name or address\n",
	"E: No policy extension\n",
	"E: No Subject alternative name extension\n",
	"E: Certificate not version 3\n",
	"E: Error parsing URL\n",
	"E: The certificate is valid for longer than 60 months\n",
	"E: Date out of range\n"
};

static const char *warning_strings[] = {
	"W: The distinguished name contains something that is not a PrintableString or UTF8String\n",
	"W: The distinguished name makes use of an IA5String\n",
	"W: The certificate is valid for longer than 39 months\n"
};

static const char *info_strings[] = {
	"I: Subject has a deprecated CommonName\n",
	"I: String not checked\n",
	"I: CRL is not a URL\n"
};

/* 
 * Turn the error information into strings.
 * Returns a buffer that should be free()d
 */
char *get_messages()
{
	char *buffer;

	/* Should be large enough for all strings. */
	buffer = malloc(8192);
	buffer[0] = '\0';

	for (int i = 0; i <= ERR_DATE_OUT_OF_RANGE; i++)
	{
		if (GetBit(errors, i))
		{
			strcat(buffer, error_strings[i]);
		}
	}

	for (int i = 0; i <= WARN_LONGER_39_MONTHS; i++)
	{
		if (i == WARN_IA5)
		{
			continue;
		}
		if (GetBit(warnings, i))
		{
			strcat(buffer, warning_strings[i]);
		}
	}

	for (int i = 0; i <= INF_CRL_NOT_URL; i++)
	{
		if (i == INF_STRING_NOT_CHECKED)
		{
			continue;
		}
		if (GetBit(info, i))
		{
			strcat(buffer, info_strings[i]);
		}
	}

	return buffer;
}

