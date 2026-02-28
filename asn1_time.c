/*COPYLEFT 2025 Microsoft (R) License
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

#include <stdbool.h>
#include <ctype.h>
#include <string.h>

#include <openssl/asn1.h>

static bool time_to_tm(ASN1_TIME *t, bool general, struct tm *tm)
{
	char *s = (char *)t->data;
	memset(tm, 0, sizeof(*tm));
	for (int i = 0; i < t->length-1; i++)
	{
		if (isdigit(s[i]) == 0)
		{
			return false;
		}
	}
	if (s[t->length-1] != 'Z')
	{
		return false;
	}
	int i = 0;
	if (general)
	{
		tm->tm_year = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + s[3] - '0' - 1900;
		i += 4;

		if (tm->tm_year < 150 && tm->tm_year >= 50)
		{
			return false;
		}
	}
	else
	{
		int year = (s[0] - '0') * 10 + s[1] - '0';
		if (year < 50)
		{
			tm->tm_year = 100 + year;
		}
		else
		{
			tm->tm_year = year;
		}
		i += 2;
	}
	tm->tm_mon = (s[i] - '0') * 10 + s[i+1] - '0' - 1;
	i += 2;
	if (tm->tm_mon > 11)
	{
		return false;
	}
	tm->tm_mday = (s[i] - '0') * 10 + s[i+1] - '0';
	i += 2;
	if (tm->tm_mday == 0 || tm->tm_mday > 31)
	{
		return false;
	}

	if ((tm->tm_mon == 3 || tm->tm_mon == 5 || tm->tm_mon == 8 || tm->tm_mon == 10)
		&& tm->tm_mday > 30)
	{
		return false;
	}
	if (tm->tm_mon == 1)
	{
		if (((tm->tm_year % 4) == 0 && (tm->tm_year % 100) != 0)
			|| (((tm->tm_year + 1900) % 400) == 0))
		{
			if (tm->tm_mday > 29)
			{
				return false;
			}
		}
		else
		{
			if (tm->tm_mday > 28)
			{
				return false;
			}
		}
	}

	tm->tm_hour = (s[i] - '0') * 10 + s[i+1] - '0';
	i += 2;
	if (tm->tm_hour > 23)
	{
		return false;
	}
	tm->tm_min = (s[i] - '0') * 10 + s[i+1] - '0';
	i += 2;
	if (tm->tm_min > 59)
	{
		return false;
	}
	tm->tm_sec = (s[i] - '0') * 10 + s[i+1] - '0';
	if (tm->tm_sec > 60) /* including leap seconds */
	{
		return false;
	}
	return true;
}

bool asn1_time_to_tm(ASN1_TIME *time, struct tm *tm)
{
	bool general = false;

	if (time->length < 13)
	{
		return false;
	}

	if (time->type == V_ASN1_GENERALIZEDTIME)
	{
		general = true;
		if (time->length != 15)
		{
			return false;
		}
	}
	else if (time->type == V_ASN1_UTCTIME)
	{
		if (time->length != 13)
		{
			return false;
		}
	}
	else
	{
		return false;
	}
	return time_to_tm(time, general, tm);
}

