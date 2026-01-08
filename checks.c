/*
 * Copyright (c) 2014-2016 Kurt Roeckx <kurt@roeckx.be>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <iconv.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "checks.h"
#include "asn1_time.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_PKEY_base_id(pkey) (pkey->type)

static void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	if (n != NULL)
		*n = r->n;
	if (e != NULL)
		*e = r->e;
	if (d != NULL)
		*d = r->d;
}

#define ASN1_STRING_get0_data ASN1_STRING_data

#endif

static iconv_t iconv_utf8;
static iconv_t iconv_ucs2;
static iconv_t iconv_utf32;

static const char *OIDStreetAddress = "2.5.4.9";
static const char *OIDpostalCode = "2.5.4.17";
static const char *OIDpostOfficeBox = "2.5.4.18";

static const char *OIDanyEKU = "2.5.29.37.0";
static const char *OIDIntelAMTvProEKU = "2.16.840.1.113741.1.2.3";

static const char *OIDjurisdictionCountryName = "1.3.6.1.4.1.311.60.2.1.3";
static const char *OIDjurisdictionLocalityName = "1.3.6.1.4.1.311.60.2.1.1";
static const char *OIDjurisdictionStateOrProvinceName = "1.3.6.1.4.1.311.60.2.1.2";

static const char *OIDCabDomainValidated = "2.23.140.1.2.1";
static const char *OIDCabOrganizationIdentityValidated = "2.23.140.1.2.2";
static const char *OIDCabIndividualIdentityValidated = "2.23.140.1.2.3";
static const char *OIDCabExtendedValidation = "2.23.140.1.1";


static ASN1_OBJECT *obj_organizationName;
static ASN1_OBJECT *obj_organizationalUnitName;
static ASN1_OBJECT *obj_StreetAddress;
static ASN1_OBJECT *obj_localityName;
static ASN1_OBJECT *obj_jurisdictionLocalityName;
static ASN1_OBJECT *obj_stateOrProvinceName;
static ASN1_OBJECT *obj_jurisdictionStateOrProvinceName;
static ASN1_OBJECT *obj_postalCode;
static ASN1_OBJECT *obj_countryName;
static ASN1_OBJECT *obj_jurisdictionCountryName;
static ASN1_OBJECT *obj_commonName;
static ASN1_OBJECT *obj_givenName;
static ASN1_OBJECT *obj_surname;
static ASN1_OBJECT *obj_businessCategory;
static ASN1_OBJECT *obj_serialNumber;
static ASN1_OBJECT *obj_dnQualifier;
static ASN1_OBJECT *obj_domainComponent;
static ASN1_OBJECT *obj_pkcs9_emailAddress;
static ASN1_OBJECT *obj_pkcs9_unstructuredName;
static ASN1_OBJECT *obj_postOfficeBox;
static ASN1_OBJECT *obj_anyEKU;
static ASN1_OBJECT *obj_IntelAMTvProEKU;

uint32_t errors[5];
uint32_t warnings[1];
uint32_t info[1];
uint32_t cert_info[1];

#define CERT_INFO_DV            0
#define CERT_INFO_OV            1
#define CERT_INFO_IV            1
#define CERT_INFO_EV            3
#define CERT_INFO_ANY_EKU       4
#define CERT_INFO_SERV_AUTH     5
#define CERT_INFO_CLIENT_AUTH   6
#define CERT_INFO_CODE_SIGN     7
#define CERT_INFO_EMAIL         8
#define CERT_INFO_TIME_STAMP    9
#define CERT_INFO_OCSP_SIGN     10
#define CERT_INFO_NO_EKU        11
#define CERT_INFO_AMTVPRO_EKU   12
#define CERT_INFO_KU_CRL_SIGN   13
#define CERT_INFO_HAS_SAN       14
#define CERT_INFO_KU_CERT_SIGN  15

const int primes[] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
	79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
	163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241,
	251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347,
	349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
	443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
	557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
	647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751
};

static BIGNUM *bn_factors;

static void SetBit(uint32_t *val, int bit)
{
	val[bit/(sizeof(uint32_t)*8)] |= ((uint32_t)1 << (bit % (sizeof(uint32_t)*8)));
}

bool GetBit(uint32_t *val, int bit)
{
	return (val[bit/(sizeof(uint32_t)*8)] & ((uint32_t)1 << (bit % (sizeof(uint32_t)*8)))) != 0;
}

#define SetError(bit) SetBit(errors, bit)
#define SetWarning(bit) SetBit(warnings, bit)
#define SetInfo(bit) SetBit(info, bit)
#define SetCertInfo(bit) SetBit(cert_info, bit)
#define GetCertInfo(bit) GetBit(cert_info, bit)

X509 *GetCert(const unsigned char *data, size_t len, CertFormat format)
{
	X509 *x509;
	BIO *bio = BIO_new_mem_buf(data, len);

	if (bio == NULL)
	{
		exit(1);
	}

	if (format == PEM)
	{
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	}
	else
	{
		x509 = d2i_X509_bio(bio, NULL);
	}

	BIO_free(bio);

	return x509;
}

static void Clear()
{
	for (int i = 0; i < sizeof(errors)/sizeof(errors[0]); i++)
	{
		errors[i] = 0;
	}
	for (int i = 0; i < sizeof(warnings)/sizeof(warnings[0]); i++)
	{
		warnings[i] = 0;
	}
	for (int i = 0; i < sizeof(info)/sizeof(info[0]); i++)
	{
		info[i] = 0;
	}
	for (int i = 0; i < sizeof(cert_info)/sizeof(cert_info[0]); i++)
	{
		cert_info[i] = 0;
	}
}

static void CheckValidURL(const unsigned char *s, int n)
{
	/* RFC3986 */
	static char *reserved_chars = ":/?#[]@!$&'()*+,;=";
	static char *unreserved_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

	int i = 0;
	while (i < n)
	{
		if (s[i] == '%')
		{
			if (n - i < 3)
			{
				SetError(ERR_INVALID_URL);
				return;
			}
			if (!isxdigit(s[i+1]) || !isxdigit(s[i+2]))
			{
				SetError(ERR_INVALID_URL);
				return;
			}
			i+=3;
			continue;
		}
		if (s[i] == '\0')
		{
			SetError(ERR_URL_WITH_NUL);
		}
		else if (strchr(reserved_chars, s[i]) == NULL && strchr(unreserved_chars, s[i]) == NULL)
		{
			SetError(ERR_INVALID_URL);
			return;
		}
		i++;
	}
	/* TODO: Check the rest of URL, like starting with "http://" */
}

static void CheckBitString(ASN1_BIT_STRING *s)
{
	if (s->length > 0 && s->data[s->length-1] == 0)
	{
		SetError(ERR_BIT_STRING_LEADING_0);
	}
}

/*
 * Check that the string contains printable characters.
 * The input is in internal UCS-4 notation.
 *
 * Returns true when no error found and false when an error was found.
 * It also updates the errors.
 */
static bool CheckPrintableChars(const uint32_t *s, int n)
{
	int i;
	bool ret = true;

	for (i = 0; i < n; i++)
	{
		if (s[i] == '\0')
		{
			SetError(ERR_STRING_WITH_NUL);
			ret = false;
		}
		else if (s[i] < 32)
		{
			SetError(ERR_NON_PRINTABLE);
			ret = false;
		}
		if (s[i] >= 0x7F && s[i] <= 0x9F)
		{
			SetError(ERR_NON_PRINTABLE);
			ret = false;
		}
	}
	return ret;
}

/*
 * Checks that a string is valid
 *
 * Returns true when no error was found and false when an error was found
 * It also updates the error
 * When no error was found it will fill in char_len with the number of
 * characters in the string, not the number of octets.
 */
static bool CheckStringValid(ASN1_STRING *data, size_t *char_len)
{
	unsigned char *utf8 = NULL;
	size_t utf8_len;
	bool ret = true;

	if (data->type == V_ASN1_UTF8STRING)
	{
		size_t n = data->length;
		size_t utf8_size = data->length;
		unsigned char *s = data->data;
		utf8 = malloc(utf8_size);
		unsigned char *pu = utf8;

		/* reset iconv */
		iconv(iconv_utf8, NULL, 0, NULL, 0);

		if (iconv(iconv_utf8, (char **)&s, &n, (char **)&pu, &utf8_size) == (size_t) -1 || n != 0)
		{
			ret = false;
			SetError(ERR_INVALID_ENCODING);
		}
		utf8_len = data->length;
	}
	else if (data->type == V_ASN1_BMPSTRING)
	{
		size_t n = data->length;
		size_t utf8_size = data->length*3;		/* U+FFFF is represented with 3 UTF-8 chars */
		unsigned char *s = data->data;
		utf8 = malloc(utf8_size);
		unsigned char *pu = utf8;

		/* reset iconv */
		iconv(iconv_ucs2, NULL, 0, NULL, 0);

		if (iconv(iconv_ucs2, (char **)&s, &n, (char **)&pu, &utf8_size) == (size_t) -1 || n != 0)
		{
			ret = false;
			SetError(ERR_INVALID_ENCODING);
		}
		utf8_len = pu - utf8;
	}
	else if (data->type == V_ASN1_PRINTABLESTRING)
	{
		for (int i = 0; i < data->length; i++)
		{
			if (data->data[i] == '\0')
			{
				ret = false;
				SetError(ERR_STRING_WITH_NUL);
			}
			else if (data->data[i] < 32)
			{
				ret = false;
				SetError(ERR_NON_PRINTABLE);
			}
			else if (!((data->data[i] >= 'A' && data->data[i] <= 'Z') ||
				(data->data[i] >= 'a' && data->data[i] <= 'z') ||
				(data->data[i] >= '0' && data->data[i] <= '9') ||
				(data->data[i] == '\'') ||
				(data->data[i] == '(') ||
				(data->data[i] == ')') ||
				(data->data[i] == '+') ||
				(data->data[i] == ',') ||
				(data->data[i] == '-') ||
				(data->data[i] == '.') ||
				(data->data[i] == '/') ||
				(data->data[i] == ':') ||
				(data->data[i] == '=') ||
				(data->data[i] == '?') ||
				(data->data[i] == ' ')))
			{
				ret = false;
				SetError(ERR_INVALID_ENCODING);
			}
		}
	}
	else if (data->type == V_ASN1_IA5STRING || data->type == V_ASN1_VISIBLESTRING)
	{
		/*
		 * IA5String's valid range is 0x00 - 0x7F,
		 * VisibleString restricts it to the visible ones: 0x20 - 0x7E
		 * We restrict both to the VisibleString range.
		 */
		for (int i = 0; i < data->length; i++)
		{
			if (data->data[i] == '\0')
			{
				ret = false;
				SetError(ERR_STRING_WITH_NUL);
			}
			else if (data->data[i] < 32)
			{
				ret = false;
				SetError(ERR_NON_PRINTABLE);
			}
			else if (data->data[i] >= 127)
			{
				ret = false;
				SetError(ERR_INVALID_ENCODING);
			}
		}
	}
	else if (data->type == V_ASN1_T61STRING)  /* TeletexString, T61String */
	{
		/* Don't try to decode it, nothing properly implements it. Just accept the 102 character set. */
		for (int i = 0; i < data->length; i++)
		{
			if (data->data[i] == '\0')
			{
				ret = false;
				SetError(ERR_STRING_WITH_NUL);
			}
			if (data->data[i] == 0x1B)
			{
				/*
				 * It's valid, but there are no implemenations that really handle
				 * things, just return an error.
				 */
				ret = false;
				SetError(ERR_TELETEX_WITH_ESCAPE);
			}
			else if (data->data[i] < 32)
			{
				ret = false;
				SetError(ERR_NON_PRINTABLE);
			}
			else if (data->data[i] >= 127)
			{
				/* Things could be mapped here, but it first requires an escape sequence */
				ret = false;
				SetError(ERR_INVALID_ENCODING);
			}
			else if (data->data[i] == 0x5C || data->data[i] == 0x5E || data->data[i] == 0x60 ||
				data->data[i] == 0x7B || data->data[i] == 0x7D || data->data[i] == 0x7E)
			{
				/* Not mapped in the 102 character set */
				ret = false;
				SetError(ERR_INVALID_ENCODING);
			}
		}
	}
	else
	{
		SetInfo(INF_STRING_NOT_CHECKED);
		return 0;
	}

	if (ret)
	{
		if (utf8 != NULL)
		{
			/* reset iconv */
			iconv(iconv_utf32, NULL, 0, NULL, 0);

			unsigned char *s = utf8;
			size_t n = utf8_len;
			if (n >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF)
			{
				s += 3; /* Ignore the BOM */
				n -= 3;
			}
			size_t utf32_size = (n+1) * 4; /* It adds a BOM */
			uint32_t *utf32 = malloc(utf32_size);
			char *pu = (char *)utf32;

			if (iconv(iconv_utf32, (char **)&s, &n, (char **)&pu, &utf32_size) == (size_t) -1 || n != 0)
			{
				/* Shouldn't happen. */
				SetError(ERR_INVALID_ENCODING);
				free(utf8);
				free(utf32);
				return false;
			}
			else
			{
				*char_len = (pu - (char *)utf32) / 4;
				if (!CheckPrintableChars(utf32, *char_len))
				{
					ret = false;
				}
				if (utf32[0] == 0xFEFF)
				{
					/* Don't count the BOM */
					(*char_len)--;
				}
			}
			free(utf32);
		}
		else
		{
			*char_len = data->length;
		}
	}
	free(utf8);
	return ret;
}

static const struct
{
	ASN1_OBJECT **obj;
	size_t min;
	size_t max;
	int error;
} size_limits[] =
{
	{ &obj_countryName, 2, 2, ERR_COUNTRY_SIZE },
	{ &obj_jurisdictionCountryName, 2, 2, ERR_COUNTRY_SIZE },
	{ &obj_commonName, 1, ub_common_name, ERR_COMMON_NAME_SIZE },
	{ &obj_localityName, 1, ub_locality_name, ERR_LOCALITY_NAME_SIZE },
	{ &obj_jurisdictionLocalityName, 1, ub_locality_name, ERR_LOCALITY_NAME_SIZE },
	{ &obj_stateOrProvinceName, 1, ub_state_name, ERR_STATE_NAME_SIZE },
	{ &obj_jurisdictionStateOrProvinceName, 1, ub_state_name, ERR_STATE_NAME_SIZE },
	{ &obj_organizationName, 1, ub_organization_name, ERR_ORGANIZATION_NAME_SIZE },
	{ &obj_organizationalUnitName, 1, ub_organization_unit_name, ERR_ORGANIZATIONAL_UNIT_NAME_SIZE },
	{ &obj_serialNumber, 1, 64, ERR_SERIAL_NUMBER_SIZE },
	{ &obj_businessCategory, 1, ub_name, ERR_BUSINESS_CATEGORY_SIZE },
	{ &obj_postalCode, 1, 40, ERR_POSTAL_CODE_SIZE },
	{ &obj_postOfficeBox, 1, 40, ERR_POST_OFFICE_BOX_SIZE },
	{ &obj_StreetAddress, 1, 128, ERR_STREET_ADDRESS_SIZE },
	{ &obj_dnQualifier, 1, ub_name, ERR_DN_QUALIFIER_SIZE }, /* Not sure */
	{ &obj_domainComponent, 1, 63, ERR_DOMAINCOMPONENT_SIZE },
	{ &obj_pkcs9_emailAddress, 1, 255, ERR_EMAIL_SIZE },
	{ &obj_pkcs9_unstructuredName, 1, 255, ERR_UNSTRUCTUREDNAME_SIZE },
	{ &obj_givenName, 1, ub_name, ERR_GIVEN_NAME_SIZE },
	{ &obj_surname, 1, 40, ERR_SURNAME_SIZE }
};

static void CheckNameEntryValid(X509_NAME_ENTRY *ne)
{
	ASN1_STRING *data = X509_NAME_ENTRY_get_data(ne);
	ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne);
	int nid = OBJ_obj2nid(obj);
	size_t char_len;

	if (CheckStringValid(data, &char_len))
	{
		bool bChecked = false;
		for (size_t i = 0; i < sizeof(size_limits)/sizeof(size_limits[0]); i++)
		{
			if (OBJ_cmp(*size_limits[i].obj, obj) == 0)
			{
				if (char_len > size_limits[i].max || char_len < size_limits[i].min)
				{
					SetError(size_limits[i].error);
				}
				bChecked = true;
				break;
			}
		}
		if (!bChecked)
		{
			SetInfo(INF_NAME_ENTRY_LENGTH_NOT_CHECKED);
		}
	}

	if (nid == NID_pkcs9_emailAddress || nid == NID_domainComponent)
	{
		if (data->type != V_ASN1_IA5STRING)
		{
			SetError(ERR_INVALID_NAME_ENTRY_TYPE);
		}
	}
	else if (nid == NID_pkcs9_unstructuredName && data->type == V_ASN1_IA5STRING)
	{
		/* PKCS#9 unstructuredName may be IA5String or DirectoryString */
	}
	else
	{
		/* It should be a DirectoryString, which is one of the below */
		if ((data->type != V_ASN1_PRINTABLESTRING) &&
			(data->type != V_ASN1_UTF8STRING) &&
			(data->type != V_ASN1_T61STRING) &&
			(data->type != V_ASN1_UNIVERSALSTRING) &&
			(data->type != V_ASN1_BMPSTRING))
		{
			SetError(ERR_INVALID_NAME_ENTRY_TYPE);
		}
		else if ((data->type != V_ASN1_PRINTABLESTRING) && (data->type != V_ASN1_UTF8STRING))
		{
			/* RFC5280 says it MUST be PrintableString or UTF8String, with exceptions. */
			SetWarning(WARN_NON_PRINTABLE_STRING);
		}
	}

	if (nid == NID_countryName && data->type != V_ASN1_PRINTABLESTRING)
	{
		SetError(ERR_INVALID_NAME_ENTRY_TYPE);
	}
	if (nid == NID_dnQualifier && data->type != V_ASN1_PRINTABLESTRING)
	{
		SetError(ERR_INVALID_NAME_ENTRY_TYPE);
	}
	if (nid == NID_serialNumber && data->type != V_ASN1_PRINTABLESTRING)
	{
		SetError(ERR_INVALID_NAME_ENTRY_TYPE);
	}

	return;
}

static void CheckDisplayText(ASN1_STRING *s)
{
	size_t char_len;

	if (s->type != V_ASN1_IA5STRING && s->type != V_ASN1_VISIBLESTRING &&
		s->type != V_ASN1_BMPSTRING && s->type != V_ASN1_UTF8STRING)
	{
		SetError(ERR_INVALID_DISPLAY_TEXT_TYPE);
	}
	if (CheckStringValid(s, &char_len))
	{
		if (char_len > 200)
		{
			SetError(ERR_INVALID_DISPLAY_TEXT_LENGTH);
		}
	}
}

static void CheckDN(X509_NAME *dn)
{
	for (int i = 0; i < X509_NAME_entry_count(dn); i++)
	{
		X509_NAME_ENTRY *ne = X509_NAME_get_entry(dn, i);
		ASN1_STRING *data = X509_NAME_ENTRY_get_data(ne);

		if (data->type != V_ASN1_SEQUENCE)
		{
			CheckNameEntryValid(ne);
		}
		else
		{
			/* TODO: It's a sequence, we should go over it's members */
			SetInfo(INF_STRING_NOT_CHECKED);
		}
	}
}

static bool IsNameObjPresent(X509_NAME *dn, ASN1_OBJECT *obj)
{
	return X509_NAME_get_index_by_OBJ(dn, obj, -1) >= 0;
}

static bool IsValidLongerThan(struct tm tm_from, struct tm tm_to, int months)
{
	int month_diff = (tm_to.tm_year - tm_from.tm_year) * 12
		+ tm_to.tm_mon - tm_from.tm_mon;
	if (month_diff > months)
	{
		return true;
	}
	if (month_diff < months)
	{
		return false;
	}
	if (tm_to.tm_mday < tm_from.tm_mday)
	{
		return false;
	}
	if (tm_to.tm_mday > tm_from.tm_mday)
	{
		return true;
	}
	if (tm_to.tm_hour < tm_from.tm_hour)
	{
		return false;
	}
	if (tm_to.tm_hour > tm_from.tm_hour)
	{
		return true;
	}
	if (tm_to.tm_min < tm_from.tm_min)
	{
		return false;
	}
	if (tm_to.tm_min > tm_from.tm_min)
	{
		return true;
	}
	if (tm_to.tm_sec < tm_from.tm_sec)
	{
		return false;
	}
	if (tm_to.tm_sec > tm_from.tm_sec)
	{
		return true;
	}
	return false;
}

static void CheckPolicy(X509 *x509, CertType type, X509_NAME *subject)
{
	int idx = -1;
	bool bPolicyFound = false;
	bool DomainValidated = false;
	bool OrganizationValidated = false;
	bool IndividualValidated = false;
	bool EVValidated = false;
	bool CabIVPresent = false;

	do
	{
		int critical = -1;

		CERTIFICATEPOLICIES *policy = X509_get_ext_d2i(x509, NID_certificate_policies, &critical, &idx);

		if (policy == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				bPolicyFound = true;
				continue;
			}
			/* Not found */
			break;
		}
		bPolicyFound = true;

		for (int pi = 0; pi < sk_POLICYINFO_num(policy); pi++)
		{
			POLICYINFO *info = sk_POLICYINFO_value(policy, pi);

			char oid[80];
			OBJ_obj2txt(oid, sizeof(oid), info->policyid, 1);

			if (type == SubscriberCertificate)
			{
				if (strcmp(oid, OIDCabDomainValidated) == 0
					|| strcmp(oid, "2.16.840.1.114413.1.7.23.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.30360.3.3.3.3.4.5.3") == 0
					|| strcmp(oid, "1.3.6.1.4.1.14777.1.2.4") == 0
					|| strcmp(oid, "2.16.840.1.114414.1.7.23.1") == 0)
				{
					DomainValidated = true;
					SetCertInfo(CERT_INFO_DV);
					/* Required by CAB base 7.1.6.1 */
					if (IsNameObjPresent(subject, obj_organizationName))
					{
						SetError(ERR_DOMAIN_WITH_ORG);
					}
					if (IsNameObjPresent(subject, obj_StreetAddress))
					{
						SetError(ERR_DOMAIN_WITH_STREET);
					}
					if (IsNameObjPresent(subject, obj_localityName))
					{
						SetError(ERR_DOMAIN_WITH_LOCALITY);
					}
					if (IsNameObjPresent(subject, obj_stateOrProvinceName))
					{
						SetError(ERR_DOMAIN_WITH_STATE);
					}
					if (IsNameObjPresent(subject, obj_postalCode))
					{
						SetError(ERR_DOMAIN_WITH_POSTAL);
					}
					if (IsNameObjPresent(subject, obj_givenName) || IsNameObjPresent(subject, obj_surname))
					{
						SetError(ERR_DOMAIN_WITH_NAME);
					}
				}

				if (strcmp(oid, OIDCabOrganizationIdentityValidated) == 0
					|| strcmp(oid, "2.16.840.1.114412.1.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.4788.2.200.1") == 0
					|| strcmp(oid, "2.16.840.1.114413.1.7.23.2") == 0
					|| strcmp(oid, "2.16.528.1.1003.1.2.5.6") == 0
					|| strcmp(oid, "1.3.6.1.4.1.8024.0.2.100.1.1") == 0
					|| strcmp(oid, "2.16.840.1.114414.1.7.23.2") == 0
					|| strcmp(oid, "1.3.6.1.4.1.30360.3.3.3.3.4.4.3") == 0
					|| strcmp(oid, "1.3.6.1.4.1.14777.1.2.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.14777.1.1.3") == 0
					|| strcmp(oid, "2.16.792.3.0.3.1.1.2") == 0)
				{
					OrganizationValidated = true;
					SetCertInfo(CERT_INFO_OV);
					/* Required by CAB base 7.1.6.1 */
					if (!IsNameObjPresent(subject, obj_organizationName))
					{
						SetError(ERR_ORGANIZATION_WITHOUT_ORG);
					}
					if (!IsNameObjPresent(subject, obj_countryName))
					{
						SetError(ERR_ORGANIZATION_WITHOUT_COUNTRY);
					}
				}

				if (strcmp(oid, OIDCabIndividualIdentityValidated) == 0)
				{
					CabIVPresent = true;
				}

				if (strcmp(oid, OIDCabIndividualIdentityValidated) == 0)
				{
					IndividualValidated = true;
					SetCertInfo(CERT_INFO_IV);
					/* Required by CAB base 7.1.6.1 */
					if (!IsNameObjPresent(subject, obj_organizationName)
						&& !(IsNameObjPresent(subject, obj_givenName) && IsNameObjPresent(subject, obj_surname)))
					{
						SetError(ERR_INDIVIDUAL_WITHOUT_NAME);
					}
					if (!IsNameObjPresent(subject, obj_countryName))
					{
						SetError(ERR_INDIVIDUAL_WITHOUT_COUNTRY);
					}
				}

				if (strcmp(oid, OIDCabExtendedValidation) == 0
					|| strcmp(oid, "2.16.840.1.114412.2.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.4788.2.202.1") == 0
					|| strcmp(oid, "2.16.840.1.114413.1.7.23.3") == 0
					|| strcmp(oid, "1.3.6.1.4.1.8024.0.2.100.1.2") == 0
					|| strcmp(oid, "2.16.840.1.114414.1.7.23.3") == 0
					|| strcmp(oid, "2.16.756.1.89.1.2.1.1") == 0
					|| strcmp(oid, "2.16.792.3.0.3.1.1.5") == 0
					|| strcmp(oid, "1.3.6.1.4.1.6449.1.2.1.5.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.14777.6.1.1") == 0
					|| strcmp(oid, "1.3.6.1.4.1.14777.6.1.2") == 0
					|| strcmp(oid, "1.3.6.1.4.1.36305.2") == 0)
				{
					EVValidated = true;
					SetCertInfo(CERT_INFO_EV);
					/* 9.2.1 */
					if (!IsNameObjPresent(subject, obj_organizationName))
					{
						SetError(ERR_EV_WITHOUT_ORGANIZATION);
					}
					/* 9.2.4 */
					if (!IsNameObjPresent(subject, obj_businessCategory))
					{
						SetError(ERR_EV_WITHOUT_BUSINESS);
					}
					/* 9.2.5 */
					if (!IsNameObjPresent(subject, obj_jurisdictionCountryName))
					{
						SetError(ERR_EV_WITHOUT_JURISDICTION_COUNTRY);
					}
					/* 9.2.6 */
					if (!IsNameObjPresent(subject, obj_serialNumber))
					{
						SetError(ERR_EV_WITHOUT_NUMBER);
					}
				}
			}

			if (info->qualifiers)
			{
				for (int i = 0; i < sk_POLICYQUALINFO_num(info->qualifiers); i++)
				{
					POLICYQUALINFO *qualinfo = sk_POLICYQUALINFO_value(info->qualifiers, i);
					int nid = OBJ_obj2nid(qualinfo->pqualid);
					if (nid == NID_id_qt_unotice)
					{
						if (qualinfo->d.usernotice->exptext)
						{
							ASN1_STRING *s = qualinfo->d.usernotice->exptext;
							CheckDisplayText(s);
							/*
							 * RFC5280 says:
							 * Conforming CAs SHOULD use the UTF8String encoding for explicitText,
							 * but MAY use IA5String. Conforming CAs MUST NOT encode explicitText
							 * as VisibleString or BMPString.
							 *
							 * RFC6818 updates that to:
							 * Conforming CAs SHOULD use the UTF8String encoding for explicitText.
							 * VisibleString or BMPString are acceptable but less preferred alternatives.
							 * Conforming CAs MUST NOT encode explicitText as IA5String.
							 *
							 * Combining both, UTF8String is the only valid encoding.
							 */
							if (s->type != V_ASN1_UTF8STRING)
							{
								SetWarning(WARN_EXPLICIT_TEXT_ENCODING);
							}
							if (s->type != V_ASN1_UTF8STRING && s->type != V_ASN1_BMPSTRING &&
								s->type != V_ASN1_VISIBLESTRING && s->type != V_ASN1_IA5STRING)
							{
								SetError(ERR_INVALID_TYPE_USER_NOTICE);
							}
						}
					}
					else if (nid == NID_id_qt_cps)
					{
						CheckValidURL(qualinfo->d.cpsuri->data, qualinfo->d.cpsuri->length);
					}
					else
					{
						SetError(ERR_INVALID_POLICY_QUALIFIER_ID);
					}
					if (nid != NID_id_qt_cps)
					{
						SetWarning(WARN_POLICY_QUALIFIER_NOT_CPS);
					}
				}
			}
		}
		CERTIFICATEPOLICIES_free(policy);
	}
	while (1);

	if (GetBit(cert_info, CERT_INFO_SERV_AUTH) || GetBit(cert_info, CERT_INFO_ANY_EKU) || GetBit(cert_info, CERT_INFO_NO_EKU))
	{
		if ((IsNameObjPresent(subject, obj_givenName) || IsNameObjPresent(subject, obj_surname))
			&& !CabIVPresent)
		{
			/* Required by CAB 7.1.4.2.2c */
			SetError(ERR_NAME_NO_IV_POLICY);
		}
	}
	else
	{
		if (DomainValidated || IndividualValidated || CabIVPresent)
		{
			SetError(ERR_POLICY_BR);
		}
	}


	if (!bPolicyFound && type == SubscriberCertificate)
	{
		/* Required by CAB 9.3.4 */
		SetError(ERR_NO_POLICY);
	}

	if (type == SubscriberCertificate && !DomainValidated && !OrganizationValidated
		&& !IndividualValidated && !EVValidated)
	{
		SetInfo(INF_UNKNOWN_VALIDATION);
	}
}

static void CheckGeneralNameType(GENERAL_NAME *name)
{
	int type;
	ASN1_STRING *s = GENERAL_NAME_get0_value(name, &type);
	if (type == GEN_DNS || type == GEN_EMAIL || type == GEN_URI)
	{
		if (s->type != V_ASN1_IA5STRING)
		{
			SetError(ERR_GEN_NAME_TYPE);
		}
	}
	else if (type == GEN_IPADD)
	{
		if (s->type != V_ASN1_OCTET_STRING)
		{
			SetError(ERR_GEN_NAME_TYPE);
		}
	}
	/* TODO: Add checks for other types. */
}

/* Compare 2 ASN1_STRINGS case insensitive to be equal,
 * returns 0 when equal, something else when not equal
 *
 * This only works with ASN1_STRINGS that are encoded in ASCII
 * like IA5_STRING and PRINTABLE_STRING.  It will not try to
 * convert things to a common encoding before comparing.
 */
static int ASN1_STRING_cmpcase(const ASN1_STRING *s1, const ASN1_STRING *s2)
{
	if (s1->length != s2->length)
	{
		return s1->length - s2->length;
	}
	return strncasecmp((const char *)s1->data, (const char *)s2->data, s1->length);
}

static void CheckSAN(X509 *x509, CertType type)
{
	int idx = -1;
	bool bSanFound = false;
	bool bSanName = false;
	bool bSanRequired = false;
	bool bCommonNameFound = false;
	ASN1_STRING *commonName = NULL;
	enum { SAN_TYPE_NOT_ALLOWED, SAN_TYPE_ALLOWED, SAN_TYPE_WARN } name_type_allowed[GEN_RID+1];

	for (int i = 0; i < GEN_RID+1; i++)
	{
		name_type_allowed[i] = SAN_TYPE_NOT_ALLOWED;
	}

	if (GetBit(cert_info, CERT_INFO_SERV_AUTH) || GetBit(cert_info, CERT_INFO_ANY_EKU) || GetBit(cert_info, CERT_INFO_NO_EKU))
	{
		name_type_allowed[GEN_DNS] = SAN_TYPE_ALLOWED;
		name_type_allowed[GEN_IPADD] = SAN_TYPE_ALLOWED;
		bSanRequired = true;
	}
	if (GetBit(cert_info, CERT_INFO_EMAIL) || GetBit(cert_info, CERT_INFO_ANY_EKU) || GetBit(cert_info, CERT_INFO_NO_EKU))
	{
		name_type_allowed[GEN_EMAIL] = SAN_TYPE_ALLOWED;
		bSanRequired = true;
	}
	if (GetBit(cert_info, CERT_INFO_CLIENT_AUTH))
	{
		/*
		 * DNS and IP address doesn't make sense for a TLS client that
		 * doesn't also do server authentication.
		 */
		if (name_type_allowed[GEN_DNS] == SAN_TYPE_NOT_ALLOWED)
		{
			name_type_allowed[GEN_DNS] = SAN_TYPE_WARN;
			name_type_allowed[GEN_IPADD] = SAN_TYPE_WARN;
		}
		name_type_allowed[GEN_EMAIL] = SAN_TYPE_ALLOWED;
	}
	if (GetBit(warnings, WARN_UNKNOWN_EKU) && !GetBit(cert_info, CERT_INFO_SERV_AUTH) && !GetBit(cert_info, CERT_INFO_ANY_EKU))
	{
		/*
		 * If it's a certificate with an unknown EKU that isn't
		 * also valid for server auth, allow the other types
		 */
		name_type_allowed[GEN_OTHERNAME] = SAN_TYPE_ALLOWED;
		name_type_allowed[GEN_X400] = SAN_TYPE_ALLOWED;
		name_type_allowed[GEN_EDIPARTY] = SAN_TYPE_ALLOWED;
		name_type_allowed[GEN_URI] = SAN_TYPE_ALLOWED;
	}

	X509_NAME *subject = X509_get_subject_name(x509);
	for (int i = 0; i < X509_NAME_entry_count(subject); i++)
	{
		X509_NAME_ENTRY *ne = X509_NAME_get_entry(subject, i);
		ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(ne);

		if (OBJ_cmp(obj_commonName, obj) == 0)
		{
			commonName = X509_NAME_ENTRY_get_data(ne);
			break;
		}
	}

	do
	{
		int critical = -1;

		GENERAL_NAMES *names = X509_get_ext_d2i(x509, NID_subject_alt_name, &critical, &idx);

		if (names == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				bSanFound = true;
				continue;
			}
			/* Not found */
			break;
		}
		if (X509_NAME_entry_count(subject) == 0 && critical == 0)
		{
			SetError(ERR_SAN_NOT_CRITICAL);
		}
		if (sk_GENERAL_NAME_num(names) == 0)
		{
			SetError(ERR_SAN_EMPTY);
		}
		for (int i = 0; i < sk_GENERAL_NAME_num(names); i++)
		{
			GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);
			int type;
			ASN1_STRING *name_s = GENERAL_NAME_get0_value(name, &type);
			if (type > GEN_RID || type < 0)
			{
				SetError(ERR_INVALID_GENERAL_NAME_TYPE);
			}
			else if (name_type_allowed[type] == SAN_TYPE_NOT_ALLOWED)
			{
				SetError(ERR_SAN_TYPE);
			}
			else if (name_type_allowed[type] == SAN_TYPE_WARN)
			{
				SetWarning(WARN_TLS_CLIENT_DNS);
			}
			if (type == GEN_DNS)
			{
				for (int j = i+1; j < sk_GENERAL_NAME_num(names); j++)
				{
					GENERAL_NAME *name2 = sk_GENERAL_NAME_value(names, j);
					int type2;
					ASN1_STRING *name2_s = GENERAL_NAME_get0_value(name2, &type2);
					if (type == type2 && ASN1_STRING_cmpcase(name_s, name2_s) == 0)
					{
						SetWarning(WARN_DUPLICATE_SAN);
					}
				}

				char *s = malloc(name_s->length + 1);
				strncpy(s, (char *)name_s->data, name_s->length);
				s[name_s->length] = '\0';

				unsigned char buf[sizeof(struct in6_addr)];
				if (inet_pton(AF_INET, s, buf) == 1 || inet_pton(AF_INET6, s, buf) == 1)
				{
					SetError(ERR_IP_IN_DNSNAME);
				}
				free(s);
			}
			if ((type == GEN_DNS || type == GEN_EMAIL) && commonName != NULL)
			{
				if (ASN1_STRING_cmpcase(name_s, commonName) == 0)
				{
					bCommonNameFound = true;
				}
			}
			if (type == GEN_IPADD)
			{
				int af = AF_UNSPEC;
				if (name_s->length == 4)
				{
					af = AF_INET;
				}
				else if (name_s->length == 16)
				{
					af = AF_INET6;
				}
				else
				{
					SetError(ERR_IP_FAMILY);
				}
				if (af != AF_UNSPEC && commonName != NULL)
				{
					unsigned char buf[sizeof(struct in6_addr)];
					char *s = malloc(commonName->length + 1);

					strncpy(s, (char *)commonName->data, commonName->length);
					s[commonName->length] = '\0';

					inet_pton(af, s, buf);

					/* We want to compare them binary, the string version is not standard. */
					if (memcmp(buf, name_s->data, name_s->length) == 0)
					{
						bCommonNameFound = true;
					}
					free(s);
				}
			}
			CheckGeneralNameType(name);
			bSanName = true;
		}
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		bSanFound = true;
	}
	while (1);

	if (!bSanFound && bSanRequired)
	{
		/* Required by CAB base 7.1.4.2.1 */
		if (type == SubscriberCertificate)
		{
			SetError(ERR_NO_SUBJECT_ALT_NAME);
		}
	}
	if (bSanFound && !bSanName)
	{
		SetError(ERR_SAN_WITHOUT_NAME);
	}
	if (bSanFound)
	{
		SetCertInfo(CERT_INFO_HAS_SAN);
	}
	if (commonName != NULL && bSanFound && !bCommonNameFound)
	{
//		SetError(ERR_CN_NOT_IN_SAN);
	}
}

static bool CheckCRL(X509 *x509)
{
	int idx = -1;
	bool HaveCRLHTTP = false;

	do
	{
		int critical = -1;

		STACK_OF(DIST_POINT) *crls = X509_get_ext_d2i(x509, NID_crl_distribution_points, &critical, &idx);

		if (crls == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				continue;
			}
			/* Not found */
			break;
		}

		bool bHaveAllReasons = false;
		for (int i = 0; i < sk_DIST_POINT_num(crls); i++)
		{
			DIST_POINT *dp = sk_DIST_POINT_value(crls, i);
			if (dp->distpoint == NULL && dp->CRLissuer == NULL)
			{
				SetError(ERR_CRL_DIST_POINT_WITHOUT_DISTPOINT_OR_ISSUER);
			}
			if (dp->CRLissuer != NULL)
			{
				if (sk_GENERAL_NAME_num(dp->CRLissuer) == 0)
				{
					SetError(ERR_CRL_ISSUER_EMPTY);
				}
				for (int j = 0; j < sk_GENERAL_NAME_num(dp->CRLissuer); j++)
				{
					GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->CRLissuer, j);
					int type;
					GENERAL_NAME_get0_value(gen, &type);
					if (type != GEN_DIRNAME)
					{
						SetError(ERR_CRL_ISSUER_NOT_DIRNAME);
					}
				}
			}
			if (dp->distpoint != NULL && dp->distpoint->type == 0)
			{
				/* full name */
				if (sk_GENERAL_NAME_num(dp->distpoint->name.fullname) == 0)
				{
					SetError(ERR_CRL_DISTPOINT_EMPTY);
				}
				for (int j = 0; j < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); j++)
				{
					GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, j);
					int type;
					ASN1_STRING *uri = GENERAL_NAME_get0_value(gen, &type);
					if (type == GEN_URI)
					{
						CheckValidURL(ASN1_STRING_get0_data(uri), ASN1_STRING_length(uri));
						if (uri->length > 7 &&
							strncmp((char *)uri->data, "http://", 7) == 0)
						{
							HaveCRLHTTP = true;
						}
					}
					else
					{
						SetInfo(INF_CRL_NOT_URL);
					}
					CheckGeneralNameType(gen);
				}
			}
			else
			{
				/* relative name */
				SetWarning(WARN_CRL_RELATIVE);
				if (dp->CRLissuer != NULL && sk_GENERAL_NAME_num(dp->CRLissuer) != 1)
				{
					SetError(ERR_RELATIVE_CRL_ISSUER_COUNT);
				}
			}
			if (dp->reasons == NULL)
			{
				bHaveAllReasons = true;
			}
			else
			{
				int reason = 0;

				CheckBitString(dp->reasons);
				if (dp->reasons->length > 0)
				{
					reason = dp->reasons->data[0];
				}
				if (dp->reasons->length > 1)
				{
					reason |= (dp->reasons->data[1] << 8);
				}
				if (dp->reasons->length > 2)
				{
					SetError(ERR_INVALID_CRL_REASON);
				}
				if ((reason & CRLDP_ALL_REASONS) != reason)
				{
					SetError(ERR_INVALID_CRL_REASON);
				}
				if (reason == CRLDP_ALL_REASONS)
				{
					bHaveAllReasons = true;
				}
			}
		}
		if (!bHaveAllReasons)
		{
			SetError(ERR_NOT_ALL_CRL_REASONS);
		}
		sk_DIST_POINT_pop_free(crls, DIST_POINT_free);
	}
	while (1);

	return HaveCRLHTTP;
}

static bool CheckAIA(X509 *x509, CertType type)
{
	int idx = -1;
	bool HaveOCSPHTTP = false;
	bool HaveCertHTTP = false;
	bool HaveAIA = false;

	do
	{
		int critical = -1;

		AUTHORITY_INFO_ACCESS *info = X509_get_ext_d2i(x509, NID_info_access, &critical, &idx);

		if (info == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				continue;
			}
			/* Not found */
			break;
		}
		if (critical != 0)
		{
			SetError(ERR_AIA_CRITICAL);
		}
		HaveAIA = true;

		for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++)
		{
			ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
			if (ad->location->type == GEN_URI)
			{
				CheckValidURL(ad->location->d.uniformResourceIdentifier->data,
					ad->location->d.uniformResourceIdentifier->length);
			}
			if (OBJ_obj2nid(ad->method) == NID_ad_OCSP && ad->location->type == GEN_URI)
			{
				if (ad->location->d.uniformResourceIdentifier->length > 7 &&
					strncmp((char *)ad->location->d.uniformResourceIdentifier->data, "http://", 7) == 0)
				{
					HaveOCSPHTTP = true;
				}
			}
			if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers && ad->location->type == GEN_URI)
			{
				if (ad->location->d.uniformResourceIdentifier->length > 7 &&
					strncmp((char *)ad->location->d.uniformResourceIdentifier->data, "http://", 7) == 0)
				{
					HaveCertHTTP = true;
				}
			}
		}
		sk_ACCESS_DESCRIPTION_pop_free(info, ACCESS_DESCRIPTION_free);
	}
	while (1);

	if (type == SubscriberCertificate)
	{
		if (!HaveCertHTTP)
		{
			SetWarning(WARN_NO_ISSUING_CERT_HTTP);
		}
		if (!HaveAIA)
		{
			SetError(ERR_NO_AIA);
		}
	}

	return HaveOCSPHTTP;
}

static void CheckRevocationOverHTTP(bool have_crl_http, bool have_ocsp_http, struct tm tm_before, struct tm tm_after, CertType type)
{
	if (!have_crl_http && !have_ocsp_http && type == SubscriberCertificate)
	{
		time_t not_before = mktime(&tm_before);
		time_t not_after = mktime(&tm_after);
		bool is_short_lived = false;
		if (not_before >= 1773532800)		/* 2026-03-15T00:00:00Z */
		{
			is_short_lived = (not_after - not_before) < 604800;	/* 7 days */
		}
		else if (not_before >= 1710460800)	/* 2024-03-15T00:00:00Z */
		{
			is_short_lived = (not_after - not_before) < 864000;	/* 10 days */
		}
		if (!is_short_lived)
		{
			SetError(ERR_NO_REVOCATION_HTTP);
		}
	}
}

static void CheckTime(X509 *x509, struct tm *tm_before, struct tm *tm_after, CertType type)
{
	ASN1_TIME *before = X509_get_notBefore(x509);
	ASN1_TIME *after = X509_get_notAfter(x509);
	bool error = false;

	if (!asn1_time_to_tm(before, tm_before))
	{
		error = true;
	}
	if (!asn1_time_to_tm(after, tm_after))
	{
		error = true;
	}

	if (error)
	{
		SetError(ERR_INVALID_TIME_FORMAT);
		return;
	}

	if (type == SubscriberCertificate)
	{
		if (GetBit(cert_info, CERT_INFO_EV))
		{
			/* EV 9.4 */
			if (IsValidLongerThan(*tm_before, *tm_after, 27))
			{
				SetError(ERR_EV_LONGER_27_MONTHS);
			}
			else if (IsValidLongerThan(*tm_before, *tm_after, 12))
			{
				SetWarning(WARN_EV_LONGER_12_MONTHS);
			}
		}
		else
		{
			/* CAB 9.4.1 */
			if (IsValidLongerThan(*tm_before, *tm_after, 60))
			{
				SetError(ERR_LONGER_60_MONTHS);
			}
			else if (IsValidLongerThan(*tm_before, *tm_after, 39))
			{
				SetWarning(WARN_LONGER_39_MONTHS);
			}
		}
	}
}

static int obj_cmp(const ASN1_OBJECT * const *a, const ASN1_OBJECT * const *b)
{
	return OBJ_cmp(*a, *b);
}

static void CheckDuplicateExtensions(X509 *x509)
{
	STACK_OF(ASN1_OBJECT) *stack = sk_ASN1_OBJECT_new(obj_cmp);

	for (int i = 0; i < X509_get_ext_count(x509); i++)
	{
		X509_EXTENSION *ext = X509_get_ext(x509, i);
		if (ext == NULL)
		{
			SetError(ERR_INVALID);
			continue;
		}
		ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
		if (sk_ASN1_OBJECT_find(stack, obj) >= 0)
		{
			SetError(ERR_DUPLICATE_EXTENSION);
		}
		else
		{
			sk_ASN1_OBJECT_push(stack, obj);
		}
	}
	sk_ASN1_OBJECT_free(stack);
}

static void CheckKU(X509 *x509, CertType type)
{
	int critical = -1;

	ASN1_BIT_STRING *usage = X509_get_ext_d2i(x509, NID_key_usage, &critical, NULL);
	if (usage == NULL)
	{
		if (critical >= 0)
		{
			/* Found but fails to parse */
			SetError(ERR_INVALID);
			return;
		}
		if (type != SubscriberCertificate)
		{
			SetError(ERR_NO_KEY_USAGE);
		}
		return;
	}
	if (critical == 0)
	{
		if (type != SubscriberCertificate)
		{
			/* The BRs make this required */
			SetError(ERR_KEY_USAGE_NOT_CRITICAL);
		}
		else
		{
			SetWarning(WARN_KEY_USAGE_NOT_CRITICAL);
		}
	}
	if (usage->length == 0)
	{
		SetError(ERR_KEY_USAGE_EMPTY);
	}
	CheckBitString(usage);
	int bits = 0;
	if (usage->length > 0)
	{
		bits = usage->data[0];
	}
	if (usage->length > 1)
	{
		bits |= (usage->data[1] << 8);
	}
	if ((bits & 0x80FF) != bits)
	{
		SetError(ERR_KEY_USAGE_UNKNOWN_BIT);
	}
	if (usage->length > 2)
	{
		SetError(ERR_KEY_USAGE_TOO_LONG);
	}
	if (bits == 0)
	{
		SetError(ERR_KEY_USAGE_EMPTY);
	}
	if (type == SubscriberCertificate && (bits & KU_KEY_CERT_SIGN) != 0)
	{
		SetError(ERR_KEY_USAGE_HAS_CERT_SIGN);
	}
	if (type != SubscriberCertificate && (bits & (KU_KEY_CERT_SIGN|KU_CRL_SIGN)) == 0)
	{
		SetWarning(WARN_KEY_USAGE_NO_CERT_OR_CRL_SIGN);
	}
	if ((bits & KU_CRL_SIGN) != 0)
	{
		SetCertInfo(CERT_INFO_KU_CRL_SIGN);
	}
	if ((bits & KU_KEY_CERT_SIGN) != 0)
	{
		SetCertInfo(CERT_INFO_KU_CERT_SIGN);
	}
	ASN1_BIT_STRING_free(usage);
}

static void CheckEKU(X509 *x509, CertType type)
{
	int idx = -1;
	bool first = true;

	do
	{
		int critical = -1;

		EXTENDED_KEY_USAGE *ekus = X509_get_ext_d2i(x509, NID_ext_key_usage, &critical, &idx);

		if (ekus == NULL)
		{
			if (critical >= 0)
			{
				/* Found but fails to parse */
				SetError(ERR_INVALID);
				continue;
			}
			/* Not found */
			if (first)
			{
				SetCertInfo(CERT_INFO_NO_EKU);
				if (type == SubscriberCertificate)
				{
					SetWarning(WARN_NO_EKU);
				}
			}
			break;
		}
		first = false;

		if (type == RootCA)
		{
			/* CAB 7.1.2.1d */
			SetError(ERR_ROOT_CA_WITH_EKU);
		}

		for (int i = 0; i < sk_ASN1_OBJECT_num(ekus); i++)
		{
			ASN1_OBJECT *oid = sk_ASN1_OBJECT_value(ekus, i);
			int nid = OBJ_obj2nid(oid);
			if (OBJ_cmp(oid, obj_anyEKU) == 0)
			{
				SetCertInfo(CERT_INFO_ANY_EKU);
			}
			else if (nid == NID_server_auth)
			{
				SetCertInfo(CERT_INFO_SERV_AUTH);
			}
			else if (nid == NID_client_auth)
			{
				SetCertInfo(CERT_INFO_CLIENT_AUTH);
			}
			else if (nid == NID_code_sign)
			{
				SetCertInfo(CERT_INFO_CODE_SIGN);
			}
			else if (nid == NID_email_protect)
			{
				SetCertInfo(CERT_INFO_EMAIL);
			}
			else if (nid == NID_time_stamp)
			{
				SetCertInfo(CERT_INFO_TIME_STAMP);
			}
			else if (nid == NID_OCSP_sign)
			{
				SetCertInfo(CERT_INFO_OCSP_SIGN);
			}
			else if (OBJ_cmp(oid, obj_IntelAMTvProEKU) == 0)
			{
				SetCertInfo(CERT_INFO_AMTVPRO_EKU);
			}
			else
			{
				SetWarning(WARN_UNKNOWN_EKU);
			}
		}
		if (GetBit(cert_info, CERT_INFO_AMTVPRO_EKU) && !GetBit(cert_info, CERT_INFO_SERV_AUTH))
		{
			SetError(ERR_MISSING_EKU);
		}
		if (sk_ASN1_OBJECT_num(ekus) == 0)
		{
			SetError(ERR_EMPTY_EKU);
		}
		sk_ASN1_OBJECT_pop_free(ekus, ASN1_OBJECT_free);
	}
	while (1);
}

static void CheckBasicConstraints(X509 *x509, CertType type)
{
	int critical = -1;

	BASIC_CONSTRAINTS *bc = X509_get_ext_d2i(x509, NID_basic_constraints, &critical, NULL);

	if (bc == NULL)
	{
		if (critical >= 0)
		{
			/* Found but fails to parse */
			SetError(ERR_INVALID);
			return;
		}
		if (type != SubscriberCertificate)
		{
			SetError(ERR_NO_BASIC_CONSTRAINTS);
		}
		return;
	}
	if (type != SubscriberCertificate)
	{
		if (critical == 0)
		{
			SetError(ERR_BASIC_CONSTRAINTS_NOT_CRITICAL);
		}
		if (bc->ca == 0)
		{
			/* X509_check_ca() supports various old methods to detect a CA. */
			SetError(ERR_CA_CERT_NOT_CA);
		}
	}
	if (bc->pathlen != NULL)
	{
		if (bc->pathlen->type == V_ASN1_NEG_INTEGER)
		{
			SetError(ERR_BASIC_CONSTRAINTS_NEG_PATHLEN);
		}
		if (bc->ca == 0)
		{
			SetError(ERR_BASIC_CONSTRAINTS_NO_CA_PATHLEN);
		}
		if (!GetCertInfo(CERT_INFO_KU_CERT_SIGN))
		{
			SetError(ERR_BASIC_CONSTRAINTS_NO_CERT_SIGN_PATHLEN);
		}
	}
	BASIC_CONSTRAINTS_free(bc);
}

static void CheckASN1_integer(ASN1_INTEGER *integer)
{
#if 0
	/* OpenSSL 1.1 should already enforce this */
	if (integer->length > 1 && (((integer->data[0] == 0) && ((integer->data[1] & 0x80) == 0))
		|| ((integer->data[0] == 0xFF) && ((integer->data[1] & 0x80) == 0x80))))
	{
		SetError(ERR_ASN1_INTEGER_NOT_MINIMAL);
	}
#endif
}

static void CheckSerial(X509 *x509)
{
	ASN1_INTEGER *serial = X509_get_serialNumber(x509);
	BIGNUM *bn_serial = ASN1_INTEGER_to_BN(serial, NULL);

	if (BN_is_negative(bn_serial) || BN_is_zero(bn_serial))
	{
		SetError(ERR_SERIAL_NOT_POSITIVE);
	}

	if (serial->length > 20)
	{
		SetError(ERR_SERIAL_TOO_LARGE);
	}

	CheckASN1_integer(serial);
	BN_free(bn_serial);
}

static void CheckPublicKey(X509 *x509, struct tm tm_after)
{
	EVP_PKEY *pkey = X509_get_pubkey(x509);
	if (pkey == NULL)
	{
		SetError(ERR_UNKNOWN_PUBLIC_KEY_TYPE);
		return;
	}

	if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA)
	{
		RSA *rsa = EVP_PKEY_get1_RSA(pkey);

		if (rsa == NULL)
		{
			SetError(ERR_INVALID);
			RSA_free(rsa);
			return;
		}

		const BIGNUM *n, *e;
		RSA_get0_key(rsa, &n, &e, NULL);
		if (n == NULL || e == NULL)
		{
			SetError(ERR_INVALID);
			RSA_free(rsa);
			return;
		}
		if (!GetBit(errors, ERR_INVALID_TIME_FORMAT))
		{
			if (tm_after.tm_year >= 114 && BN_num_bits(n) < 2048)
			{
				SetError(ERR_RSA_SIZE_2048);
			}
		}
		if (BN_is_negative(n))
		{
			SetError(ERR_RSA_MODULUS_NEGATIVE);
		}
		if (BN_is_odd(e) == 0)
		{
			SetError(ERR_RSA_EXP_NOT_ODD);
		}
		BIGNUM *i = BN_new();
		BN_set_word(i, 3);
		if (BN_cmp(e, i) < 0)
		{
			SetError(ERR_RSA_EXP_3);
		}
		else
		{
			BN_set_word(i, 0x10001);
			if (BN_cmp(e, i) < 0)
			{
				SetWarning(WARN_RSA_EXP_RANGE);
			}
			BN_hex2bn(&i, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
			if (BN_cmp(e, i) > 0)
			{
				SetWarning(WARN_RSA_EXP_RANGE);
			}
		}
		BN_CTX *ctx = BN_CTX_new();
		if (BN_gcd(i, n, bn_factors, ctx) == 0 || !BN_is_one(i))
		{
			SetError(ERR_RSA_SMALL_FACTOR);
		}

		X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(x509);
		const unsigned char *k;
		int pklen;
		X509_ALGOR *a;
		X509_PUBKEY_get0_param(NULL, &k, &pklen, &a, pubkey);
		if (a->parameter == NULL)
		{
			SetError(ERR_ALG_PARAMETER_MISSING);
		}
		else if (a->parameter->type != V_ASN1_NULL)
		{
			SetError(ERR_ALG_PARAMETER_NOT_NULL);
		}

		BN_free(i);
		BN_CTX_free(ctx);
		RSA_free(rsa);
	}
	else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC)
	{
		EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
		const EC_GROUP *group = EC_KEY_get0_group(ec_key);
		const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
		BN_CTX *ctx = BN_CTX_new();
		BIGNUM *order = BN_new();
		EC_GROUP_get_order(group, order, ctx);
		if (EC_POINT_is_at_infinity(group, point))
		{
			SetError(ERR_EC_AT_INFINITY);
		}
		if (EC_POINT_is_on_curve(group, point, ctx) != 1)
		{
			SetError(ERR_EC_POINT_NOT_ON_CURVE);
		}
		EC_POINT *result = EC_POINT_new(group);
		if (BN_is_zero(order))
		{
			SetError(ERR_EC_INVALID_GROUP_ORDER);
		}
		EC_POINT_mul(group, result, NULL, point, order, ctx);
		if (!EC_POINT_is_at_infinity(group, result))
		{
			SetError(ERR_EC_INCORRECT_ORDER);
		}
		int nid = EC_GROUP_get_curve_name(group);
		if (nid != NID_X9_62_prime256v1 && nid != NID_secp384r1 && nid != NID_secp521r1)
		{
			SetError(ERR_EC_NON_ALLOWED_CURVE);
		}

		X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(x509);
		const unsigned char *k;
		int pklen;
		X509_ALGOR *a;
		X509_PUBKEY_get0_param(NULL, &k, &pklen, &a, pubkey);

		int pkey_nid = OBJ_obj2nid(a->algorithm);
		if (pkey_nid != NID_X9_62_id_ecPublicKey)
		{
			/* How did we get here? */
			SetError(ERR_INVALID);
		}
		if (a->parameter == NULL)
		{
			SetError(ERR_EC_NO_PARAMETER);
		}
		if (a->parameter != NULL && a->parameter->type != V_ASN1_OBJECT)
		{
			SetError(ERR_NOT_NAMED_CURVE);
		}

		EC_POINT_free(result);
		BN_free(order);
		BN_CTX_free(ctx);
		EC_KEY_free(ec_key);
	}
	else if (EVP_PKEY_id(pkey) == EVP_PKEY_ED25519 || EVP_PKEY_id(pkey) == EVP_PKEY_ED448 || EVP_PKEY_id(pkey) == EVP_PKEY_X25519 || EVP_PKEY_id(pkey) == EVP_PKEY_X448)
	{
		X509_PUBKEY *pubkey = X509_get_X509_PUBKEY(x509);
		const unsigned char *k;
		int pklen;
		X509_ALGOR *a;
		X509_PUBKEY_get0_param(NULL, &k, &pklen, &a, pubkey);
		if (a->parameter != NULL)
		{
			SetError(ERR_ALG_PARAMETER_PRESENT);
		}
	}
	else
	{
		SetError(ERR_UNKNOWN_PUBLIC_KEY_TYPE);
	}

	EVP_PKEY_free(pkey);
}

static void CheckSKID(X509 *x509, CertType type)
{
	int critical = -1;

	ASN1_OCTET_STRING *skid = X509_get_ext_d2i(x509, NID_subject_key_identifier, &critical, NULL);
	if (skid == NULL && critical >= 0)
	{
		SetError(ERR_INVALID);
	}
	if (skid == NULL && type != SubscriberCertificate)
	{
		SetError(ERR_SKID_MISSING);
	}
	if (skid != NULL && critical > 0)
	{
		SetError(ERR_SKID_CRITICAL);
	}
	ASN1_OCTET_STRING_free(skid);
}

CertType GetType(X509 *x509)
{
	int ca = X509_check_ca(x509);

	int critical = -1;
	AUTHORITY_KEYID *akid = X509_get_ext_d2i(x509, NID_authority_key_identifier, &critical, NULL);
	if (akid == NULL && critical >= 0)
	{
		SetError(ERR_INVALID);
	}

	bool self_issued = X509_check_issued(x509, x509) == X509_V_OK;
	bool self_signed = self_issued && (akid == NULL || X509_check_akid(x509, akid) == X509_V_OK);

	if (!self_signed && akid == NULL)
	{
		SetError(ERR_AKID_MISSING);
	}
	if (akid != NULL && critical > 0)
	{
		SetError(ERR_AKID_CRITICAL);
	}
	if (akid != NULL && akid->keyid == NULL)
	{
		SetError(ERR_AKID_WITHOUT_KEY_ID);
	}

	AUTHORITY_KEYID_free(akid);

	if (!ca)
	{
		return SubscriberCertificate;
	}
	else if (!self_signed)
	{
		return IntermediateCA;
	}
	else
	{
		return RootCA;
	}
}

static void CheckPSSSig(const RSA_PSS_PARAMS *pss)
{
	int hash_nid = NID_undef, mask_nid = NID_undef, mask_hash_nid = NID_undef;
	int64_t salt_len = 20;
	int64_t trailer = 1;

	if (pss->hashAlgorithm == NULL)
	{
		hash_nid = NID_sha1;
	}
	else
	{
		hash_nid = OBJ_obj2nid(pss->hashAlgorithm->algorithm);
		if (hash_nid == NID_sha1)
		{
			SetError(ERR_DEFAULT_VALUE);
		}
		if (pss->hashAlgorithm->parameter == NULL)
		{
			SetError(ERR_ALG_PARAMETER_MISSING);
		}
		else if (pss->hashAlgorithm->parameter->type != V_ASN1_NULL)
		{
			SetError(ERR_ALG_PARAMETER_NOT_NULL);
		}
	}
	if (hash_nid != NID_sha256 && hash_nid != NID_sha384 && hash_nid != NID_sha512)
	{
		/* BR 7.1.3.2.1 */
		SetError(ERR_NOT_ALLOWED_HASH);
	}

	if (pss->maskGenAlgorithm == NULL)
	{
		mask_nid = NID_mgf1;
		mask_hash_nid = NID_sha1;
		/* BR 7.1.3.2.1 */
		SetError(ERR_NOT_ALLOWED_HASH);
	}
	else
	{
		mask_nid = OBJ_obj2nid(pss->maskGenAlgorithm->algorithm);
		if (pss->maskGenAlgorithm->parameter == NULL)
		{
			SetError(ERR_ALG_PARAMETER_MISSING);
		}
		else if (pss->maskGenAlgorithm->parameter->type != V_ASN1_SEQUENCE)
		{
			SetError(ERR_ALG_WRONG_TYPE);
		}
		else
		{
			const unsigned char *p = pss->maskGenAlgorithm->parameter->value.sequence->data;
			X509_ALGOR *a = d2i_X509_ALGOR(NULL, &p, pss->maskGenAlgorithm->parameter->value.sequence->length);
			if (a == NULL)
			{
				SetError(ERR_ALG_WRONG_TYPE);
			}
			else
			{
				mask_hash_nid = OBJ_obj2nid(a->algorithm);
				if (a->parameter == NULL)
				{
					SetError(ERR_ALG_PARAMETER_MISSING);
				}
				else if (a->parameter->type != V_ASN1_NULL)
				{
					SetError(ERR_ALG_PARAMETER_NOT_NULL);
				}
				if (mask_nid == NID_mgf1 && mask_hash_nid == NID_sha1)
				{
					SetError(ERR_DEFAULT_VALUE);
				}
				if (mask_hash_nid != NID_sha256 && mask_hash_nid != NID_sha384 && mask_hash_nid != NID_sha512)
				{
					/* BR 7.1.3.2.1 */
					SetError(ERR_NOT_ALLOWED_HASH);
				}
				X509_ALGOR_free(a);
			}
		}
	}
	if (mask_nid != NID_mgf1)
	{
		/* BR 7.1.3.2.1 */
		SetError(ERR_NOT_ALLOWED_MASK_ALGORITHM);
	}

	if (hash_nid != mask_hash_nid)
	{
		/* RFC4055 recommends them to be equal, BR 7.1.3.2.1 only allows them to be equal */
		SetError(ERR_PSS_HASH_NOT_EQUAL);
	}

	if (pss->saltLength != NULL)
	{
		if (!ASN1_INTEGER_get_int64(&salt_len, pss->saltLength))
		{
			SetError(ERR_PSS_INVALID_SALT_LENGTH);
		}
		else if (salt_len == 20)
		{
			SetError(ERR_DEFAULT_VALUE);
		}
	}
	if ((hash_nid == NID_sha256 && salt_len != 32)
		|| (hash_nid == NID_sha384 && salt_len != 40)
		|| (hash_nid == NID_sha512 && salt_len != 48))
	{
		/* BR 7.1.3.2.1 */
		SetError(ERR_PSS_INVALID_SALT_LENGTH);
	}

	if (pss->trailerField != NULL)
	{
		if (!ASN1_INTEGER_get_int64(&trailer, pss->trailerField))
		{
			SetError(ERR_PSS_INVALID_TRAILER);
		}
		else if (trailer == 1)
		{
			SetError(ERR_DEFAULT_VALUE);
		}
	}
	if (trailer != 1)
	{
		SetError(ERR_PSS_INVALID_TRAILER);
	}
}

static void CheckSigAlg(X509 *x509)
{
	const X509_ALGOR *sig_alg, *tbs_sig_alg;
	X509_get0_signature(NULL, &sig_alg, x509);
	tbs_sig_alg = X509_get0_tbs_sigalg(x509);
	if (X509_ALGOR_cmp(sig_alg, tbs_sig_alg) != 0)
	{
		SetError(ERR_SIG_ALG_MISMATCH);
	}
	int sig_nid = OBJ_obj2nid(sig_alg->algorithm);
	if (sig_nid == NID_undef)
	{
		SetError(ERR_UNKNOWN_SIGNATURE_ALGORITHM);
		return;
	}
	int pkey_nid;
	if (OBJ_find_sigid_algs(sig_nid, NULL, &pkey_nid) == 0)
	{
		SetError(ERR_UNKNOWN_SIGNATURE_ALGORITHM);
		return;
	}
	if (pkey_nid == NID_dsa || pkey_nid == NID_dsa_2 || pkey_nid == NID_ED25519
	   || pkey_nid == NID_ED448 || pkey_nid == NID_X9_62_id_ecPublicKey
	   || pkey_nid == NID_id_GostR3411_94 || pkey_nid == NID_id_GostR3410_2001)
	{
		if (sig_alg->parameter != NULL || tbs_sig_alg->parameter != NULL)
		{
			SetError(ERR_ALG_PARAMETER_PRESENT);
		}
	}
	else if (sig_nid == NID_rsassaPss)
	{
		if (sig_alg->parameter == NULL || tbs_sig_alg->parameter == NULL)
		{
			SetError(ERR_ALG_PARAMETER_MISSING);
		}
		else if (sig_alg->parameter->type != V_ASN1_SEQUENCE || tbs_sig_alg->parameter->type != V_ASN1_SEQUENCE)
		{
			SetError(ERR_ALG_WRONG_TYPE);
		}
		else
		{
			RSA_PSS_PARAMS *pss = NULL;
			const unsigned char *p = sig_alg->parameter->value.sequence->data;
			pss = d2i_RSA_PSS_PARAMS(NULL, &p, sig_alg->parameter->value.sequence->length);
			if (pss == NULL)
			{
				SetError(ERR_ALG_FAILED_DECODING);
			}
			else
			{
				CheckPSSSig(pss);
			}
			RSA_PSS_PARAMS_free(pss);

			p = tbs_sig_alg->parameter->value.sequence->data;
			pss = d2i_RSA_PSS_PARAMS(NULL, &p, sig_alg->parameter->value.sequence->length);
			if (pss == NULL)
			{
				SetError(ERR_ALG_FAILED_DECODING);
			}
			else
			{
				CheckPSSSig(pss);
			}
			RSA_PSS_PARAMS_free(pss);
		}
	}
	else if (pkey_nid == NID_rsaEncryption)
	{
		if (sig_alg->parameter == NULL || tbs_sig_alg->parameter == NULL)
		{
			SetError(ERR_ALG_PARAMETER_MISSING);
		}
		else if (sig_alg->parameter->type != V_ASN1_NULL || tbs_sig_alg->parameter->type != V_ASN1_NULL)
		{
			SetError(ERR_ALG_PARAMETER_NOT_NULL);
		}
	}
	else
	{
		SetError(ERR_UNKNOWN_SIGNATURE_ALGORITHM);
	}
}

void check(const unsigned char *cert_buffer, size_t cert_len, CertFormat format, CertType type)
{
	X509_NAME *issuer;
	X509_NAME *subject;
	int ret;
	X509 *x509;
	struct tm tm_before;
	struct tm tm_after;

	Clear();

	x509 = GetCert(cert_buffer, cert_len, format);
	if (x509 == NULL)
	{
		SetError(ERR_INVALID);
		return;
	}

	if (type != GetType(x509))
	{
		SetWarning(WARN_CALLED_WITH_WRONG_TYPE);
	}

	if (type == SubscriberCertificate)
	{
		SetInfo(INF_CHECKING_LEAF);
	}
	else if (type == IntermediateCA)
	{
		SetInfo(INF_CHECKING_INTERMEDIATE_CA);
	}
	else if (type == RootCA)
	{
		SetInfo(INF_CHECKING_ROOT_CA);
	}

	ret = X509_get_version(x509);
	if (ret != 2)
	{
		SetError(ERR_NOT_VERSION3);
	}
	//CheckASN1_integer(x509->cert_info->version);

	issuer = X509_get_issuer_name(x509);
	if (issuer == NULL)
	{
		SetError(ERR_INVALID);
		return;
	}
	CheckDN(issuer);
	if (X509_NAME_entry_count(issuer) == 0)
	{
		SetError(ERR_EMPTY_ISSUER);
	}

	CheckSerial(x509);
	CheckTime(x509, &tm_before, &tm_after, type);

	/* Required by CAB base 9.1.3 */
	if (!IsNameObjPresent(issuer, obj_organizationName))
	{
		SetError(ERR_ISSUER_ORG_NAME);
	}

	/* Required by CAB base 9.1.4 */
	if (!IsNameObjPresent(issuer, obj_countryName))
	{
		SetError(ERR_ISSUER_COUNTRY);
	}

	subject = X509_get_subject_name(x509);
	if (subject == NULL)
	{
		SetError(ERR_INVALID);
		return;
	}
	CheckDN(subject);

	CheckDuplicateExtensions(x509);

	/* Prohibited in CAB base 7.1.4.2.2d */
	if (!IsNameObjPresent(subject, obj_organizationName)
		&& !IsNameObjPresent(subject, obj_givenName)
		&& !IsNameObjPresent(subject, obj_surname)
		&& IsNameObjPresent(subject, obj_StreetAddress))
	{
		SetError(ERR_SUBJECT_ADDR);
	}

	/* Required in CAB base 7.1.4.2.2e and 7.1.4.2.2f */
	if (((IsNameObjPresent(subject, obj_organizationName) && type == SubscriberCertificate) ||
		IsNameObjPresent(subject, obj_givenName) ||
		IsNameObjPresent(subject, obj_surname))
		&& !IsNameObjPresent(subject, obj_stateOrProvinceName)
		&& !IsNameObjPresent(subject, obj_localityName))
	{
		SetError(ERR_SUBJECT_ORG_NO_PLACE);
	}

	/* Prohibited in CAB base 7.1.4.2.2e or 7.1.4.2.2f */
	if (!IsNameObjPresent(subject, obj_organizationName)
		&& !IsNameObjPresent(subject, obj_givenName)
		&& !IsNameObjPresent(subject, obj_surname)
		&& (IsNameObjPresent(subject, obj_localityName)
			|| IsNameObjPresent(subject, obj_stateOrProvinceName)))
	{
		SetError(ERR_SUBJECT_NO_ORG_PLACE);
	}

	/* Required by CAB base 7.1.4.2.2g */
	if (!IsNameObjPresent(subject, obj_organizationName)
		&& !IsNameObjPresent(subject, obj_givenName)
		&& !IsNameObjPresent(subject, obj_surname)
		&& IsNameObjPresent(subject, obj_postalCode))
	{
		SetError(ERR_SUBJECT_POSTAL);
	}

	/* Required by CAB base 7.1.4.2.2h */
	if ((IsNameObjPresent(subject, obj_organizationName) ||
		IsNameObjPresent(subject, obj_givenName) ||
		IsNameObjPresent(subject, obj_surname))
		&& !IsNameObjPresent(subject, obj_countryName))
	{
		SetError(ERR_SUBJECT_COUNTRY);
	}

	CheckKU(x509, type);
	CheckEKU(x509, type);
	CheckPolicy(x509, type, subject);
	CheckSAN(x509, type);
	CheckBasicConstraints(x509, type);
	CheckSKID(x509, type);

	/* Deprecated in CAB base 7.1.4.2.2a */
	if (IsNameObjPresent(subject, obj_commonName))
	{
		if (type == SubscriberCertificate)
		{
			SetInfo(INF_SUBJECT_CN);
		}
	}
	else if (type != SubscriberCertificate)
	{
		SetWarning(WARN_NO_CN);
	}

	CheckRevocationOverHTTP(CheckCRL(x509), CheckAIA(x509, type), tm_before, tm_after, type);

	CheckPublicKey(x509, tm_after);

	if ((type != SubscriberCertificate
		|| GetCertInfo(CERT_INFO_KU_CRL_SIGN)
		|| !GetCertInfo(CERT_INFO_HAS_SAN)
		) && X509_NAME_entry_count(subject) == 0)
	{
		SetError(ERR_EMPTY_SUBJECT);
	}

	CheckSigAlg(x509);

	X509_free(x509);
}

void check_init()
{
	OpenSSL_add_all_algorithms();

	iconv_utf8 = iconv_open("utf-8", "utf-8");
	iconv_ucs2 = iconv_open("utf-8", "ucs-2be");
	iconv_utf32 = iconv_open("utf-32", "utf-8");

	obj_organizationName = OBJ_nid2obj(NID_organizationName);
	obj_organizationalUnitName = OBJ_nid2obj(NID_organizationalUnitName);
	obj_localityName = OBJ_nid2obj(NID_localityName);
	obj_stateOrProvinceName = OBJ_nid2obj(NID_stateOrProvinceName);
	obj_countryName = OBJ_nid2obj(NID_countryName);
	obj_commonName = OBJ_nid2obj(NID_commonName);
	obj_givenName = OBJ_nid2obj(NID_givenName);
	obj_surname = OBJ_nid2obj(NID_surname);
	obj_businessCategory = OBJ_nid2obj(NID_businessCategory);
	obj_serialNumber = OBJ_nid2obj(NID_serialNumber);
	obj_dnQualifier = OBJ_nid2obj(NID_dnQualifier);
	obj_domainComponent = OBJ_nid2obj(NID_domainComponent);
	obj_pkcs9_emailAddress = OBJ_nid2obj(NID_pkcs9_emailAddress);
	obj_pkcs9_unstructuredName = OBJ_nid2obj(NID_pkcs9_unstructuredName);

	obj_jurisdictionCountryName = OBJ_txt2obj(OIDjurisdictionCountryName, 1);
	obj_jurisdictionLocalityName = OBJ_txt2obj(OIDjurisdictionLocalityName, 1);
	obj_jurisdictionStateOrProvinceName = OBJ_txt2obj(OIDjurisdictionStateOrProvinceName, 1);

	obj_StreetAddress = OBJ_txt2obj(OIDStreetAddress, 1);
	obj_postalCode = OBJ_txt2obj(OIDpostalCode, 1);
	obj_postOfficeBox = OBJ_txt2obj(OIDpostOfficeBox, 1);
	obj_anyEKU = OBJ_txt2obj(OIDanyEKU, 1);
	obj_IntelAMTvProEKU = OBJ_txt2obj(OIDIntelAMTvProEKU, 1);

	bn_factors = BN_new();

	BN_set_word(bn_factors, 2);
	for (int i = 1; i < sizeof(primes)/sizeof(*primes); i++)
	{
		BN_mul_word(bn_factors, primes[i]);
	}
}

void check_finish()
{
	iconv_close(iconv_utf8);
	iconv_close(iconv_ucs2);
	iconv_close(iconv_utf32);
	BN_free(bn_factors);
	ASN1_OBJECT_free(obj_jurisdictionCountryName);
	ASN1_OBJECT_free(obj_jurisdictionLocalityName);
	ASN1_OBJECT_free(obj_jurisdictionStateOrProvinceName);
	ASN1_OBJECT_free(obj_StreetAddress);
	ASN1_OBJECT_free(obj_postalCode);
	ASN1_OBJECT_free(obj_postOfficeBox);
	ASN1_OBJECT_free(obj_anyEKU);
	ASN1_OBJECT_free(obj_IntelAMTvProEKU);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

