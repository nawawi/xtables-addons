/*
 *	"asn" match extension for iptables
 *	Copyright © Samuel Jean <peejix [at] people netfilter org>, 2004 - 2008
 *	Copyright © Nicolas Bouliane <acidfu [at] people netfilter org>, 2004 - 2008
 *	Jan Engelhardt, 2008-2011
 *	D. Stussy, 2019 - Converted libxt_geoip.c to ASN use
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xtables.h>
#include "xt_asn.h"
#include "compat_user.h"
#define ASN_DB_DIR "/usr/share/xt_asn"

static void asn_help(void)
{
	printf (
	"asn match options:\n"
	"[!] --src-asn, --source-number number[,number...]\n"
	"	Match packet coming from (one of) the specified ASN(s)\n"
	"[!] --dst-asn, --destination-number number[,number...]\n"
	"	Match packet going to (one of) the specified ASN(s)\n"
	"\n"
	"NOTE: The number is inputed by its ISO3166 code.\n"
	"\n"
	);
}

static struct option asn_opts[] = {
	{.name = "dst-asn",            .has_arg = true, .val = '2'},
	{.name = "destination-number", .has_arg = true, .val = '2'},
	{.name = "src-asn",            .has_arg = true, .val = '1'},
	{.name = "source-number",      .has_arg = true, .val = '1'},
	{NULL},
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
static void asn_swap_le16(uint16_t *buf)
{
	unsigned char *p = (void *)buf;
	uint16_t n= p[0] + (p[1] << 8);
	p[0] = (n >> 8) & 0xff;
	p[1] = n & 0xff;
}

static void asn_swap_in6(struct in6_addr *in6)
{
	asn_swap_le16(&in6->s6_addr16[0]);
	asn_swap_le16(&in6->s6_addr16[1]);
	asn_swap_le16(&in6->s6_addr16[2]);
	asn_swap_le16(&in6->s6_addr16[3]);
	asn_swap_le16(&in6->s6_addr16[4]);
	asn_swap_le16(&in6->s6_addr16[5]);
	asn_swap_le16(&in6->s6_addr16[6]);
	asn_swap_le16(&in6->s6_addr16[7]);
}

static void asn_swap_le32(uint32_t *buf)
{
	unsigned char *p = (void *)buf;
	uint32_t n = p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24);
	p[0] = (n >> 24) & 0xff;
	p[1] = (n >> 16) & 0xff;
	p[2] = (n >> 8) & 0xff;
	p[3] = n & 0xff;
}
#endif

static void *
asn_get_subnets(const char *code, uint32_t *count, uint8_t nfproto)
{
	void *subnets;
	struct stat sb;
	char buf[256];
	int fd;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int n;
#endif

	/* Use simple integer vector files */
	if (nfproto == NFPROTO_IPV6)
		snprintf(buf, sizeof(buf), ASN_DB_DIR "/%s.iv6", code);
	else
		snprintf(buf, sizeof(buf), ASN_DB_DIR "/%s.iv4", code);

	if ((fd = open(buf, O_RDONLY)) < 0) {
		fprintf(stderr, "Could not open %s: %s\n", buf, strerror(errno));
		xtables_error(OTHER_PROBLEM, "Could not read asn database");
	}

	fstat(fd, &sb);
	*count = sb.st_size;
	switch (nfproto) {
	case NFPROTO_IPV6:
		if (sb.st_size % sizeof(struct asn_subnet6) != 0)
			xtables_error(OTHER_PROBLEM,
				"Database file %s seems to be corrupted", buf);
		*count /= sizeof(struct asn_subnet6);
		break;
	case NFPROTO_IPV4:
		if (sb.st_size % sizeof(struct asn_subnet4) != 0)
			xtables_error(OTHER_PROBLEM,
				"Database file %s seems to be corrupted", buf);
		*count /= sizeof(struct asn_subnet4);
		break;
	}
	subnets = malloc(sb.st_size);
	if (subnets == NULL)
		xtables_error(OTHER_PROBLEM, "asn: insufficient memory");
	read(fd, subnets, sb.st_size);
	close(fd);

#if __BYTE_ORDER == __LITTLE_ENDIAN
	for (n = 0; n < *count; ++n) {
		switch (nfproto) {
		case NFPROTO_IPV6: {
			struct asn_subnet6 *gs6 = &(((struct asn_subnet6 *)subnets)[n]);
			asn_swap_in6(&gs6->begin);
			asn_swap_in6(&gs6->end);
			break;
		}
		case NFPROTO_IPV4: {
			struct asn_subnet4 *gs4 = &(((struct asn_subnet4 *)subnets)[n]);
			asn_swap_le32(&gs4->begin);
			asn_swap_le32(&gs4->end);
			break;
		}
		}
	}
#endif
	return subnets;
}

static struct asn_number_user *asn_load_asn(const char *code,
    unsigned long asn, uint8_t nfproto)
{
	struct asn_number_user *ginfo;
	ginfo = malloc(sizeof(struct asn_number_user));

	if (!ginfo)
		return NULL;

	ginfo->subnets = (unsigned long)asn_get_subnets(code,
	                 &ginfo->count, nfproto);
	ginfo->asn = asn;

	return ginfo;
}

static u_int32_t
check_asn_value(char *asn, u_int32_t asn_used[], u_int8_t count)
{
	u_int8_t i;
	u_int32_t tmp_asn = 0;

	for (i = 0; i < strlen(asn); i++)
		if (!isdigit(asn[i]))
			xtables_error(PARAMETER_PROBLEM,
				"asn:  invalid number code '%s'", asn);

	if (i < 1) /* Empty string */
		xtables_error(PARAMETER_PROBLEM, "asn: missing number code");

	tmp_asn = strtoul(asn, NULL, 10);

	// Check for presence of value in asn_used
	for (i = 0; i < count; i++)
		if (tmp_asn == asn_used[i])
			return 0; // Present, skip it!

	return tmp_asn;
}

static unsigned int parse_asn_value(const char *asnstr, uint32_t *asn,
    union asn_number_group *mem, uint8_t nfproto)
{
	char *buffer, *cp, *next;
	u_int8_t i, count = 0;
	u_int32_t asntmp;

	buffer = strdup(asnstr);
	if (!buffer)
		xtables_error(OTHER_PROBLEM,
			"asn: insufficient memory available");

	for (cp = buffer, i = 0; cp && i < XT_ASN_MAX; cp = next, i++)
	{
		next = strchr(cp, ',');
		if (next) *next++ = '\0';

		if ((asntmp = check_asn_value(cp, asn, count)) != 0) {
			if ((mem[count++].user =
			    (unsigned long)asn_load_asn(cp, asntmp, nfproto)) == 0)
				xtables_error(OTHER_PROBLEM,
					"asn: insufficient memory available");
			asn[count-1] = asntmp;
		} /* ASN 0 is reserved and ignored */
	}

	if (cp)
		xtables_error(PARAMETER_PROBLEM,
			"asn: too many ASNs specified");
	free(buffer);

	if (count == 0)
		xtables_error(PARAMETER_PROBLEM,
			"asn: don't know what happened");

	return count;
}

static int asn_parse(int c, bool invert, unsigned int *flags,
    const char *arg, struct xt_asn_match_info *info, uint8_t nfproto)
{
	switch (c) {
	case '1':
		if (*flags & (XT_ASN_SRC | XT_ASN_DST))
			xtables_error(PARAMETER_PROBLEM,
				"asn: Only exactly one of --src-asn "
				"or --dst-asn must be specified!");

		*flags |= XT_ASN_SRC;
		if (invert)
			*flags |= XT_ASN_INV;

		info->count = parse_asn_value(arg, info->asn, info->mem,
		              nfproto);
		info->flags = *flags;
		return true;

	case '2':
		if (*flags & (XT_ASN_SRC | XT_ASN_DST))
			xtables_error(PARAMETER_PROBLEM,
				"asn: Only exactly one of --src-asn "
				"or --dst-asn must be specified!");

		*flags |= XT_ASN_DST;
		if (invert)
			*flags |= XT_ASN_INV;

		info->count = parse_asn_value(arg, info->asn, info->mem,
		              nfproto);
		info->flags = *flags;
		return true;
	}

	return false;
}

static int asn_parse6(int c, char **argv, int invert, unsigned int *flags,
    const void *entry, struct xt_entry_match **match)
{
	return asn_parse(c, invert, flags, optarg,
	       (void *)(*match)->data, NFPROTO_IPV6);
}

static int asn_parse4(int c, char **argv, int invert, unsigned int *flags,
    const void *entry, struct xt_entry_match **match)
{
	return asn_parse(c, invert, flags, optarg,
	       (void *)(*match)->data, NFPROTO_IPV4);
}

static void
asn_final_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			"asn: missing arguments");
}

static void
asn_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_asn_match_info *info = (void *)match->data;
	u_int8_t i;

	if (info->flags & XT_ASN_INV)
		printf(" !");

	if (info->flags & XT_ASN_SRC)
		printf(" --src-asn ");
	else
		printf(" --dst-asn ");

	for (i = 0; i < info->count; i++)
		printf("%s%u", i ? "," : "", info->asn[i]);
}

static void
asn_print(const void *ip, const struct xt_entry_match *match, int numeric)
{
	printf(" -m asn");
	asn_save(ip, match);
}

static struct xtables_match asn_match[] = {
	{
		.family        = NFPROTO_IPV6,
		.name          = "asn",
		.revision      = 1,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_asn_match_info)),
		.userspacesize = offsetof(struct xt_asn_match_info, mem),
		.help          = asn_help,
		.parse         = asn_parse6,
		.final_check   = asn_final_check,
		.print         = asn_print,
		.save          = asn_save,
		.extra_opts    = asn_opts,
	},
	{
		.family        = NFPROTO_IPV4,
		.name          = "asn",
		.revision      = 1,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_asn_match_info)),
		.userspacesize = offsetof(struct xt_asn_match_info, mem),
		.help          = asn_help,
		.parse         = asn_parse4,
		.final_check   = asn_final_check,
		.print         = asn_print,
		.save          = asn_save,
		.extra_opts    = asn_opts,
	},
};

static __attribute__((constructor)) void asn_mt_ldr(void)
{
	xtables_register_matches(asn_match,
		sizeof(asn_match) / sizeof(*asn_match));
}
