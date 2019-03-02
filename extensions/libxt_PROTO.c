/*
 * PROTO Target module
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <xtables.h>
#include "xt_PROTO.h"

enum {
	O_PROTO_SET = 0,
	O_PROTO_STOP_AT_FRAG = 1,
	O_PROTO_STOP_AT_AUTH = 2,
	F_PROTO_SET = 1 << O_PROTO_SET,
	F_PROTO_STOP_AT_FRAG = 1 << O_PROTO_STOP_AT_FRAG,
	F_PROTO_STOP_AT_AUTH = 1 << O_PROTO_STOP_AT_AUTH,
};

#define s struct xt_PROTO_info
static const struct xt_option_entry PROTO_opts[] = {
	{.name = "proto-set", .type = XTTYPE_UINT8, .id = O_PROTO_SET,
	 .flags = XTOPT_PUT | XTOPT_MAND, XTOPT_POINTER(s, proto)},
	{.name = "stop-at-frag", .type = XTTYPE_NONE, .id = O_PROTO_STOP_AT_FRAG},
	{.name = "stop-at-auth", .type = XTTYPE_NONE, .id = O_PROTO_STOP_AT_AUTH},
	XTOPT_TABLEEND,
};
#undef s

static void PROTO_help(void)
{
	printf(
"PROTO target options\n"
"  --proto-set value		Set protocol to <value 0-255>\n"
	);
}

static void PROTO_parse(struct xt_option_call *cb)
{
	struct xt_PROTO_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_PROTO_SET:
		info->mode |= 1 << XT_PROTO_SET;
		break;
	case O_PROTO_STOP_AT_FRAG:
		info->mode |= 1 << XT_PROTO_STOP_AT_FRAG;
		break;
	case O_PROTO_STOP_AT_AUTH:
		info->mode |= 1 << XT_PROTO_STOP_AT_AUTH;
		break;
	}
}

static void PROTO_check(struct xt_fcheck_call *cb)
{
	if (!(cb->xflags & F_PROTO_SET))
		xtables_error(PARAMETER_PROBLEM,
				"PROTO: You must specify the proto to be set");
}

static void PROTO_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_PROTO_info *info = 
		(struct xt_PROTO_info *) target->data;

	if(info->mode & (1 << XT_PROTO_SET)){
		printf(" --proto-set %u", info->proto);
	} 
	if(info->mode & (1 << XT_PROTO_STOP_AT_FRAG)){
		printf(" --stop-at-frag");
	} 
	if(info->mode & (1 << XT_PROTO_STOP_AT_AUTH)){
		printf(" --stop-at-auth");
	} 
}

static void PROTO_print(const void *ip, const struct xt_entry_target *target,
                     int numeric)
{
	const struct xt_PROTO_info *info =
		(struct xt_PROTO_info *) target->data;

	printf(" PROTO ");
	if(info->mode & (1 << XT_PROTO_SET)){
		printf("set to %u", info->proto);
	} 
	if(info->mode & (1 << XT_PROTO_STOP_AT_FRAG)){
		printf(" stop-at-frag");
	} 
	if(info->mode & (1 << XT_PROTO_STOP_AT_AUTH)){
		printf(" stop-at-auth");
	} 
}

static struct xtables_target proto_tg_reg = {
	.name 		= "PROTO",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_UNSPEC,
	.size		= XT_ALIGN(sizeof(struct xt_PROTO_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct xt_PROTO_info)),
	.help		= PROTO_help,
	.print		= PROTO_print,
	.save		= PROTO_save,
	.x6_parse	= PROTO_parse,
	.x6_fcheck	= PROTO_check,
	.x6_options	= PROTO_opts,
};

static __attribute__((constructor)) void _init(void)
{
	xtables_register_target(&proto_tg_reg);

}
