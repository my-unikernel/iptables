/* Shared library add-on to iptables to add TRACE target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_COLO.h>


#define s struct xt_colo_primary_info
static const struct xt_option_entry colo_opts[] = {
	{.name = "index", .id = 0, .type = XTTYPE_UINT32,
	 .flags = XTOPT_PUT, XTOPT_POINTER(s, index),
	 .excl = 1},
	XTOPT_TABLEEND,
};
#undef s


static void colo_parse(struct xt_option_call *cb)
{
	struct xt_colo_primary_info *einfo = cb->data;

	xtables_option_parse(cb);
	einfo->index = cb->val.u32;
}


static void colo_print(const void *ip, const struct xt_entry_target *target,
                      int numeric)
{
	const struct xt_colo_primary_info *einfo =
		(const struct xt_colo_primary_info *)target->data;

	printf("PMYCOLO");

	printf("index %d", einfo->index);
}

static void colo_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_colo_primary_info *einfo =
		(const struct xt_colo_primary_info *)target->data;

	printf("--index %d", einfo->index);
}
/*
static void colo_primary_init(struct xt_entry_target *target)
{
	struct xt_colo_primary_info *info = (void *)target->data;

	info->index = 33;
}
*/
static struct xtables_target colo_target = {
	.family		= NFPROTO_UNSPEC,
	.name		= "PMYCOLO",
	.version	= XTABLES_VERSION,
	.size		= XT_ALIGN(sizeof(struct xt_colo_primary_info)),
	//.size		= 0,
	.userspacesize	= offsetof(struct xt_colo_primary_info, colo),
	//.userspacesize	= XT_ALIGN(sizeof(struct xt_COLO_info)),
	.save		= colo_save,
	.print		= colo_print,
	.x6_parse	= colo_parse,
	.x6_options	= colo_opts,
	//.init		= colo_primary_init,
};


void _init(void)
{
	xtables_register_target(&colo_target);
}
