#pragma once

#include <osmocom/core/linuxlist.h>

struct hlr_smsc {
	/* g_hlr->smsc_list */
	struct llist_head list;
	struct hlr *hlr;
	/* name (must match the IPA ID tag) */
	const char *name;
	/* human-readable description */
	const char *description;
};

struct hlr_smsc *smsc_find(struct hlr *hlr, const char *name);
struct hlr_smsc *smsc_alloc(struct hlr *hlr, const char *name);
void smsc_del(struct hlr_smsc *smsc);

struct hlr_smsc_route {
	/* g_hlr->smsc_routes */
	struct llist_head list;
	const char *num_addr;
	struct hlr_smsc *smsc;
};

struct hlr_smsc_route *smsc_route_find(struct hlr *hlr, const char *num_addr);
struct hlr_smsc_route *smsc_route_alloc(struct hlr *hlr, const char *num_addr,
					struct hlr_smsc *smsc);
void smsc_route_del(struct hlr_smsc_route *rt);

void forward_mo_sms(struct osmo_gsup_req *req);
