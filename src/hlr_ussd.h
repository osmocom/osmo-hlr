#pragma once

#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsup.h>

#include "gsup_server.h"

struct hlr_ussd_route {
	/* g_hlr.routes */
	struct llist_head list;
	const char *prefix;
	bool is_external;
	union {
		struct hlr_euse *euse;
		const struct hlr_iuse *iuse;
	} u;
};

struct hlr_euse {
	/* list in the per-hlr list of EUSEs */
	struct llist_head list;
	struct hlr *hlr;
	/* name (must match the IPA ID tag) */
	const char *name;
	/* human-readable description */
	const char *description;

	/* GSUP connection to the EUSE, if any */
	struct osmo_gsup_conn *conn;
};

struct hlr_euse *euse_find(struct hlr *hlr, const char *name);
struct hlr_euse *euse_alloc(struct hlr *hlr, const char *name);
void euse_del(struct hlr_euse *euse);

const struct hlr_iuse *iuse_find(const char *name);

struct hlr_ussd_route *ussd_route_find_prefix(struct hlr *hlr, const char *prefix);
struct hlr_ussd_route *ussd_route_prefix_alloc_int(struct hlr *hlr, const char *prefix,
						   const struct hlr_iuse *iuse);
struct hlr_ussd_route *ussd_route_prefix_alloc_ext(struct hlr *hlr, const char *prefix,
						   struct hlr_euse *euse);
void ussd_route_del(struct hlr_ussd_route *rt);

int rx_proc_ss_req(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup);
int rx_proc_ss_error(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup);

struct ss_session;
struct ss_request;

/* Internal USSD Handler */
struct hlr_iuse {
	const char *name;
	/* call-back to be called for any incoming USSD messages for this IUSE */
	int (*handle_ussd)(struct osmo_gsup_conn *conn, struct ss_session *ss,
			   const struct osmo_gsup_message *gsup, const struct ss_request *req);
};
