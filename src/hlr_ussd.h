#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsup.h>
#include "gsup_server.h"

struct osmo_gsup_conn;

struct hlr_euse_route {
	/* hlr_euse.routes */
	struct llist_head list;
	struct hlr_euse *euse;
	const char *prefix;
};

struct hlr_euse {
	/* list in the per-hlr list of EUSEs */
	struct llist_head list;
	struct hlr *hlr;
	/* name (must match the IPA ID tag) */
	const char *name;
	/* human-readable description */
	const char *description;
	/* list of hlr_euse_route */
	struct llist_head routes;

	/* GSUP connection to the EUSE, if any */
	struct osmo_gsup_conn *conn;
};


struct hlr_euse *euse_find(struct hlr *hlr, const char *name);
struct hlr_euse *euse_alloc(struct hlr *hlr, const char *name);
void euse_del(struct hlr_euse *euse);

struct hlr_euse_route *euse_route_find(struct hlr_euse *euse, const char *prefix);
struct hlr_euse_route *euse_route_prefix_alloc(struct hlr_euse *euse, const char *prefix);
void euse_route_del(struct hlr_euse_route *rt);

int rx_proc_ss_req(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup);
int rx_proc_ss_error(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup);
