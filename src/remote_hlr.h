#pragma once

#include <stdbool.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>

struct osmo_gsup_client;
struct osmo_gsup_message;
struct msgb;

#define LOG_GSUPC(gsupc, level, fmt, args...) \
	LOGP(DDGSM, level, "HLR Proxy: GSUP from %s:%u: " fmt, (gsupc)->link->addr, (gsupc)->link->port, ##args)

#define LOG_GSUPC_MSG(gsupc, gsup_msg, level, fmt, args...) \
	LOG_GSUPC(gsupc, level, "%s: " fmt, osmo_gsup_message_type_name((gsup_msg)->message_type), ##args)

/* GSUP client link for proxying to a remote HLR. */
struct remote_hlr {
	struct llist_head entry;
	struct osmo_sockaddr_str addr;
	struct osmo_gsup_client *gsupc;
};

struct remote_hlr *remote_hlr_get(const struct osmo_sockaddr_str *addr, bool create);
void remote_hlr_destroy(struct remote_hlr *remote_hlr);
int remote_hlr_msgb_send(struct remote_hlr *remote_hlr, struct msgb *msg);
int remote_hlr_gsup_send(struct remote_hlr *remote_hlr, const struct osmo_gsup_message *gsup);
