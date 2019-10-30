#pragma once

#include <stdbool.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>

struct osmo_gsup_client;
struct osmo_gsup_message;
struct msgb;

struct remote_hlr {
	struct llist_head entry;
	struct osmo_sockaddr_str addr;
	struct osmo_gsup_client *gsupc;
};

struct remote_hlr *remote_hlr_get(const struct osmo_sockaddr_str *addr, bool create);
int remote_hlr_msgb_send(struct remote_hlr *remote_hlr, struct msgb *msg);
int remote_hlr_gsup_send(struct remote_hlr *remote_hlr, const struct osmo_gsup_message *gsup);
