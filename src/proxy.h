#pragma once

#include <time.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/sockaddr_str.h>
#include "global_title.h"

void timestamp_update(struct timeval *timestamp);
time_t timestamp_age(const struct timeval *timestamp);

struct proxy {
	struct llist_head subscr_list;

	/* How long to keep proxy entries without a refresh, in seconds. */
	uint32_t fresh_time;

	/* How often to garbage collect the proxy cache, period in seconds.
	 * To change this and take effect immediately, rather use proxy_set_gc_period(). */
	uint32_t gc_period;

	struct osmo_timer_list gc_timer;
};

struct proxy_subscr {
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	char msisdn[GSM23003_MSISDN_MAX_DIGITS+1];
#if 0
	/* Set if this is a middle proxy, i.e. a proxy behind another proxy. */
	struct global_title vlr_via_proxy;
#endif
	struct global_title vlr_name;
	struct osmo_sockaddr_str remote_hlr_addr;
	struct timeval last_lu;
};

struct proxy *proxy_init(void *ctx);
void proxy_del(struct proxy *proxy);
void proxy_set_gc_period(struct proxy *proxy, uint32_t gc_period);

/* The API to access / modify proxy entries keeps the implementation opaque, to make sure that we can easily move proxy
 * storage to SQLite db. */
const struct proxy_subscr *proxy_subscr_get_by_imsi(struct proxy *proxy, const char *imsi);
const struct proxy_subscr *proxy_subscr_get_by_msisdn(struct proxy *proxy, const char *msisdn);
void proxy_subscrs_get_by_remote_hlr(struct proxy *proxy, const struct osmo_sockaddr_str *remote_hlr_addr,
				     bool (*yield)(struct proxy *proxy, const struct proxy_subscr *subscr, void *data),
				     void *data);
const struct proxy_subscr *proxy_subscr_get_by_imsi(struct proxy *proxy, const char *imsi);
int proxy_subscr_update(struct proxy *proxy, const struct proxy_subscr *proxy_subscr);
int proxy_subscr_del(struct proxy *proxy, const char *imsi);
