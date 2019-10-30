#pragma once

#include <time.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/sockaddr_str.h>

struct proxy_subscr {
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	struct osmo_sockaddr_str remote_hlr;
};

void proxy_init(void *ctx);
const struct proxy_subscr *proxy_subscr_get(const char *imsi);
int proxy_subscr_update(const struct proxy_subscr *proxy_subscr);
int proxy_subscr_del(const char *imsi);

void timestamp_update(struct timeval *timestamp);
time_t timestamp_age(const struct timeval *timestamp);
