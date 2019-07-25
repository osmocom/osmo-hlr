#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsup.h>

#include "gsup_server.h"

enum hlr_sms_route_type {
	HLR_SMS_RT_SMSC_ADDR,
	HLR_SMS_RT_SENDER_MSISDN,
	HLR_SMS_RT_SENDER_IMSI,
};

struct hlr_sms_route {
	struct llist_head list;
	enum hlr_sms_route_type type;
	char *match_pattern;
	const struct hlr_euse *euse;
};

struct hlr_sms_route *sms_route_find(struct hlr *hlr,
				     enum hlr_sms_route_type type,
				     const char *pattern);
struct hlr_sms_route *sms_route_alloc(struct hlr *hlr,
				      enum hlr_sms_route_type type,
				      const char *pattern,
				      const struct hlr_euse *euse);
void sms_route_del(struct hlr_sms_route *rt);
