#pragma once
#include <stdbool.h>

#include <osmocom/gsupclient/gsup_req.h>

#define OSMO_MSLOOKUP_SERVICE_SMS_GSUP "gsup.sms"

bool sms_over_gsup_check_handle_msg(struct osmo_gsup_req *req);
