#pragma once

#include <osmocom/core/logging.h>

enum {
	DMAIN,
	DDB,
	DGSUP,
	DAUC,
	DSS,
	DMSLOOKUP,
	DLU,
	DDGSM,
	DCTRL,
};

extern const struct log_info hlr_log_info;
