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
};

extern const struct log_info hlr_log_info;
