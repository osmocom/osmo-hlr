#include <osmocom/core/utils.h>
#include <osmocom/hlr/logging.h>

const struct log_info_cat hlr_log_info_cat[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.description = "Main Program",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DDB] = {
		.name = "DDB",
		.description = "Database Layer",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DAUC] = {
		.name = "DAUC",
		.description = "Authentication Center",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSS] = {
		.name = "DSS",
		.description = "Supplementary Services",
		.color = "\033[1;34m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DLU] = {
		.name = "DLU",
		.description = "Location Updating",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},

};

const struct log_info hlr_log_info = {
	.cat = hlr_log_info_cat,
	.num_cat = ARRAY_SIZE(hlr_log_info_cat),
};
