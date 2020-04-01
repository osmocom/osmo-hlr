#pragma once

#include <stdint.h>
#include <inttypes.h>
#include <osmocom/hlr/db.h>

#define LOGPSEUDO(id, level, fmt, args ...) LOGP(DPSEUDO, level, "subscriber_id='%" PRId64 "': " fmt, id, ## args)

struct imsi_pseudo_data {
	int alloc_count; /* 0: none, 1: only current is allocated, 2: current and previous are allocated */
	int64_t i; /* current imsi_pseudo_i */
	char current[GSM23003_IMSI_MAX_DIGITS+1];
	char previous[GSM23003_IMSI_MAX_DIGITS+1];
};

int db_get_imsi_pseudo_data(struct db_context *dbc, int64_t subscr_id, struct imsi_pseudo_data *data);
int db_alloc_imsi_pseudo(struct db_context *dbc, int64_t subscr_id, const char *imsi_pseudo, int64_t imsi_pseudo_i);
int db_dealloc_imsi_pseudo(struct db_context *dbc, const char *imsi_pseudo);
int db_get_imsi_pseudo_next(struct db_context *dbc, char *imsi_pseudo);
