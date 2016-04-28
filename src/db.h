#pragma once

#include <sqlite3.h>

enum stmt_idx {
	SEL_BY_IMSI	= 0,
	UPD_BY_IMSI	= 1,
	AUC_BY_IMSI	= 2,
	AUC_UPD_SQN	= 3,
	_NUM_STMT
};

struct db_context {
	char *fname;
	sqlite3 *db;
	sqlite3_stmt *stmt[_NUM_STMT];
};

void db_close(struct db_context *dbc);
struct db_context *db_open(void *ctx, const char *fname);

#include <osmocom/crypt/auth.h>

/* obtain the authentication data for a given imsi */
int db_get_auth_data(struct db_context *dbc, const char *imsi,
		     struct osmo_sub_auth_data *aud2g,
		     struct osmo_sub_auth_data *aud3g,
		     uint64_t *suscr_id);

int db_update_sqn(struct db_context *dbc, uint64_t id,
		      uint64_t new_sqn);

int db_get_auc(struct db_context *dbc, const char *imsi,
	    struct osmo_auth_vector *vec, unsigned int num_vec,
	    const uint8_t *rand_auts, const uint8_t *auts);
