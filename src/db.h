#pragma once

#include <stdbool.h>
#include <sqlite3.h>

enum stmt_idx {
	DB_STMT_SEL_BY_IMSI,
	DB_STMT_SEL_BY_MSISDN,
	DB_STMT_SEL_BY_ID,
	DB_STMT_UPD_VLR_BY_ID,
	DB_STMT_UPD_SGSN_BY_ID,
	DB_STMT_AUC_BY_IMSI,
	DB_STMT_AUC_UPD_SQN,
	DB_STMT_UPD_PURGE_CS_BY_IMSI,
	DB_STMT_UPD_PURGE_PS_BY_IMSI,
	DB_STMT_UPD_NAM_PS_BY_IMSI,
	DB_STMT_UPD_NAM_CS_BY_IMSI,
	DB_STMT_SUBSCR_CREATE,
	DB_STMT_DEL_BY_ID,
	DB_STMT_SET_MSISDN_BY_IMSI,
	_NUM_DB_STMT
};

struct db_context {
	char *fname;
	sqlite3 *db;
	sqlite3_stmt *stmt[_NUM_DB_STMT];
};

void db_remove_reset(sqlite3_stmt *stmt);
bool db_bind_text(sqlite3_stmt *stmt, const char *param_name, const char *text);
bool db_bind_int(sqlite3_stmt *stmt, const char *param_name, int nr);
bool db_bind_int64(sqlite3_stmt *stmt, const char *param_name, int64_t nr);
void db_close(struct db_context *dbc);
struct db_context *db_open(void *ctx, const char *fname);

#include <osmocom/crypt/auth.h>

/* obtain the authentication data for a given imsi */
int db_get_auth_data(struct db_context *dbc, const char *imsi,
		     struct osmo_sub_auth_data *aud2g,
		     struct osmo_sub_auth_data *aud3g,
		     int64_t *subscr_id);

int db_update_sqn(struct db_context *dbc, int64_t id,
		      uint64_t new_sqn);

int db_get_auc(struct db_context *dbc, const char *imsi,
	       unsigned int auc_3g_ind, struct osmo_auth_vector *vec,
	       unsigned int num_vec, const uint8_t *rand_auts,
	       const uint8_t *auts);

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

/* TODO: Get this from somewhere? */
#define GT_MAX_DIGITS	15

struct hlr_subscriber {
	struct llist_head list;

	int64_t		id;
	char		imsi[GSM23003_IMSI_MAX_DIGITS+1];
	char		msisdn[GT_MAX_DIGITS+1];
	/* imeisv? */
	char		vlr_number[GT_MAX_DIGITS+1];
	char		sgsn_number[GT_MAX_DIGITS+1];
	char		sgsn_address[GT_MAX_DIGITS+1];
	/* ggsn number + address */
	/* gmlc number */
	/* smsc number */
	uint32_t	periodic_lu_timer;
	uint32_t	periodic_rau_tau_timer;
	bool		nam_cs;
	bool		nam_ps;
	uint32_t	lmsi;
	bool		ms_purged_cs;
	bool		ms_purged_ps;
};

int db_subscr_create(struct db_context *dbc, const char *imsi);
int db_subscr_delete_by_id(struct db_context *dbc, int64_t subscr_id);

int db_subscr_update_msisdn_by_imsi(struct db_context *dbc, const char *imsi,
				    const char *msisdn);

int db_subscr_get_by_imsi(struct db_context *dbc, const char *imsi,
			  struct hlr_subscriber *subscr);
int db_subscr_get_by_msisdn(struct db_context *dbc, const char *msisdn,
			    struct hlr_subscriber *subscr);
int db_subscr_get_by_id(struct db_context *dbc, int64_t id,
			struct hlr_subscriber *subscr);
int db_subscr_nam(struct db_context *dbc, const char *imsi, bool nam_val, bool is_ps);
int db_subscr_lu(struct db_context *dbc, int64_t subscr_id,
		 const char *vlr_or_sgsn_number, bool is_ps);

int db_subscr_purge(struct db_context *dbc, const char *by_imsi,
		    bool purge_val, bool is_ps);
