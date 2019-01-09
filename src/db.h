#pragma once

#include <stdbool.h>
#include <sqlite3.h>

struct hlr;

enum stmt_idx {
	DB_STMT_SEL_BY_IMSI,
	DB_STMT_SEL_BY_MSISDN,
	DB_STMT_SEL_BY_ID,
	DB_STMT_SEL_BY_IMEI,
	DB_STMT_UPD_VLR_BY_ID,
	DB_STMT_UPD_SGSN_BY_ID,
	DB_STMT_UPD_IMEI_BY_IMSI,
	DB_STMT_AUC_BY_IMSI,
	DB_STMT_AUC_UPD_SQN,
	DB_STMT_UPD_PURGE_CS_BY_IMSI,
	DB_STMT_UPD_PURGE_PS_BY_IMSI,
	DB_STMT_UPD_NAM_PS_BY_IMSI,
	DB_STMT_UPD_NAM_CS_BY_IMSI,
	DB_STMT_SUBSCR_CREATE,
	DB_STMT_DEL_BY_ID,
	DB_STMT_SET_MSISDN_BY_IMSI,
	DB_STMT_DELETE_MSISDN_BY_IMSI,
	DB_STMT_AUC_2G_INSERT,
	DB_STMT_AUC_2G_DELETE,
	DB_STMT_AUC_3G_INSERT,
	DB_STMT_AUC_3G_DELETE,
	DB_STMT_SET_LAST_LU_SEEN,
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
struct db_context *db_open(void *ctx, const char *fname, bool enable_sqlite3_logging, bool allow_upgrades);

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
	char		imei[GSM23003_IMEI_NUM_DIGITS+1];
	char		vlr_number[32];
	char		sgsn_number[32];
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
	time_t		last_lu_seen;
};

/* A format string for use with strptime(3). This format string is
 * used to parse the last_lu_seen column stored in the HLR database.
 * See https://sqlite.org/lang_datefunc.html, function datetime(). */
#define DB_LAST_LU_SEEN_FMT "%Y-%m-%d %H:%M:%S"

/* Like struct osmo_sub_auth_data, but the keys are in hexdump representation.
 * This is useful because SQLite requires them in hexdump format, and callers
 * like the VTY and CTRL interface also have them available as hexdump to begin
 * with. In the binary format, a VTY command would first need to hexparse,
 * after which the db function would again hexdump, copying to separate
 * buffers. The roundtrip can be saved by providing char* to begin with. */
struct sub_auth_data_str {
	enum osmo_sub_auth_type type;
	enum osmo_auth_algo algo;
	union {
		struct {
			const char *opc;
			const char *k;
			uint64_t sqn;
			int opc_is_op;
			unsigned int ind_bitlen;
		} umts;
		struct {
			const char *ki;
		} gsm;
	} u;
};

int db_subscr_create(struct db_context *dbc, const char *imsi);
int db_subscr_delete_by_id(struct db_context *dbc, int64_t subscr_id);

int db_subscr_update_msisdn_by_imsi(struct db_context *dbc, const char *imsi,
				    const char *msisdn);
int db_subscr_update_aud_by_id(struct db_context *dbc, int64_t subscr_id,
			       const struct sub_auth_data_str *aud);
int db_subscr_update_imei_by_imsi(struct db_context *dbc, const char* imsi, const char *imei);

int db_subscr_get_by_imsi(struct db_context *dbc, const char *imsi,
			  struct hlr_subscriber *subscr);
int db_subscr_get_by_msisdn(struct db_context *dbc, const char *msisdn,
			    struct hlr_subscriber *subscr);
int db_subscr_get_by_id(struct db_context *dbc, int64_t id,
			struct hlr_subscriber *subscr);
int db_subscr_get_by_imei(struct db_context *dbc, const char *imei, struct hlr_subscriber *subscr);
int db_subscr_nam(struct db_context *dbc, const char *imsi, bool nam_val, bool is_ps);
int db_subscr_lu(struct db_context *dbc, int64_t subscr_id,
		 const char *vlr_or_sgsn_number, bool is_ps);

int db_subscr_purge(struct db_context *dbc, const char *by_imsi,
		    bool purge_val, bool is_ps);

int hlr_subscr_nam(struct hlr *hlr, struct hlr_subscriber *subscr, bool nam_val, bool is_ps);

/*! Call sqlite3_column_text() and copy result to a char[].
 * \param[out] buf  A char[] used as sizeof() arg(!) and osmo_strlcpy() target.
 * \param[in] stmt  An sqlite3_stmt*.
 * \param[in] idx   Index in stmt's returned columns.
 */
#define copy_sqlite3_text_to_buf(buf, stmt, idx) \
	do { \
		const char *_txt = (const char *) sqlite3_column_text(stmt, idx); \
		osmo_strlcpy(buf, _txt, sizeof(buf)); \
	} while (0)
