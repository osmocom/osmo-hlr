/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/utils.h>

#include <stdbool.h>
#include <sqlite3.h>
#include <string.h>

#include "logging.h"
#include "db.h"

#define SEL_COLUMNS \
	"id," \
	"imsi," \
	"msisdn," \
	"vlr_number," \
	"sgsn_number," \
	"sgsn_address," \
	"periodic_lu_tmr," \
	"periodic_rau_tau_tmr," \
	"nam_cs," \
	"nam_ps," \
	"lmsi," \
	"ms_purged_cs," \
	"ms_purged_ps"

static const char *stmt_sql[] = {
	[DB_STMT_SEL_BY_IMSI] = "SELECT " SEL_COLUMNS " FROM subscriber WHERE imsi = ?",
	[DB_STMT_SEL_BY_MSISDN] = "SELECT " SEL_COLUMNS " FROM subscriber WHERE msisdn = ?",
	[DB_STMT_SEL_BY_ID] = "SELECT " SEL_COLUMNS " FROM subscriber WHERE id = ?",
	[DB_STMT_UPD_VLR_BY_ID] = "UPDATE subscriber SET vlr_number = ? WHERE id = ?",
	[DB_STMT_UPD_SGSN_BY_ID] = "UPDATE subscriber SET sgsn_number = ? WHERE id = ?",
	[DB_STMT_AUC_BY_IMSI] =
		"SELECT id, algo_id_2g, ki, algo_id_3g, k, op, opc, sqn, ind_bitlen"
		" FROM subscriber"
		" LEFT JOIN auc_2g ON auc_2g.subscriber_id = subscriber.id"
		" LEFT JOIN auc_3g ON auc_3g.subscriber_id = subscriber.id"
		" WHERE imsi = ?",
	[DB_STMT_AUC_UPD_SQN] = "UPDATE auc_3g SET sqn = ? WHERE subscriber_id = ?",
	[DB_STMT_UPD_PURGE_CS_BY_IMSI] = "UPDATE subscriber SET ms_purged_cs=1 WHERE imsi = ?",
	[DB_STMT_UPD_PURGE_PS_BY_IMSI] = "UPDATE subscriber SET ms_purged_ps=1 WHERE imsi = ?",
	[DB_STMT_SET_NAM_PS_BY_IMSI] = "UPDATE subscriber SET nam_ps=1 WHERE imsi = ?",
	[DB_STMT_UNSET_NAM_PS_BY_IMSI] = "UPDATE subscriber SET nam_ps=0 WHERE imsi = ?",
	[DB_STMT_SUBSCR_CREATE] = "INSERT INTO subscriber (imsi) VALUES ($imsi)",
	[DB_STMT_DEL_BY_ID] = "DELETE FROM subscriber WHERE id = $subscriber_id",
	[DB_STMT_SET_MSISDN_BY_IMSI] = "UPDATE subscriber SET msisdn = $msisdn WHERE imsi = $imsi",
};

static void sql3_error_log_cb(void *arg, int err_code, const char *msg)
{
	LOGP(DDB, LOGL_ERROR, "(%d) %s\n", err_code, msg);
}

static void sql3_sql_log_cb(void *arg, sqlite3 *s3, const char *stmt, int type)
{
	switch (type) {
	case 0:
		LOGP(DDB, LOGL_DEBUG, "Opened database\n");
		break;
	case 1:
		LOGP(DDB, LOGL_DEBUG, "%s\n", stmt);
		break;
	case 2:
		LOGP(DDB, LOGL_DEBUG, "Closed database\n");
		break;
	default:
		LOGP(DDB, LOGL_DEBUG, "Unknown %d\n", type);
		break;
	}
}

/* remove bindings and reset statement to be re-executed */
void db_remove_reset(sqlite3_stmt *stmt)
{
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
}

/** bind text arg and do proper cleanup in case of failure. If param_name is
 * NULL, bind to the first parameter (useful for SQL statements that have only
 * one parameter). */
bool db_bind_text(sqlite3_stmt *stmt, const char *param_name, const char *text)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_text(stmt, idx, text, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding text to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

/** bind int arg and do proper cleanup in case of failure. If param_name is
 * NULL, bind to the first parameter (useful for SQL statements that have only
 * one parameter). */
bool db_bind_int(sqlite3_stmt *stmt, const char *param_name, int nr)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_int(stmt, idx, nr);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding int64 to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

/** bind int64 arg and do proper cleanup in case of failure. If param_name is
 * NULL, bind to the first parameter (useful for SQL statements that have only
 * one parameter). */
bool db_bind_int64(sqlite3_stmt *stmt, const char *param_name, int64_t nr)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_int64(stmt, idx, nr);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding int64 to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

void db_close(struct db_context *dbc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(dbc->stmt); i++) {
		/* it is ok to call finalize on NULL */
		sqlite3_finalize(dbc->stmt[i]);
	}
	sqlite3_close(dbc->db);
	talloc_free(dbc);
}

struct db_context *db_open(void *ctx, const char *fname)
{
	struct db_context *dbc = talloc_zero(ctx, struct db_context);
	unsigned int i;
	int rc;
	bool has_sqlite_config_sqllog = false;

	LOGP(DDB, LOGL_NOTICE, "using database: %s\n", fname);
	LOGP(DDB, LOGL_INFO, "Compiled against SQLite3 lib version %s\n", SQLITE_VERSION);
	LOGP(DDB, LOGL_INFO, "Running with SQLite3 lib version %s\n", sqlite3_libversion());

	dbc->fname = talloc_strdup(dbc, fname);

	for (i = 0; i < 0xfffff; i++) {
		const char *o = sqlite3_compileoption_get(i);
		if (!o)
			break;
		LOGP(DDB, LOGL_DEBUG, "SQLite3 compiled with '%s'\n", o);
		if (!strcmp(o, "ENABLE_SQLLOG"))
			has_sqlite_config_sqllog = true;
	}

	rc = sqlite3_config(SQLITE_CONFIG_LOG, sql3_error_log_cb, NULL);
	if (rc != SQLITE_OK)
		LOGP(DDB, LOGL_NOTICE, "Unable to set SQLite3 error log callback\n");

	if (has_sqlite_config_sqllog) {
		rc = sqlite3_config(SQLITE_CONFIG_SQLLOG, sql3_sql_log_cb, NULL);
		if (rc != SQLITE_OK)
			LOGP(DDB, LOGL_NOTICE, "Unable to set SQLite3 SQL log callback\n");
	} else
			LOGP(DDB, LOGL_DEBUG, "Not setting SQL log callback:"
			     " SQLite3 compiled without support for it\n");

	rc = sqlite3_open(dbc->fname, &dbc->db);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to open DB; rc = %d\n", rc);
		talloc_free(dbc);
		return NULL;
	}

	/* enable extended result codes */
	rc = sqlite3_extended_result_codes(dbc->db, 1);
	if (rc != SQLITE_OK)
		LOGP(DDB, LOGL_ERROR, "Unable to enable SQLite3 extended result codes\n");

	char *err_msg;
	rc = sqlite3_exec(dbc->db, "PRAGMA journal_mode=WAL; PRAGMA synchonous = NORMAL;", 0, 0, &err_msg);
	if (rc != SQLITE_OK)
		LOGP(DDB, LOGL_ERROR, "Unable to set Write-Ahead Logging: %s\n",
			err_msg);

	/* prepare all SQL statements */
	for (i = 0; i < ARRAY_SIZE(dbc->stmt); i++) {
		rc = sqlite3_prepare_v2(dbc->db, stmt_sql[i], -1,
					&dbc->stmt[i], NULL);
		if (rc != SQLITE_OK) {
			LOGP(DDB, LOGL_ERROR, "Unable to prepare SQL statement '%s'\n", stmt_sql[i]);
			goto out_free;
		}
	}

	return dbc;
out_free:
	db_close(dbc);
	return NULL;
}
