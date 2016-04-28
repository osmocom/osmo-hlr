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

#include <sqlite3.h>

#include "logging.h"
#include "db.h"

static const char *stmt_sql[] = {
	[SEL_BY_IMSI] = "SELECT * FROM subscriber WHERE imsi = ?",
	[UPD_BY_IMSI] = "UPDATE subscriber SET vlr_number = ? WHERE imsi = ?",
	[AUC_BY_IMSI] = "SELECT id, algo_id_2g, ki, algo_id_3g, k, op, opc, sqn FROM subscriber LEFT JOIN auc_2g ON auc_2g.subscriber_id = subscriber.id LEFT JOIN auc_3g ON auc_3g.subscriber_id = subscriber.id WHERE imsi = ?",
	[AUC_UPD_SQN] = "UPDATE auc_3g SET sqn = ? WHERE subscriber_id = ?",
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
		LOGP(DDB, LOGL_DEBUG, stmt);
		break;
	case 2:
		LOGP(DDB, LOGL_DEBUG, "Closed database\n");
		break;
	default:
		LOGP(DDB, LOGL_DEBUG, "Unknown %d\n", type);
		break;
	}
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

	LOGP(DDB, LOGL_INFO, "Compiled against SQLite3 lib version %s\n", SQLITE_VERSION);
	LOGP(DDB, LOGL_INFO, "Running with SQLite3 lib version %s\n", sqlite3_libversion());

	dbc->fname = talloc_strdup(dbc, fname);

	for (i = 0; i < 0xfffff; i++) {
		const char *o = sqlite3_compileoption_get(i);
		if (!o)
			break;
		LOGP(DDB, LOGL_DEBUG, "SQlite3 compiled with '%s'\n", o);
	}

	rc = sqlite3_config(SQLITE_CONFIG_LOG, sql3_error_log_cb, NULL);
	if (rc != SQLITE_OK)
		LOGP(DDB, LOGL_NOTICE, "Unable to set SQlite3 error log callback\n");

	rc = sqlite3_config(SQLITE_CONFIG_SQLLOG, sql3_sql_log_cb, NULL);
	if (rc != SQLITE_OK)
		LOGP(DDB, LOGL_NOTICE, "Unable to set SQlite3 SQL statement log callback\n");

	rc = sqlite3_open(dbc->fname, &dbc->db);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to open DB; rc = %d\n", rc);
		talloc_free(dbc);
		return NULL;
	}

	/* enable extended result codes */
	rc = sqlite3_extended_result_codes(dbc->db, 1);
	if (rc != SQLITE_OK)
		LOGP(DDB, LOGL_ERROR, "Unable to enable SQlite3 extended result codes\n");

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
