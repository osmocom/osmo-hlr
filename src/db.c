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
#include <errno.h>

#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/db.h>

#include "db_bootstrap.h"

/* This constant is currently duplicated in sql/hlr.sql and must be kept in sync! */
#define CURRENT_SCHEMA_VERSION	6

#define SEL_COLUMNS \
	"id," \
	"imsi," \
	"msisdn," \
	"imei," \
	"vlr_number," \
	"sgsn_number," \
	"sgsn_address," \
	"periodic_lu_tmr," \
	"periodic_rau_tau_tmr," \
	"nam_cs," \
	"nam_ps," \
	"lmsi," \
	"ms_purged_cs," \
	"ms_purged_ps," \
	"last_lu_seen," \
	"last_lu_seen_ps," \
	"vlr_via_proxy," \
	"sgsn_via_proxy"

static const char *stmt_sql[] = {
	[DB_STMT_SEL_BY_IMSI] = "SELECT " SEL_COLUMNS " FROM subscriber WHERE imsi = ?",
	[DB_STMT_SEL_BY_MSISDN] = "SELECT " SEL_COLUMNS " FROM subscriber WHERE msisdn = ?",
	[DB_STMT_SEL_BY_ID] = "SELECT " SEL_COLUMNS " FROM subscriber WHERE id = ?",
	[DB_STMT_SEL_BY_IMEI] = "SELECT " SEL_COLUMNS " FROM subscriber WHERE imei = ?",
	[DB_STMT_UPD_VLR_BY_ID] = "UPDATE subscriber SET vlr_number = $number, vlr_via_proxy = $proxy WHERE id = $subscriber_id",
	[DB_STMT_UPD_SGSN_BY_ID] = "UPDATE subscriber SET sgsn_number = $number, sgsn_via_proxy = $proxy WHERE id = $subscriber_id",
	[DB_STMT_UPD_IMEI_BY_IMSI] = "UPDATE subscriber SET imei = $imei WHERE imsi = $imsi",
	[DB_STMT_AUC_BY_IMSI] =
		"SELECT id, algo_id_2g, ki, algo_id_3g, k, op, opc, sqn, ind_bitlen"
		" FROM subscriber"
		" LEFT JOIN auc_2g ON auc_2g.subscriber_id = subscriber.id"
		" LEFT JOIN auc_3g ON auc_3g.subscriber_id = subscriber.id"
		" WHERE imsi = $imsi",
	[DB_STMT_AUC_UPD_SQN] = "UPDATE auc_3g SET sqn = $sqn WHERE subscriber_id = $subscriber_id",
	[DB_STMT_UPD_PURGE_CS_BY_IMSI] = "UPDATE subscriber SET ms_purged_cs = $val WHERE imsi = $imsi",
	[DB_STMT_UPD_PURGE_PS_BY_IMSI] = "UPDATE subscriber SET ms_purged_ps = $val WHERE imsi = $imsi",
	[DB_STMT_UPD_NAM_CS_BY_IMSI] = "UPDATE subscriber SET nam_cs = $val WHERE imsi = $imsi",
	[DB_STMT_UPD_NAM_PS_BY_IMSI] = "UPDATE subscriber SET nam_ps = $val WHERE imsi = $imsi",
	[DB_STMT_SUBSCR_CREATE] = "INSERT INTO subscriber (imsi, nam_cs, nam_ps) VALUES ($imsi, $nam_cs, $nam_ps)",
	[DB_STMT_DEL_BY_ID] = "DELETE FROM subscriber WHERE id = $subscriber_id",
	[DB_STMT_SET_MSISDN_BY_IMSI] = "UPDATE subscriber SET msisdn = $msisdn WHERE imsi = $imsi",
	[DB_STMT_DELETE_MSISDN_BY_IMSI] = "UPDATE subscriber SET msisdn = NULL WHERE imsi = $imsi",
	[DB_STMT_AUC_2G_INSERT] =
		"INSERT INTO auc_2g (subscriber_id, algo_id_2g, ki)"
		" VALUES($subscriber_id, $algo_id_2g, $ki)",
	[DB_STMT_AUC_2G_DELETE] = "DELETE FROM auc_2g WHERE subscriber_id = $subscriber_id",
	[DB_STMT_AUC_3G_INSERT] =
		"INSERT INTO auc_3g (subscriber_id, algo_id_3g, k, op, opc, ind_bitlen)"
		" VALUES($subscriber_id, $algo_id_3g, $k, $op, $opc, $ind_bitlen)",
	[DB_STMT_AUC_3G_DELETE] = "DELETE FROM auc_3g WHERE subscriber_id = $subscriber_id",
	[DB_STMT_SET_LAST_LU_SEEN] = "UPDATE subscriber SET last_lu_seen = datetime($val, 'unixepoch') WHERE id = $subscriber_id",
	[DB_STMT_SET_LAST_LU_SEEN_PS] = "UPDATE subscriber SET last_lu_seen_ps = datetime($val, 'unixepoch') WHERE id = $subscriber_id",
	[DB_STMT_EXISTS_BY_IMSI] = "SELECT 1 FROM subscriber WHERE imsi = $imsi",
	[DB_STMT_EXISTS_BY_MSISDN] = "SELECT 1 FROM subscriber WHERE msisdn = $msisdn",
	[DB_STMT_IND_SELECT] = "SELECT ind FROM ind WHERE cn_domain = $cn_domain AND vlr = $vlr",
	[DB_STMT_IND_DEL] = "DELETE FROM ind WHERE cn_domain = $cn_domain AND vlr = $vlr",
	[DB_STMT_IND_ADD] =
		/* This SQL statement is quite the works, so let me elaborate.
		 * This is about auc_3g IND pool choice for a given attached VLR (MSC or SGSN).
		 * - We want to insert an unused IND into the table, where a CS IND should be odd-numbered and a PS IND
		 *   should be even (see OS#4319). In short, an IND collision between MSC and SGSN of the same site is a
		 *   grave sink of SQN numbers and HLR CPU cycles, so it is worth it to avoid that with 100% certainty.
		 * - We want to start from zero/one (for PS/CS) and,
		 * - When there is a gap due to deletion, we always want to first fill up the gaps before picking unused
		 *   INDs from the end of the range.
		 * - We also want to treat $cn_domain as an integer, to be ready for future added cn_domain enum values.
		 *   That implies having one single table for all cn_domains,
		 * - The other benefit of having a single table for both cn_domains is that we can beyond all doubt
		 *   prevent any IND assigned twice.
		 * - If too many sites show up for the IND_bitlen of a subscriber, the auc_3g code actually takes the
		 *   modulo to fit in the IND_bitlen space, so here all we do is grow IND values into "all infinity",
		 *   causing effective round-robin of any arbitrary IND_bitlen space. That is why we fill gaps first.
		 *
		 * $cn_domain is: PS=1 CS=2, so $cn_domain - 1 gives PS=0 CS=1
		 * Given any arbitrary nr, this always hits the right even/odd per CN domain:
		 *    nr - (nr % 2) + ($cn_domain-1)
		 * However, CN domains are always spaced two apart, so we often want (nr + 2).
		 * With above always-hit-the-right-bucket, that gives
		 *    (nr+2) - ((nr+2) % 2) + ($cn_domain-1)
		 * This modulo dance is aggressively applied to gracefully recover even when a user has manually
		 * modified the IND table to actually pair an even/odd IND to the wrong cn_domain.
		 *
		 * The deeper SELECT between THEN and ELSE picks the lowest unused IND for a given $cn_domain.
		 * However, that only works when there already is any one entry in the table.
		 * That's why we need the entire CASE WHEN .. THEN .. ELSE .. END stuff.
		 *
		 * That CASE's ELSE..END part returns the absolute first value for a $cn_domain for an empty table.
		 *
		 * The outermost SELECT puts the values ($cn_domain, $ind, $vlr) together.
		 *
		 * So, again, this time from outside to inside:
		 *   INSERT...
		 *   SELECT ($cn_domain, <IND>, $vlr)
		 *
		 * where <IND> is done like:
		 *   CASE WHEN <table-already-has-such-$cn_domain>
		 *   THEN
		 *       <FIND-UNUSED-IND>
		 *   ELSE
		 *       <use-first-ind-for-this-$cn_domain>
		 *
		 * where in turn <FIND-UNUSED-IND> is [CC-BY-SA-4.0]
		 *   kindly taken from the answer of https://stackoverflow.com/users/55159/quassnoi (MySQL section)
		 *   to the question https://stackoverflow.com/questions/1312101/how-do-i-find-a-gap-in-running-counter-with-sql
		 *   and modified to use the even/odd skipping according to $cn_domain instead of simple increment.
		 * <FIND-UNUSED-IND> works such that it selects an IND number for which IND + 2 yields no entry,
		 * modification here: the entry must also match the given $cn_domain.
		 *
		 * The C invoking this still first tries to just find an entry for a given $vlr, so when this statement
		 * is invoked, we actually definitely want to insert an entry and expect no constraint conflicts.
		 *
		 * Parameters are $cn_domain (integer) and $vlr (text). The $cn_domain should be either 1 (PS)
		 * or 2 (CS), any other value should default to 1 (because according to GSUP specs PS is the default).
		 */
		"INSERT INTO ind (cn_domain, ind, vlr)"
		"SELECT  $cn_domain,"
		"	CASE WHEN EXISTS(SELECT NULL FROM ind WHERE cn_domain = $cn_domain LIMIT 1)"
		"	THEN"
		"		("
		"		SELECT ((ind + 2) - ((ind + 2)%2) + ($cn_domain-1))"
		"		FROM ind as mo"
		"		WHERE NOT EXISTS ("
		"			SELECT NULL"
		"			FROM ind as mi"
		"			WHERE cn_domain = $cn_domain"
		"			AND mi.ind = ((mo.ind + 2) - ((mo.ind + 2)%2) + $cn_domain-1)"
		"			)"
		"		ORDER BY ind"
		"		LIMIT 1"
		"		)"
		"	ELSE ($cn_domain-1)"
		"	END ind"
		"	, $vlr"
		,
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
	/* sqlite3_reset() just repeats an error code already evaluated during sqlite3_step(). */
	/* coverity[CHECKED_RETURN] */
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

bool db_bind_null(sqlite3_stmt *stmt, const char *param_name)
{
	int rc;
	int idx = param_name ? sqlite3_bind_parameter_index(stmt, param_name) : 1;
	if (idx < 1) {
		LOGP(DDB, LOGL_ERROR, "Error composing SQL, cannot bind parameter '%s'\n",
		     param_name);
		return false;
	}
	rc = sqlite3_bind_null(stmt, idx);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Error binding NULL to SQL parameter %s: %d\n",
		     param_name ? param_name : "#1", rc);
		db_remove_reset(stmt);
		return false;
	}
	return true;
}

void db_close(struct db_context *dbc)
{
	unsigned int i;
	int rc;

	for (i = 0; i < ARRAY_SIZE(dbc->stmt); i++) {
		/* it is ok to call finalize on NULL */
		sqlite3_finalize(dbc->stmt[i]);
	}

	/* Ask sqlite3 to close DB */
	rc = sqlite3_close(dbc->db);
	if (rc != SQLITE_OK) { /* Make sure it's actually closed! */
		LOGP(DDB, LOGL_ERROR, "Couldn't close database: (rc=%d) %s\n",
			rc, sqlite3_errmsg(dbc->db));
	}

	talloc_free(dbc);
}

static int db_run_statements(struct db_context *dbc, const char **statements, size_t statements_count)
{
	int rc;
	int i;
	for (i = 0; i < statements_count; i++) {
		const char *stmt_str = statements[i];
		sqlite3_stmt *stmt;

		rc = sqlite3_prepare_v2(dbc->db, stmt_str, -1, &stmt, NULL);
		if (rc != SQLITE_OK) {
			LOGP(DDB, LOGL_ERROR, "Unable to prepare SQL statement '%s'\n", stmt_str);
			return rc;
		}
		rc = sqlite3_step(stmt);
		db_remove_reset(stmt);
		sqlite3_finalize(stmt);
		if (rc != SQLITE_DONE) {
			LOGP(DDB, LOGL_ERROR, "SQL error: (%d) %s, during stmt '%s'",
			     rc, sqlite3_errmsg(dbc->db), stmt_str);
			return rc;
		}
	}
	return rc;
}

static int db_bootstrap(struct db_context *dbc)
{
	int rc = db_run_statements(dbc, stmt_bootstrap_sql, ARRAY_SIZE(stmt_bootstrap_sql));
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Cannot bootstrap database\n");
		return rc;
	}
	return SQLITE_OK;
}

/* https://www.sqlite.org/fileformat2.html#storage_of_the_sql_database_schema */
static bool db_table_exists(struct db_context *dbc, const char *table_name)
{
	const char *table_exists_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
	sqlite3_stmt *stmt;
	int rc;

	rc = sqlite3_prepare_v2(dbc->db, table_exists_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to prepare SQL statement '%s'\n", table_exists_sql);
		return false;
	}

	if (!db_bind_text(stmt, NULL, table_name))
		return false;

	rc = sqlite3_step(stmt);
	db_remove_reset(stmt);
	sqlite3_finalize(stmt);
	return (rc == SQLITE_ROW);
}

/* Indicate whether the database is initialized with tables for schema version 0.
 * We only check for the 'subscriber' table here because Neels said so. */
static bool db_is_bootstrapped_v0(struct db_context *dbc)
{
	if (!db_table_exists(dbc, "subscriber")) {
		LOGP(DDB, LOGL_DEBUG, "Table 'subscriber' not found in database '%s'\n", dbc->fname);
		return false;
	}

	return true;
}

static int
db_upgrade_v1(struct db_context *dbc)
{
	int rc;
	const char *statements[] = {
		"ALTER TABLE subscriber ADD COLUMN last_lu_seen TIMESTAMP default NULL",
		"PRAGMA user_version = 1",
	};

	rc = db_run_statements(dbc, statements, ARRAY_SIZE(statements));
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Unable to update HLR database schema to version 1\n");
		return rc;
	}
	return rc;
}

static int db_upgrade_v2(struct db_context *dbc)
{
	int rc;
	const char *statements[] = {
		"ALTER TABLE subscriber ADD COLUMN imei VARCHAR(14)",
		"PRAGMA user_version = 2",
	};

	rc = db_run_statements(dbc, statements, ARRAY_SIZE(statements));
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Unable to update HLR database schema to version 2\n");
		return rc;
	}
	return rc;
}

static int db_upgrade_v3(struct db_context *dbc)
{
	int rc;

	/* A newer SQLite version would allow simply 'ATLER TABLE subscriber RENAME COLUMN hlr_number TO msc_number'.
	 * This is a really expensive workaround for that in order to cover earlier SQLite versions as well:
	 * Create a new table with the new column name and copy the data over (https://www.sqlite.org/faq.html#q11).
	 */
#define SUBSCR_V3_CREATE  \
"(\n" \
"-- OsmoHLR's DB scheme is modelled roughly after TS 23.008 version 13.3.0\n" \
"	id		INTEGER PRIMARY KEY,\n" \
"	-- Chapter 2.1.1.1\n" \
"	imsi		VARCHAR(15) UNIQUE NOT NULL,\n" \
"	-- Chapter 2.1.2\n" \
"	msisdn		VARCHAR(15) UNIQUE,\n" \
"	-- Chapter 2.2.3: Most recent / current IMEISV\n" \
"	imeisv		VARCHAR,\n" \
"	-- Chapter 2.1.9: Most recent / current IMEI\n" \
"	imei		VARCHAR(14),\n" \
"	-- Chapter 2.4.5\n" \
"	vlr_number	VARCHAR(15),\n" \
"	-- Chapter 2.4.6\n" \
"	msc_number	VARCHAR(15),\n" \
"	-- Chapter 2.4.8.1\n" \
"	sgsn_number	VARCHAR(15),\n" \
"	-- Chapter 2.13.10\n" \
"	sgsn_address	VARCHAR,\n" \
"	-- Chapter 2.4.8.2\n" \
"	ggsn_number	VARCHAR(15),\n" \
"	-- Chapter 2.4.9.2\n" \
"	gmlc_number	VARCHAR(15),\n" \
"	-- Chapter 2.4.23\n" \
"	smsc_number	VARCHAR(15),\n" \
"	-- Chapter 2.4.24\n" \
"	periodic_lu_tmr	INTEGER,\n" \
"	-- Chapter 2.13.115\n" \
"	periodic_rau_tau_tmr INTEGER,\n" \
"	-- Chapter 2.1.1.2: network access mode\n" \
"	nam_cs		BOOLEAN NOT NULL DEFAULT 1,\n" \
"	nam_ps		BOOLEAN NOT NULL DEFAULT 1,\n" \
"	-- Chapter 2.1.8\n" \
"	lmsi		INTEGER,\n" \
 \
"	-- The below purged flags might not even be stored non-volatile,\n" \
"	-- refer to TS 23.012 Chapter 3.6.1.4\n" \
"	-- Chapter 2.7.5\n" \
"	ms_purged_cs	BOOLEAN NOT NULL DEFAULT 0,\n" \
"	-- Chapter 2.7.6\n" \
"	ms_purged_ps	BOOLEAN NOT NULL DEFAULT 0,\n" \
 \
"	-- Timestamp of last location update seen from subscriber\n" \
"	-- The value is a string which encodes a UTC timestamp in granularity of seconds.\n" \
"	last_lu_seen TIMESTAMP default NULL\n" \
")\n"

#define SUBSCR_V2_COLUMN_NAMES \
	"id," \
	"imsi," \
	"msisdn," \
	"imeisv," \
	"imei," \
	"vlr_number," \
	"hlr_number," \
	"sgsn_number," \
	"sgsn_address," \
	"ggsn_number," \
	"gmlc_number," \
	"smsc_number," \
	"periodic_lu_tmr," \
	"periodic_rau_tau_tmr," \
	"nam_cs," \
	"nam_ps," \
	"lmsi," \
	"ms_purged_cs," \
	"ms_purged_ps," \
	"last_lu_seen"

#define SUBSCR_V3_COLUMN_NAMES \
	"id," \
	"imsi," \
	"msisdn," \
	"imeisv," \
	"imei," \
	"vlr_number," \
	"msc_number," \
	"sgsn_number," \
	"sgsn_address," \
	"ggsn_number," \
	"gmlc_number," \
	"smsc_number," \
	"periodic_lu_tmr," \
	"periodic_rau_tau_tmr," \
	"nam_cs," \
	"nam_ps," \
	"lmsi," \
	"ms_purged_cs," \
	"ms_purged_ps," \
	"last_lu_seen"

	const char *statements[] = {
		"BEGIN TRANSACTION",
		"CREATE TEMPORARY TABLE subscriber_backup" SUBSCR_V3_CREATE,
		"INSERT INTO subscriber_backup SELECT " SUBSCR_V2_COLUMN_NAMES " FROM subscriber",
		"DROP TABLE subscriber",
		"CREATE TABLE subscriber" SUBSCR_V3_CREATE,
		"INSERT INTO subscriber SELECT " SUBSCR_V3_COLUMN_NAMES " FROM subscriber_backup",
		"DROP TABLE subscriber_backup",
		"COMMIT",
		"PRAGMA user_version = 3",
	};

	rc = db_run_statements(dbc, statements, ARRAY_SIZE(statements));
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Unable to update HLR database schema to version 3\n");
		return rc;
	}
	return rc;
}

static int db_upgrade_v4(struct db_context *dbc)
{
	int rc;
	const char *statements[] = {
		"ALTER TABLE subscriber ADD COLUMN last_lu_seen_ps TIMESTAMP default NULL",
		"PRAGMA user_version = 4",
	};

	rc = db_run_statements(dbc, statements, ARRAY_SIZE(statements));
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Unable to update HLR database schema to version 4\n");
		return rc;
	}
	return rc;
}

static int db_upgrade_v5(struct db_context *dbc)
{
	int rc;
	const char *statements[] = {
		"ALTER TABLE subscriber ADD COLUMN vlr_via_proxy VARCHAR",
		"ALTER TABLE subscriber ADD COLUMN sgsn_via_proxy VARCHAR",
		"PRAGMA user_version = 5",
	};

	rc = db_run_statements(dbc, statements, ARRAY_SIZE(statements));
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Unable to update HLR database schema to version 5\n");
		return rc;
	}
	return rc;
}

static int db_upgrade_v6(struct db_context *dbc)
{
	int rc;
	const char *statements[] = {
		"CREATE TABLE ind (\n"
		"	cn_domain INTEGER NOT NULL,\n"
		"	-- 3G auth IND bucket to be used for this VLR, where IND = (idx << 1) + cn_domain -1\n"
		"	ind     INTEGER PRIMARY KEY,\n"
		"	-- VLR identification, usually the GSUP source_name\n"
		"	vlr     TEXT NOT NULL,\n"
		"	UNIQUE (cn_domain, vlr)\n"
		")"
		,
		"PRAGMA user_version = 6",
	};

	rc = db_run_statements(dbc, statements, ARRAY_SIZE(statements));
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Unable to update HLR database schema to version 6\n");
		return rc;
	}
	return rc;
}

typedef int (*db_upgrade_func_t)(struct db_context *dbc);
static db_upgrade_func_t db_upgrade_path[] = {
	db_upgrade_v1,
	db_upgrade_v2,
	db_upgrade_v3,
	db_upgrade_v4,
	db_upgrade_v5,
	db_upgrade_v6,
};

static int db_get_user_version(struct db_context *dbc)
{
	const char *user_version_sql = "PRAGMA user_version";
	sqlite3_stmt *stmt;
	int version, rc;

	rc = sqlite3_prepare_v2(dbc->db, user_version_sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to prepare SQL statement '%s'\n", user_version_sql);
		return -1;
	}
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		version = sqlite3_column_int(stmt, 0);
	} else {
		LOGP(DDB, LOGL_ERROR, "SQL statement '%s' failed: %d\n", user_version_sql, rc);
		version = -1;
	}

	db_remove_reset(stmt);
	sqlite3_finalize(stmt);
	return version;
}

struct db_context *db_open(void *ctx, const char *fname, bool enable_sqlite_logging, bool allow_upgrade)
{
	struct db_context *dbc = talloc_zero(ctx, struct db_context);
	unsigned int i;
	int rc;
	bool has_sqlite_config_sqllog = false;
	int version;

	LOGP(DDB, LOGL_NOTICE, "using database: %s\n", fname);
	LOGP(DDB, LOGL_INFO, "Compiled against SQLite3 lib version %s\n", SQLITE_VERSION);
	LOGP(DDB, LOGL_INFO, "Running with SQLite3 lib version %s\n", sqlite3_libversion());

#ifdef SQLITE_USE_TALLOC
	/* Configure SQLite3 to use talloc memory allocator */
	rc = db_sqlite3_use_talloc(ctx);
	if (rc == SQLITE_OK) {
		LOGP(DDB, LOGL_NOTICE, "SQLite3 is configured to use talloc\n");
	} else {
		LOGP(DDB, LOGL_ERROR, "Failed to configure SQLite3 "
		     "to use talloc, using default memory allocator\n");
	}
#endif

	dbc->fname = talloc_strdup(dbc, fname);

	for (i = 0; i < 0xfffff; i++) {
		const char *o = sqlite3_compileoption_get(i);
		if (!o)
			break;
		LOGP(DDB, LOGL_DEBUG, "SQLite3 compiled with '%s'\n", o);
		if (!strcmp(o, "ENABLE_SQLLOG"))
			has_sqlite_config_sqllog = true;
	}

	if (enable_sqlite_logging) {
		rc = sqlite3_config(SQLITE_CONFIG_LOG, sql3_error_log_cb, NULL);
		if (rc != SQLITE_OK)
			LOGP(DDB, LOGL_NOTICE, "Unable to set SQLite3 error log callback\n");
	}

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

	version = db_get_user_version(dbc);
	if (version < 0) {
		LOGP(DDB, LOGL_ERROR, "Unable to read user version number from database '%s'\n", dbc->fname);
		goto out_free;
	}

	/* An empty database will always report version zero. */
	if (version == 0 && !db_is_bootstrapped_v0(dbc)) {
		LOGP(DDB, LOGL_NOTICE, "Missing database tables detected; Bootstrapping database '%s'\n", dbc->fname);
		rc = db_bootstrap(dbc);
		if (rc != SQLITE_OK) {
			LOGP(DDB, LOGL_ERROR, "Failed to bootstrap DB: (rc=%d) %s\n",
			     rc, sqlite3_errmsg(dbc->db));
			goto out_free;
		}
		version = CURRENT_SCHEMA_VERSION;
	}

	LOGP(DDB, LOGL_NOTICE, "Database '%s' has HLR DB schema version %d\n", dbc->fname, version);

	for (; allow_upgrade && (version < ARRAY_SIZE(db_upgrade_path)); version++) {
		db_upgrade_func_t upgrade_func = db_upgrade_path[version];
		rc = upgrade_func(dbc);
		if (rc != SQLITE_DONE) {
			LOGP(DDB, LOGL_ERROR, "Failed to upgrade HLR DB schema to version %d: (rc=%d) %s\n",
			     version+1, rc, sqlite3_errmsg(dbc->db));
			goto out_free;
		}
		LOGP(DDB, LOGL_NOTICE, "Database '%s' has been upgraded to HLR DB schema version %d\n",
		     dbc->fname, version+1);
	}

	if (version != CURRENT_SCHEMA_VERSION) {
		if (version < CURRENT_SCHEMA_VERSION) {
			LOGP(DDB, LOGL_NOTICE, "HLR DB schema version %d is outdated\n", version);
			if (!allow_upgrade) {
				LOGP(DDB, LOGL_ERROR, "Not upgrading HLR database to schema version %d; "
				     "use the --db-upgrade option to allow HLR database upgrades\n",
				     CURRENT_SCHEMA_VERSION);
			}
		} else
			LOGP(DDB, LOGL_ERROR, "HLR DB schema version %d is unknown\n", version);

		goto out_free;
	}

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
