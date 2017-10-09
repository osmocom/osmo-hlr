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

#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <osmocom/core/utils.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gsm/gsm23003.h>

#include <sqlite3.h>

#include "logging.h"
#include "db.h"

#define LOGHLR(imsi, level, fmt, args ...)	LOGP(DAUC, level, "IMSI='%s': " fmt, imsi, ## args)

#define SL3_TXT(x, stmt, idx) 					\
	do {							\
		const char *_txt = (const char *) sqlite3_column_text(stmt, idx);\
		if (_txt)					\
			strncpy(x, _txt, sizeof(x));		\
		x[sizeof(x)-1] = '\0';				\
	} while (0)

int db_subscr_create(struct db_context *dbc, const char *imsi)
{
	sqlite3_stmt *stmt;
	int rc;

	if (!osmo_imsi_str_valid(imsi)) {
		LOGP(DAUC, LOGL_ERROR, "Cannot create subscriber: invalid IMSI: '%s'\n",
		     imsi);
		return -EINVAL;
	}

	stmt = dbc->stmt[DB_STMT_SUBSCR_CREATE];

	if (!db_bind_text(stmt, "$imsi", imsi))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	db_remove_reset(stmt);
	if (rc != SQLITE_DONE) {
		LOGHLR(imsi, LOGL_ERROR, "Cannot create subscriber: SQL error: (%d) %s\n",
		       rc, sqlite3_errmsg(dbc->db));
		return -EIO;
	}

	return 0;
}

int db_subscr_delete_by_id(struct db_context *dbc, int64_t subscr_id)
{
	int rc;
	int ret = 0;

	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_DEL_BY_ID];

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR,
		       "Cannot delete subscriber ID=%"PRId64": SQL error: (%d) %s\n",
		       subscr_id, rc, sqlite3_errmsg(dbc->db));
		db_remove_reset(stmt);
		return -EIO;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot delete: no such subscriber: ID=%"PRId64"\n",
		     subscr_id);
		ret = -ENOENT;
	} else if (rc != 1) {
		LOGP(DAUC, LOGL_ERROR, "Delete subscriber ID=%"PRId64
		     ": SQL modified %d rows (expected 1)\n", subscr_id, rc);
		ret = -EIO;
	}

	/* FIXME: also remove authentication data from auc_2g and auc_3g */

	db_remove_reset(stmt);
	return ret;
}

int db_subscr_update_msisdn_by_imsi(struct db_context *dbc, const char *imsi,
				    const char *msisdn)
{
	int rc;
	int ret = 0;

	if (!osmo_msisdn_str_valid(msisdn)) {
		LOGHLR(imsi, LOGL_ERROR,
		       "Cannot update subscriber: invalid MSISDN: '%s'\n",
		       msisdn);
		return -EINVAL;
	}

	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_SET_MSISDN_BY_IMSI];

	if (!db_bind_text(stmt, "$imsi", imsi))
		return -EIO;
	if (!db_bind_text(stmt, "$msisdn", msisdn))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGHLR(imsi, LOGL_ERROR,
		       "Cannot update subscriber's MSISDN: SQL error: (%d) %s\n",
		       rc, sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot update MSISDN: no such subscriber: IMSI='%s'\n",
		     imsi);
		ret = -ENOENT;
		goto out;
	} else if (rc != 1) {
		LOGHLR(imsi, LOGL_ERROR, "Update MSISDN: SQL modified %d rows (expected 1)\n", rc);
		ret = -EIO;
	}

out:
	db_remove_reset(stmt);
	return ret;

}

/* Common code for db_subscr_get_by_*() functions. */
static int db_sel(struct db_context *dbc, sqlite3_stmt *stmt, struct hlr_subscriber *subscr,
		  const char **err)
{
	int rc;
	int ret = 0;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		ret = -ENOENT;
		goto out;
	}
	if (rc != SQLITE_ROW) {
		ret = -EIO;
		goto out;
	}

	if (!subscr)
		goto out;

	/* obtain the various columns */
	subscr->id = sqlite3_column_int64(stmt, 0);
	SL3_TXT(subscr->imsi, stmt, 1);
	SL3_TXT(subscr->msisdn, stmt, 2);
	/* FIXME: These should all be BLOBs as they might contain NUL */
	SL3_TXT(subscr->vlr_number, stmt, 3);
	SL3_TXT(subscr->sgsn_number, stmt, 4);
	SL3_TXT(subscr->sgsn_address, stmt, 5);
	subscr->periodic_lu_timer = sqlite3_column_int(stmt, 6);
	subscr->periodic_rau_tau_timer = sqlite3_column_int(stmt, 7);
	subscr->nam_cs = sqlite3_column_int(stmt, 8);
	subscr->nam_ps = sqlite3_column_int(stmt, 9);
	subscr->lmsi = sqlite3_column_int(stmt, 10);
	subscr->ms_purged_cs = sqlite3_column_int(stmt, 11);
	subscr->ms_purged_ps = sqlite3_column_int(stmt, 12);

out:
	db_remove_reset(stmt);

	switch (ret) {
	case 0:
		*err = NULL;
		break;
	case -ENOENT:
		*err = "No such subscriber";
		break;
	default:
		*err = sqlite3_errmsg(dbc->db);
		break;
	}
	return ret;
}

int db_subscr_get_by_imsi(struct db_context *dbc, const char *imsi,
			  struct hlr_subscriber *subscr)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_SEL_BY_IMSI];
	const char *err;
	int rc;

	if (!db_bind_text(stmt, NULL, imsi))
		return -EIO;

	rc = db_sel(dbc, stmt, subscr, &err);
	if (rc)
		LOGP(DAUC, LOGL_ERROR, "Cannot read subscriber from db: IMSI='%s': %s\n",
		     imsi, err);
	return rc;
}

int db_subscr_get_by_msisdn(struct db_context *dbc, const char *msisdn,
			    struct hlr_subscriber *subscr)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_SEL_BY_MSISDN];
	const char *err;
	int rc;

	if (!db_bind_text(stmt, NULL, msisdn))
		return -EIO;

	rc = db_sel(dbc, stmt, subscr, &err);
	if (rc)
		LOGP(DAUC, LOGL_ERROR, "Cannot read subscriber from db: MSISDN='%s': %s\n",
		     msisdn, err);
	return rc;
}

int db_subscr_get_by_id(struct db_context *dbc, int64_t id,
			struct hlr_subscriber *subscr)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_SEL_BY_ID];
	const char *err;
	int rc;

	if (!db_bind_int64(stmt, NULL, id))
		return -EIO;

	rc = db_sel(dbc, stmt, subscr, &err);
	if (rc)
		LOGP(DAUC, LOGL_ERROR, "Cannot read subscriber from db: ID=%"PRId64": %s\n",
		     id, err);
	return rc;
}

int db_subscr_ps(struct db_context *dbc, const char *imsi, bool enable)
{
	sqlite3_stmt *stmt =
		dbc->stmt[enable ? DB_STMT_SET_NAM_PS_BY_IMSI : DB_STMT_UNSET_NAM_PS_BY_IMSI];
	int rc;

	if (!db_bind_text(stmt, NULL, imsi))
		return -EINVAL;

	rc = sqlite3_step(stmt); /* execute the statement */
	if (rc != SQLITE_DONE) {
		LOGHLR(imsi, LOGL_ERROR, "Error executing SQL: %d\n", rc);
		db_remove_reset(stmt);
		return -ENOEXEC;
	}

	rc = sqlite3_changes(dbc->db); /* verify execution result */
	if (rc != 1) {
		LOGHLR(imsi, LOGL_ERROR, "SQL modified %d rows (expected 1)\n",
		       rc);
		rc = -EINVAL;
	}

	db_remove_reset(stmt);
	return rc;
}

int db_subscr_lu(struct db_context *dbc,
		 const struct hlr_subscriber *subscr,
		 const char *vlr_or_sgsn_number, bool lu_is_ps)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_UPD_VLR_BY_ID];
	const char *txt;
	int rc, ret = 0;

	if (lu_is_ps) {
		stmt = dbc->stmt[DB_STMT_UPD_SGSN_BY_ID];
		txt = subscr->sgsn_number;
	} else {
		stmt = dbc->stmt[DB_STMT_UPD_VLR_BY_ID];
		txt = subscr->vlr_number;
	}

	rc = sqlite3_bind_int64(stmt, 1, subscr->id);
	if (rc != SQLITE_OK) {
		LOGP(DAUC, LOGL_ERROR, "Error binding ID: %d\n", rc);
		return -EINVAL;
	}

	rc = sqlite3_bind_text(stmt, 2, txt, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		LOGP(DAUC, LOGL_ERROR, "Error binding VLR/SGSN Number: %d\n", rc);
		ret = -EBADMSG;
		goto out;
	}

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR, "Error updating SQN: %d\n", rc);
		ret = -ENOEXEC;
	}
out:
	db_remove_reset(stmt);

	return ret;
}

int db_subscr_purge(struct db_context *dbc, const char *imsi, bool is_ps)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_UPD_VLR_BY_ID];
	int rc, ret = 1;

	if (is_ps)
		stmt = dbc->stmt[DB_STMT_UPD_PURGE_PS_BY_IMSI];
	else
		stmt = dbc->stmt[DB_STMT_UPD_PURGE_CS_BY_IMSI];

	if (!db_bind_text(stmt, NULL, imsi))
		return -EINVAL;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR, "Error setting Purged: %d\n", rc);
		ret = -ENOEXEC;
	}
	/* FIXME: return 0 in case IMSI not known */

	db_remove_reset(stmt);

	return ret;
}
