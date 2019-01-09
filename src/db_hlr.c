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

#define _POSIX_C_SOURCE 200809L /* for strptime(3) */
/* These are needed as well due to the above _POSIX_C_SOURCE definition: */
#define _DEFAULT_SOURCE		/* for struct timezone */
#define _XOPEN_SOURCE		/* for clockid_t */

#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>

#include <osmocom/core/utils.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gsm/gsm23003.h>

#include <sqlite3.h>

#include "logging.h"
#include "hlr.h"
#include "db.h"
#include "gsup_server.h"
#include "luop.h"

#define LOGHLR(imsi, level, fmt, args ...)	LOGP(DAUC, level, "IMSI='%s': " fmt, imsi, ## args)

/*! Add new subscriber record to the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] imsi  ASCII string of IMSI digits, is validated.
 * \returns 0 on success, -EINVAL on invalid IMSI, -EIO on database error.
 */
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

/*! Completely delete a subscriber record from the HLR database.
 * Also remove authentication data.
 * Future todo: also drop from all other database tables, which aren't used yet
 * at the time of writing this.
 * \param[in,out] dbc  database context.
 * \param[in] subscr_id  ID of the subscriber in the HLR db.
 * \returns if the subscriber was found and removed, -EIO on database error,
 *          -ENOENT if no such subscriber data exists.
 */
int db_subscr_delete_by_id(struct db_context *dbc, int64_t subscr_id)
{
	int rc;
	struct sub_auth_data_str aud;
	int ret = 0;

	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_DEL_BY_ID];

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR,
		       "Cannot delete subscriber ID=%" PRId64 ": SQL error: (%d) %s\n",
		       subscr_id, rc, sqlite3_errmsg(dbc->db));
		db_remove_reset(stmt);
		return -EIO;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot delete: no such subscriber: ID=%" PRId64 "\n",
		     subscr_id);
		ret = -ENOENT;
	} else if (rc != 1) {
		LOGP(DAUC, LOGL_ERROR, "Delete subscriber ID=%" PRId64
		     ": SQL modified %d rows (expected 1)\n", subscr_id, rc);
		ret = -EIO;
	}
	db_remove_reset(stmt);

	/* make sure to remove authentication data for this subscriber id, for
	 * both 2G and 3G. */

	aud = (struct sub_auth_data_str){
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_NONE,
	};
	rc = db_subscr_update_aud_by_id(dbc, subscr_id, &aud);
	if (ret == -ENOENT && !rc)
		ret = 0;

	aud = (struct sub_auth_data_str){
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_NONE,
	};
	rc = db_subscr_update_aud_by_id(dbc, subscr_id, &aud);
	if (ret == -ENOENT && !rc)
		ret = 0;

	return ret;
}

/*! Set a subscriber's MSISDN in the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] imsi  ASCII string of IMSI digits
 * \param[in] msisdn  ASCII string of MSISDN digits, or NULL to remove the MSISDN.
 * \returns 0 on success, -EINVAL in case of invalid MSISDN string, -EIO on
 *          database failure, -ENOENT if no such subscriber exists.
 */
int db_subscr_update_msisdn_by_imsi(struct db_context *dbc, const char *imsi,
				    const char *msisdn)
{
	int rc;
	int ret = 0;

	if (msisdn && !osmo_msisdn_str_valid(msisdn)) {
		LOGHLR(imsi, LOGL_ERROR,
		       "Cannot update subscriber: invalid MSISDN: '%s'\n",
		       msisdn);
		return -EINVAL;
	}

	sqlite3_stmt *stmt = dbc->stmt[
		msisdn ? DB_STMT_SET_MSISDN_BY_IMSI : DB_STMT_DELETE_MSISDN_BY_IMSI];

	if (!db_bind_text(stmt, "$imsi", imsi))
		return -EIO;
	if (msisdn) {
		if (!db_bind_text(stmt, "$msisdn", msisdn))
			return -EIO;
	}

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

/*! Insert or update 2G or 3G authentication tokens in the database.
 * If aud->type is OSMO_AUTH_TYPE_GSM, the auc_2g table entry for the
 * subscriber will be added or modified; if aud->algo is OSMO_AUTH_ALG_NONE,
 * however, the auc_2g entry for the subscriber is deleted. If aud->type is
 * OSMO_AUTH_TYPE_UMTS, the auc_3g table is updated; again, if aud->algo is
 * OSMO_AUTH_ALG_NONE, the auc_3g entry is deleted.
 * \param[in,out] dbc  database context.
 * \param[in] subscr_id  DB ID of the subscriber.
 * \param[in] aud  Pointer to new auth data (in ASCII string form).
 * \returns 0 on success, -EINVAL for invalid aud, -ENOENT for unknown
 *          subscr_id, -EIO for database errors.
 */
int db_subscr_update_aud_by_id(struct db_context *dbc, int64_t subscr_id,
			       const struct sub_auth_data_str *aud)
{
	sqlite3_stmt *stmt_del;
	sqlite3_stmt *stmt_ins;
	sqlite3_stmt *stmt;
	const char *label;
	int rc;
	int ret = 0;

	switch (aud->type) {
	case OSMO_AUTH_TYPE_GSM:
		label = "auc_2g";
		stmt_del = dbc->stmt[DB_STMT_AUC_2G_DELETE];
		stmt_ins = dbc->stmt[DB_STMT_AUC_2G_INSERT];

		switch (aud->algo) {
		case OSMO_AUTH_ALG_NONE:
		case OSMO_AUTH_ALG_COMP128v1:
		case OSMO_AUTH_ALG_COMP128v2:
		case OSMO_AUTH_ALG_COMP128v3:
		case OSMO_AUTH_ALG_XOR:
			break;
		case OSMO_AUTH_ALG_MILENAGE:
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " auth algo not suited for 2G: %s\n",
			     osmo_auth_alg_name(aud->algo));
			return -EINVAL;
		default:
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " Unknown auth algo: %d\n", aud->algo);
			return -EINVAL;
		}

		if (aud->algo == OSMO_AUTH_ALG_NONE)
			break;
		if (!osmo_is_hexstr(aud->u.gsm.ki, 32, 32, true)) {
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " Invalid KI: '%s'\n", aud->u.gsm.ki);
			return -EINVAL;
		}
		break;

	case OSMO_AUTH_TYPE_UMTS:
		label = "auc_3g";
		stmt_del = dbc->stmt[DB_STMT_AUC_3G_DELETE];
		stmt_ins = dbc->stmt[DB_STMT_AUC_3G_INSERT];
		switch (aud->algo) {
		case OSMO_AUTH_ALG_NONE:
		case OSMO_AUTH_ALG_MILENAGE:
			break;
		case OSMO_AUTH_ALG_COMP128v1:
		case OSMO_AUTH_ALG_COMP128v2:
		case OSMO_AUTH_ALG_COMP128v3:
		case OSMO_AUTH_ALG_XOR:
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " auth algo not suited for 3G: %s\n",
			     osmo_auth_alg_name(aud->algo));
			return -EINVAL;
		default:
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " Unknown auth algo: %d\n", aud->algo);
			return -EINVAL;
		}

		if (aud->algo == OSMO_AUTH_ALG_NONE)
			break;
		if (!osmo_is_hexstr(aud->u.umts.k, 32, 32, true)) {
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " Invalid K: '%s'\n", aud->u.umts.k);
			return -EINVAL;
		}
		if (!osmo_is_hexstr(aud->u.umts.opc, 32, 32, true)) {
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " Invalid OP/OPC: '%s'\n", aud->u.umts.opc);
			return -EINVAL;
		}
		if (aud->u.umts.ind_bitlen > OSMO_MILENAGE_IND_BITLEN_MAX) {
			LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
			     " Invalid ind_bitlen: %d\n", aud->u.umts.ind_bitlen);
			return -EINVAL;
		}
		break;
	default:
		LOGP(DAUC, LOGL_ERROR, "Cannot update auth tokens:"
		     " unknown auth type: %d\n", aud->type);
		return -EINVAL;
	}

	stmt = stmt_del;

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR,
		     "Cannot delete %s row: SQL error: (%d) %s\n",
		     label, rc, sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc)
		/* Leave "no such entry" logging to the caller -- during
		 * db_subscr_delete_by_id(), we call this to make sure it is
		 * empty, and no entry is not an error then.*/
		ret = -ENOENT;
	else if (rc != 1) {
		LOGP(DAUC, LOGL_ERROR, "Delete subscriber ID=%" PRId64
		     " from %s: SQL modified %d rows (expected 1)\n",
		     subscr_id, label, rc);
		ret = -EIO;
	}

	db_remove_reset(stmt);

	/* Error situation? Return now. */
	if (ret && ret != -ENOENT)
		return ret;

	/* Just delete requested? */
	if (aud->algo == OSMO_AUTH_ALG_NONE)
		return ret;

	/* Don't return -ENOENT if inserting new data. */
	ret = 0;

	/* Insert new row */
	stmt = stmt_ins;

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	switch (aud->type) {
	case OSMO_AUTH_TYPE_GSM:
		if (!db_bind_int(stmt, "$algo_id_2g", aud->algo))
			return -EIO;
		if (!db_bind_text(stmt, "$ki", aud->u.gsm.ki))
			return -EIO;
		break;
	case OSMO_AUTH_TYPE_UMTS:
		if (!db_bind_int(stmt, "$algo_id_3g", aud->algo))
			return -EIO;
		if (!db_bind_text(stmt, "$k", aud->u.umts.k))
			return -EIO;
		if (!db_bind_text(stmt, "$op",
				  aud->u.umts.opc_is_op ? aud->u.umts.opc : NULL))
			return -EIO;
		if (!db_bind_text(stmt, "$opc",
				  aud->u.umts.opc_is_op ? NULL : aud->u.umts.opc))
			return -EIO;
		if (!db_bind_int(stmt, "$ind_bitlen", aud->u.umts.ind_bitlen))
			return -EIO;
		break;
	default:
		OSMO_ASSERT(false);
	}

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR,
		     "Cannot insert %s row: SQL error: (%d) %s\n",
		     label, rc, sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

out:
	db_remove_reset(stmt);
	return ret;
}

/*! Set a subscriber's IMEI in the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] imsi  ASCII string of IMSI digits
 * \param[in] imei  ASCII string of identifier digits, or NULL to remove the IMEI.
 * \returns 0 on success, -ENOENT when the given subscriber does not exist,
 *         -EIO on database errors.
 */
int db_subscr_update_imei_by_imsi(struct db_context *dbc, const char* imsi, const char *imei)
{
	int rc, ret = 0;
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_UPD_IMEI_BY_IMSI];

	if (imei && !osmo_imei_str_valid(imei, false)) {
		LOGP(DAUC, LOGL_ERROR, "Cannot update subscriber IMSI='%s': invalid IMEI: '%s'\n", imsi, imei);
		return -EINVAL;
	}

	if (!db_bind_text(stmt, "$imsi", imsi))
		return -EIO;
	if (imei && !db_bind_text(stmt, "$imei", imei))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR, "Update IMEI for subscriber IMSI='%s': SQL Error: %s\n", imsi,
		     sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot update IMEI for subscriber IMSI='%s': no such subscriber\n", imsi);
		ret = -ENOENT;
	} else if (rc != 1) {
		LOGP(DAUC, LOGL_ERROR, "Update IMEI for subscriber IMSI='%s': SQL modified %d rows (expected 1)\n",
		     imsi, rc);
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
	const char *last_lu_seen_str;
	struct tm tm;

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

	*subscr = (struct hlr_subscriber){};

	/* obtain the various columns */
	subscr->id = sqlite3_column_int64(stmt, 0);
	copy_sqlite3_text_to_buf(subscr->imsi, stmt, 1);
	copy_sqlite3_text_to_buf(subscr->msisdn, stmt, 2);
	copy_sqlite3_text_to_buf(subscr->imei, stmt, 3);
	/* FIXME: These should all be BLOBs as they might contain NUL */
	copy_sqlite3_text_to_buf(subscr->vlr_number, stmt, 4);
	copy_sqlite3_text_to_buf(subscr->sgsn_number, stmt, 5);
	copy_sqlite3_text_to_buf(subscr->sgsn_address, stmt, 6);
	subscr->periodic_lu_timer = sqlite3_column_int(stmt, 7);
	subscr->periodic_rau_tau_timer = sqlite3_column_int(stmt, 8);
	subscr->nam_cs = sqlite3_column_int(stmt, 9);
	subscr->nam_ps = sqlite3_column_int(stmt, 10);
	subscr->lmsi = sqlite3_column_int(stmt, 11);
	subscr->ms_purged_cs = sqlite3_column_int(stmt, 12);
	subscr->ms_purged_ps = sqlite3_column_int(stmt, 13);
	last_lu_seen_str = (const char *)sqlite3_column_text(stmt, 14);
	if (last_lu_seen_str && last_lu_seen_str[0] != '\0') {
		if (strptime(last_lu_seen_str, DB_LAST_LU_SEEN_FMT, &tm) == NULL) {
			LOGP(DAUC, LOGL_ERROR, "Cannot parse last LU timestamp '%s' of subscriber with IMSI='%s': %s\n",
			     last_lu_seen_str, subscr->imsi, strerror(errno));
		} else {
			subscr->last_lu_seen = mktime(&tm);
			if (subscr->last_lu_seen == -1) {
				LOGP(DAUC, LOGL_ERROR, "Cannot convert LU timestamp '%s' to time_t: %s\n",
				     last_lu_seen_str, strerror(errno));
				subscr->last_lu_seen = 0;
			}
		}
	}

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

/*! Retrieve subscriber data from the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] imsi  ASCII string of IMSI digits.
 * \param[out] subscr  place retrieved data in this struct.
 * \returns 0 on success, -ENOENT if no such subscriber was found, -EIO on
 *          database error.
 */
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

/*! Retrieve subscriber data from the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] msisdn  ASCII string of MSISDN digits.
 * \param[out] subscr  place retrieved data in this struct.
 * \returns 0 on success, -ENOENT if no such subscriber was found, -EIO on
 *          database error.
 */
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

/*! Retrieve subscriber data from the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] id  ID of the subscriber in the HLR db.
 * \param[out] subscr  place retrieved data in this struct.
 * \returns 0 on success, -ENOENT if no such subscriber was found, -EIO on
 *          database error.
 */
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
		LOGP(DAUC, LOGL_ERROR, "Cannot read subscriber from db: ID=%" PRId64 ": %s\n",
		     id, err);
	return rc;
}

/*! Retrieve subscriber data from the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] imei  ASCII string of identifier digits
 * \param[out] subscr  place retrieved data in this struct.
 * \returns 0 on success, -ENOENT if no such subscriber was found, -EIO on
 *          database error.
 */
int db_subscr_get_by_imei(struct db_context *dbc, const char *imei, struct hlr_subscriber *subscr)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_SEL_BY_IMEI];
	const char *err;
	int rc;

	if (!db_bind_text(stmt, NULL, imei))
		return -EIO;

	rc = db_sel(dbc, stmt, subscr, &err);
	if (rc)
		LOGP(DAUC, LOGL_ERROR, "Cannot read subscriber from db: IMEI=%s: %s\n", imei, err);
	return rc;
}

/*! You should use hlr_subscr_nam() instead; enable or disable PS or CS for a
 * subscriber without notifying GSUP clients.
 * \param[in,out] dbc  database context.
 * \param[in] imsi  ASCII string of IMSI digits.
 * \param[in] nam_val True to enable CS/PS, false to disable.
 * \param[in] is_ps  when true, set nam_ps, else set nam_cs.
 * \returns 0 on success, -ENOENT when the given IMSI does not exist, -EIO on
 *          database errors.
 */
int db_subscr_nam(struct db_context *dbc, const char *imsi, bool nam_val, bool is_ps)
{
	sqlite3_stmt *stmt;
	int rc;
	int ret = 0;

	stmt = dbc->stmt[is_ps ? DB_STMT_UPD_NAM_PS_BY_IMSI
			       : DB_STMT_UPD_NAM_CS_BY_IMSI];

	if (!db_bind_text(stmt, "$imsi", imsi))
		return -EIO;
	if (!db_bind_int(stmt, "$val", nam_val ? 1 : 0))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGHLR(imsi, LOGL_ERROR, "%s %s: SQL error: %s\n",
		       nam_val ? "enable" : "disable",
		       is_ps ? "PS" : "CS",
		       sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot %s %s: no such subscriber: IMSI='%s'\n",
		     nam_val ? "enable" : "disable",
		     is_ps ? "PS" : "CS",
		     imsi);
		ret = -ENOENT;
		goto out;
	} else if (rc != 1) {
		LOGHLR(imsi, LOGL_ERROR, "%s %s: SQL modified %d rows (expected 1)\n",
		       nam_val ? "enable" : "disable",
		       is_ps ? "PS" : "CS",
		       rc);
		ret = -EIO;
	}

out:
	db_remove_reset(stmt);
	return ret;
}

/*! Record a Location Updating in the database.
 * \param[in,out] dbc  database context.
 * \param[in] subscr_id  ID of the subscriber in the HLR db.
 * \param[in] vlr_or_sgsn_number  ASCII string of identifier digits.
 * \param[in] is_ps  when true, set sgsn_number, else set vlr_number.
 * \returns 0 on success, -ENOENT when the given subscriber does not exist,
 *         -EIO on database errors.
 */
int db_subscr_lu(struct db_context *dbc, int64_t subscr_id,
		 const char *vlr_or_sgsn_number, bool is_ps)
{
	sqlite3_stmt *stmt;
	int rc, ret = 0;
	struct timespec localtime;

	stmt = dbc->stmt[is_ps ? DB_STMT_UPD_SGSN_BY_ID
			       : DB_STMT_UPD_VLR_BY_ID];

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	if (!db_bind_text(stmt, "$number", vlr_or_sgsn_number))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR, "Update %s number for subscriber ID=%" PRId64 ": SQL Error: %s\n",
		     is_ps? "SGSN" : "VLR", subscr_id, sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot update %s number for subscriber ID=%" PRId64
		     ": no such subscriber\n",
		     is_ps? "SGSN" : "VLR", subscr_id);
		ret = -ENOENT;
		goto out;
	} else if (rc != 1) {
		LOGP(DAUC, LOGL_ERROR, "Update %s number for subscriber ID=%" PRId64
		       ": SQL modified %d rows (expected 1)\n",
		       is_ps? "SGSN" : "VLR", subscr_id, rc);
		ret = -EIO;
		goto out;
	}

	db_remove_reset(stmt);

	if (osmo_clock_gettime(CLOCK_REALTIME, &localtime) != 0) {
		LOGP(DAUC, LOGL_ERROR, "Cannot get the current time: (%d) %s\n", errno, strerror(errno));
		ret = -errno;
		goto out;
	}

	stmt = dbc->stmt[DB_STMT_SET_LAST_LU_SEEN];

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;
	/* The timestamp will be converted to UTC by SQLite. */
	if (!db_bind_int64(stmt, "$val", (int64_t)localtime.tv_sec)) {
		ret = -EIO;
		goto out;
	}

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR,
		       "Cannot update LU timestamp for subscriber ID=%" PRId64 ": SQL error: (%d) %s\n",
		       subscr_id, rc, sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot update LU timestamp for subscriber ID=%" PRId64
		     ": no such subscriber\n", subscr_id);
		ret = -ENOENT;
		goto out;
	} else if (rc != 1) {
		LOGP(DAUC, LOGL_ERROR, "Update LU timestamp for subscriber ID=%" PRId64
		     ": SQL modified %d rows (expected 1)\n", subscr_id, rc);
		ret = -EIO;
	}
out:
	db_remove_reset(stmt);
	return ret;
}

/*! Set the ms_purged_cs or ms_purged_ps values in the database.
 * \param[in,out] dbc  database context.
 * \param[in] by_imsi  ASCII string of IMSI digits.
 * \param[in] purge_val  true to purge, false to un-purge.
 * \param[in] is_ps  when true, set ms_purged_ps, else set ms_purged_cs.
 * \returns 0 on success, -ENOENT when the given IMSI does not exist, -EIO on
 *          database errors.
 */
int db_subscr_purge(struct db_context *dbc, const char *by_imsi,
		    bool purge_val, bool is_ps)
{
	sqlite3_stmt *stmt;
	int rc, ret = 0;

	stmt = dbc->stmt[is_ps ? DB_STMT_UPD_PURGE_PS_BY_IMSI
			       : DB_STMT_UPD_PURGE_CS_BY_IMSI];

	if (!db_bind_text(stmt, "$imsi", by_imsi))
		return -EIO;
	if (!db_bind_int(stmt, "$val", purge_val ? 1 : 0))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR, "%s %s: SQL error: %s\n",
		     purge_val ? "purge" : "un-purge",
		     is_ps ? "PS" : "CS",
		     sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot %s %s: no such subscriber: IMSI='%s'\n",
		     purge_val ? "purge" : "un-purge",
		     is_ps ? "PS" : "CS",
		     by_imsi);
		ret = -ENOENT;
		goto out;
	} else if (rc != 1) {
		LOGHLR(by_imsi, LOGL_ERROR, "%s %s: SQL modified %d rows (expected 1)\n",
		       purge_val ? "purge" : "un-purge",
		       is_ps ? "PS" : "CS",
		       rc);
		ret = -EIO;
	}

out:
	db_remove_reset(stmt);

	return ret;
}

/*! Update nam_cs/nam_ps in the db and trigger notifications to GSUP clients.
 * \param[in,out] hlr  Global hlr context.
 * \param[in] subscr   Subscriber from a fresh db_subscr_get_by_*() call.
 * \param[in] nam_val  True to enable CS/PS, false to disable.
 * \param[in] is_ps    True to enable/disable PS, false for CS.
 * \returns 0 on success, ENOEXEC if there is no need to change, a negative
 *          value on error.
 */
int hlr_subscr_nam(struct hlr *hlr, struct hlr_subscriber *subscr, bool nam_val, bool is_ps)
{
	int rc;
        struct lu_operation *luop;
        struct osmo_gsup_conn *co;
	bool is_val = is_ps? subscr->nam_ps : subscr->nam_cs;

	if (is_val == nam_val) {
		LOGHLR(subscr->imsi, LOGL_DEBUG, "Already has the requested value when asked to %s %s\n",
		       nam_val ? "enable" : "disable", is_ps ? "PS" : "CS");
		return ENOEXEC;
	}

	rc = db_subscr_nam(hlr->dbc, subscr->imsi, nam_val, is_ps);
	if (rc)
		return rc > 0? -rc : rc;

	/* If we're disabling, send a notice out to the GSUP client that is
	 * responsible. Otherwise no need. */
	if (nam_val)
		return 0;

	/* FIXME: only send to single SGSN where latest update for IMSI came from */
	llist_for_each_entry(co, &hlr->gs->clients, list) {
		luop = lu_op_alloc_conn(co);
		if (!luop) {
			LOGHLR(subscr->imsi, LOGL_ERROR,
			       "Cannot notify GSUP client, cannot allocate lu_operation,"
			       " for %s:%u\n",
			       co && co->conn && co->conn->server? co->conn->server->addr : "unset",
			       co && co->conn && co->conn->server? co->conn->server->port : 0);
			continue;
		}
		luop->subscr = *subscr;
		lu_op_tx_del_subscr_data(luop);
		lu_op_free(luop);
	}
	return 0;
}
