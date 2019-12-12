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
#include <osmocom/core/timer.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gsm/gsm23003.h>

#include <sqlite3.h>

#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/db.h>
#include <osmocom/gsupclient/gsup_peer_id.h>

#define LOGHLR(imsi, level, fmt, args ...)	LOGP(DAUC, level, "IMSI='%s': " fmt, imsi, ## args)

/*! Add new subscriber record to the HLR database.
 * \param[in,out] dbc  database context.
 * \param[in] imsi  ASCII string of IMSI digits, is validated.
 * \param[in] flags  Bitmask of DB_SUBSCR_FLAG_*.
 * \returns 0 on success, -EINVAL on invalid IMSI, -EIO on database error.
 */
int db_subscr_create(struct db_context *dbc, const char *imsi, uint8_t flags)
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
	if (!db_bind_int(stmt, "$nam_cs", (flags & DB_SUBSCR_FLAG_NAM_CS) != 0))
		return -EIO;
	if (!db_bind_int(stmt, "$nam_ps", (flags & DB_SUBSCR_FLAG_NAM_PS) != 0))
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

static void parse_last_lu_seen(time_t *dst, const char *last_lu_seen_str, const char *imsi, const char *label)
{
	struct tm tm = {0};
	time_t val;
	if (!last_lu_seen_str || last_lu_seen_str[0] == '\0')
		return;

	if (strptime(last_lu_seen_str, DB_LAST_LU_SEEN_FMT, &tm) == NULL) {
		LOGP(DAUC, LOGL_ERROR, "IMSI-%s: Last LU Seen %s: Cannot parse timestamp '%s'\n",
		     imsi, label, last_lu_seen_str);
		return;
	}

	errno = 0;
	val = mktime(&tm);
	if (val == -1) {
		LOGP(DAUC, LOGL_ERROR, "IMSI-%s: Last LU Seen %s: Cannot convert timestamp '%s' to time_t: %s\n",
		     imsi, label, last_lu_seen_str, strerror(errno));
		val = 0;
	}

	*dst = val;
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
	parse_last_lu_seen(&subscr->last_lu_seen, (const char *)sqlite3_column_text(stmt, 14),
			   subscr->imsi, "CS");
	parse_last_lu_seen(&subscr->last_lu_seen_ps, (const char *)sqlite3_column_text(stmt, 15),
			   subscr->imsi, "PS");
	copy_sqlite3_text_to_ipa_name(&subscr->vlr_via_proxy, stmt, 16);
	copy_sqlite3_text_to_ipa_name(&subscr->sgsn_via_proxy, stmt, 17);

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

/*! Check if a subscriber exists in the HLR database.
 * \param[in, out] dbc  database context.
 * \param[in] imsi  ASCII string of IMSI digits.
 * \returns 0 if it exists, -ENOENT if it does not exist, -EIO on database error.
 */
int db_subscr_exists_by_imsi(struct db_context *dbc, const char *imsi) {
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_EXISTS_BY_IMSI];
	const char *err;
	int rc;

	if (!db_bind_text(stmt, NULL, imsi))
		return -EIO;

	rc = sqlite3_step(stmt);
	db_remove_reset(stmt);
	if (rc == SQLITE_ROW)
		return 0; /* exists */
	if (rc == SQLITE_DONE)
		return -ENOENT; /* does not exist */

	err = sqlite3_errmsg(dbc->db);
	LOGP(DAUC, LOGL_ERROR, "Failed to check if subscriber exists by IMSI='%s': %s\n", imsi, err);
	return rc;
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
	if (rc && rc != -ENOENT)
		LOGP(DAUC, LOGL_ERROR, "Cannot read subscriber from db: IMSI='%s': %s\n",
		     imsi, err);
	return rc;
}

/*! Check if a subscriber exists in the HLR database.
 * \param[in, out] dbc  database context.
 * \param[in] msisdn  ASCII string of MSISDN digits.
 * \returns 0 if it exists, -ENOENT if it does not exist, -EIO on database error.
 */
int db_subscr_exists_by_msisdn(struct db_context *dbc, const char *msisdn)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_EXISTS_BY_MSISDN];
	const char *err;
	int rc;

	if (!db_bind_text(stmt, NULL, msisdn))
		return -EIO;

	rc = sqlite3_step(stmt);
	db_remove_reset(stmt);
	if (rc == SQLITE_ROW)
		return 0; /* exists */
	if (rc == SQLITE_DONE)
		return -ENOENT; /* does not exist */

	err = sqlite3_errmsg(dbc->db);
	LOGP(DAUC, LOGL_ERROR, "Failed to check if subscriber exists "
		"by MSISDN='%s': %s\n", msisdn, err);
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
	if (rc && rc != -ENOENT)
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
	if (rc && rc != -ENOENT)
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
	if (rc && rc != -ENOENT)
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
		 const struct osmo_ipa_name *vlr_name, bool is_ps,
		 const struct osmo_ipa_name *via_proxy)
{
	sqlite3_stmt *stmt;
	int rc, ret = 0;
	struct timespec localtime;

	stmt = dbc->stmt[is_ps ? DB_STMT_UPD_SGSN_BY_ID
			       : DB_STMT_UPD_VLR_BY_ID];

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	if (!db_bind_text(stmt, "$number", (char*)vlr_name->val))
		return -EIO;

	if (via_proxy && via_proxy->len) {
		if (!db_bind_text(stmt, "$proxy", (char*)via_proxy->val))
			return -EIO;
	} else {
		if (!db_bind_null(stmt, "$proxy"))
			return -EIO;
	}

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

	stmt = dbc->stmt[is_ps? DB_STMT_SET_LAST_LU_SEEN_PS : DB_STMT_SET_LAST_LU_SEEN];

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

static int _db_ind_run(struct db_context *dbc, sqlite3_stmt *stmt, const char *vlr, bool reset)
{
	int rc;

	if (!db_bind_text(stmt, "$vlr", vlr))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (reset)
		db_remove_reset(stmt);
	return rc;
}

static int _db_ind_add(struct db_context *dbc, const char *vlr)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_IND_ADD];
	if (_db_ind_run(dbc, stmt, vlr, true) != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "Cannot create IND entry for %s\n", osmo_quote_str_c(OTC_SELECT, vlr, -1));
		return -EIO;
	}
	return 0;
}

static int _db_ind_del(struct db_context *dbc, const char *vlr)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_IND_DEL];
	_db_ind_run(dbc, stmt, vlr, true);
	/* We don't really care about the result. If it didn't exist, then that was the goal anyway. */
	return 0;
}

static int _db_ind_get(struct db_context *dbc, const char *vlr, unsigned int *ind)
{
	int ret = 0;
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_IND_SELECT];
	int rc = _db_ind_run(dbc, stmt, vlr, false);
	if (rc == SQLITE_DONE) {
		/* Does not exist yet */
		ret = -ENOENT;
		goto out;
	} else if (rc != SQLITE_ROW) {
		LOGP(DDB, LOGL_ERROR, "Error executing SQL: %d\n", rc);
		ret = -EIO;
		goto out;
	}

	OSMO_ASSERT(ind);
	*ind = sqlite3_column_int64(stmt, 0);
out:
	db_remove_reset(stmt);
	return ret;
}

int _db_ind(struct db_context *dbc, const struct osmo_gsup_peer_id *vlr,
	    unsigned int *ind, bool del)
{
	const char *vlr_name = NULL;
	int rc;

	switch (vlr->type) {
	case OSMO_GSUP_PEER_ID_IPA_NAME:
		if (vlr->ipa_name.len < 2 || vlr->ipa_name.val[vlr->ipa_name.len - 1] != '\0') {
			LOGP(DDB, LOGL_ERROR, "Expecting VLR ipa_name to be zero terminated; found %s\n",
			     osmo_ipa_name_to_str(&vlr->ipa_name));
			return -ENOTSUP;
		}
		vlr_name = (const char*)vlr->ipa_name.val;
		break;
	default:
		LOGP(DDB, LOGL_ERROR, "Unsupported osmo_gsup_peer_id type: %s\n",
		     osmo_gsup_peer_id_type_name(vlr->type));
		return -ENOTSUP;
	}

	if (del)
		return _db_ind_del(dbc, vlr_name);

	rc = _db_ind_get(dbc, vlr_name, ind);
	if (!rc)
		return 0;

	/* Does not exist yet, create. */
	rc = _db_ind_add(dbc, vlr_name);
	if (rc) {
		LOGP(DDB, LOGL_ERROR, "Error creating IND entry for %s\n", osmo_quote_str_c(OTC_SELECT, vlr_name, -1));
		return rc;
	}

	/* To be sure, query again from scratch. */
	return _db_ind_get(dbc, vlr_name, ind);
}

int db_ind(struct db_context *dbc, const struct osmo_gsup_peer_id *vlr, unsigned int *ind)
{
	return _db_ind(dbc, vlr, ind, false);
}

int db_ind_del(struct db_context *dbc, const struct osmo_gsup_peer_id *vlr)
{
	return _db_ind(dbc, vlr, NULL, true);
}
