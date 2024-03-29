/* (C) 2015-2023 by Harald Welte <laforge@gnumonks.org>
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
#include <inttypes.h>
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/crypt/auth.h>

#include <sqlite3.h>

#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/auc.h>
#include <osmocom/hlr/rand.h>

#define LOGAUC(imsi, level, fmt, args ...)	LOGP(DAUC, level, "IMSI='%s': " fmt, imsi, ## args)

/* update the SQN for a given subscriber ID */
int db_update_sqn(struct db_context *dbc, int64_t subscr_id, uint64_t new_sqn)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_AUC_UPD_SQN];
	int rc;
	int ret = 0;

	if (!db_bind_int64(stmt, "$sqn", new_sqn))
		return -EIO;

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DAUC, LOGL_ERROR, "Cannot update SQN for subscriber ID=%" PRId64
		     ": SQL error: (%d) %s\n",
		     subscr_id, rc, sqlite3_errmsg(dbc->db));
		ret = -EIO;
		goto out;
	}

	/* verify execution result */
	rc = sqlite3_changes(dbc->db);
	if (!rc) {
		LOGP(DAUC, LOGL_ERROR, "Cannot update SQN for subscriber ID=%" PRId64
		     ": no auc_3g entry for such subscriber\n", subscr_id);
		ret = -ENOENT;
	} else if (rc != 1) {
		LOGP(DAUC, LOGL_ERROR, "Update SQN for subscriber ID=%" PRId64
		     ": SQL modified %d rows (expected 1)\n", subscr_id, rc);
		ret = -EIO;
	}

out:
	db_remove_reset(stmt);
	return ret;
}

/* hexparse a specific column of a sqlite prepared statement into dst (with length check)
 * returns byte length in case of success, -EIO on error */
static int hexparse_stmt(uint8_t *dst, size_t dst_len_min, size_t dst_len_max, sqlite3_stmt *stmt,
			 int col, const char *col_name, const char *imsi)
{
	const uint8_t *text;
	size_t col_len;

	/* Bytes are stored as hex strings in database, hence divide length by two */
	col_len = sqlite3_column_bytes(stmt, col) / 2;

	if (col_len < dst_len_min) {
		LOGAUC(imsi, LOGL_ERROR, "Error reading %s, expected min length %lu but has length %lu\n", col_name,
		       dst_len_min, col_len);
		return -EIO;
	}

	if (col_len > dst_len_max) {
		LOGAUC(imsi, LOGL_ERROR, "Error reading %s, expected max length %lu but has length %lu\n", col_name,
		       dst_len_max, col_len);
		return -EIO;
	}

	text = sqlite3_column_text(stmt, col);
	if (!text) {
		LOGAUC(imsi, LOGL_ERROR, "Error reading %s\n", col_name);
		return -EIO;
	}

	if (osmo_hexparse((void *)text, dst, dst_len_max) != col_len)
		return -EINVAL;

	return col_len;
}

/* obtain the authentication data for a given imsi
 * returns 0 for success, negative value on error:
 * -ENOENT if the IMSI is not known, -ENOKEY if the IMSI is known but has no auth data,
 * -EIO on db failure */
int db_get_auth_data(struct db_context *dbc, const char *imsi,
		     struct osmo_sub_auth_data2 *aud2g,
		     struct osmo_sub_auth_data2 *aud3g,
		     int64_t *subscr_id)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_AUC_BY_IMSI];
	int ret = 0;
	int rc;

	memset(aud2g, 0, sizeof(*aud2g));
	memset(aud3g, 0, sizeof(*aud3g));

	if (!db_bind_text(stmt, "$imsi", imsi))
		return -EIO;

	/* execute the statement */
	rc = sqlite3_step(stmt);
	if (rc == SQLITE_DONE) {
		LOGAUC(imsi, LOGL_INFO, "No such subscriber\n");
		ret = -ENOENT;
		goto out;
	} else if (rc != SQLITE_ROW) {
		LOGAUC(imsi, LOGL_ERROR, "Error executing SQL: %d\n", rc);
		ret = -EIO;
		goto out;
	}

	/* as an optimization, we retrieve the subscriber ID, to ensure we can
	 * update the SQN later without having to go back via a JOIN with the
	 * subscriber table. */
	if (subscr_id)
		*subscr_id = sqlite3_column_int64(stmt, 0);

	/* obtain result values using sqlite3_column_*() */
	if (sqlite3_column_type(stmt, 1) == SQLITE_INTEGER) {
		/* we do have some 2G authentication data */
		if (hexparse_stmt(aud2g->u.gsm.ki, sizeof(aud2g->u.gsm.ki), sizeof(aud2g->u.gsm.ki),
				  stmt, 2, "Ki", imsi) < 0)
			goto end_2g;
		aud2g->algo = sqlite3_column_int(stmt, 1);
		aud2g->type = OSMO_AUTH_TYPE_GSM;
	} else
		LOGAUC(imsi, LOGL_DEBUG, "No 2G Auth Data\n");
end_2g:
	if (sqlite3_column_type(stmt, 3) == SQLITE_INTEGER) {
		/* we do have some 3G authentication data */
		rc = hexparse_stmt(aud3g->u.umts.k, 16, sizeof(aud3g->u.umts.k), stmt, 4, "K", imsi);
		if (rc < 0) {
			ret = -EIO;
			goto out;
		}
		aud3g->u.umts.k_len = rc;
		aud3g->algo = sqlite3_column_int(stmt, 3);

		/* UMTS Subscribers can have either OP or OPC */
		if (sqlite3_column_text(stmt, 5)) {
			rc = hexparse_stmt(aud3g->u.umts.opc, 16, sizeof(aud3g->u.umts.opc), stmt, 5, "OP", imsi);
			if (rc < 0) {
				ret = -EIO;
				goto out;
			}
			aud3g->u.umts.opc_len = rc;
			aud3g->u.umts.opc_is_op = 1;
		} else {
			rc = hexparse_stmt(aud3g->u.umts.opc, 16, sizeof(aud3g->u.umts.opc), stmt, 6, "OPC", imsi);
			if (rc < 0) {
				ret = -EIO;
				goto out;
			}
			aud3g->u.umts.opc_len = rc;
			aud3g->u.umts.opc_is_op = 0;
		}
		aud3g->u.umts.sqn = sqlite3_column_int64(stmt, 7);
		aud3g->u.umts.ind_bitlen = sqlite3_column_int(stmt, 8);
		/* FIXME: amf? */
		aud3g->type = OSMO_AUTH_TYPE_UMTS;
	} else
		LOGAUC(imsi, LOGL_DEBUG, "No 3G Auth Data\n");

	if (aud2g->type == 0 && aud3g->type == 0)
		ret = -ENOKEY;

out:
	db_remove_reset(stmt);
	return ret;
}

/* return number of vectors generated, negative value on error:
 * -ENOENT if the IMSI is not known, -ENOKEY if the IMSI is known but has no auth data,
 * -EIO on db failure */
int db_get_auc(struct db_context *dbc, const char *imsi,
	       unsigned int auc_3g_ind, struct osmo_auth_vector *vec,
	       unsigned int num_vec, const uint8_t *rand_auts,
	       const uint8_t *auts, bool separation_bit)
{
	struct osmo_sub_auth_data2 aud2g, aud3g;
	int64_t subscr_id;
	int ret = 0;
	int rc;

	rc = db_get_auth_data(dbc, imsi, &aud2g, &aud3g, &subscr_id);
	if (rc)
		return rc;

	/* modulo by the IND bitlen value range. For example, ind_bitlen == 5 would modulo 32:
	 * 1 << 5 == 0b0100000 == 32
	 * - 1 == 0b0011111 == bitmask of 5 lowest bits
	 * x &= 0b0011111 == modulo 32
	 * Why do this? osmo-hlr cannot possibly choose individual VLR INDs always matching all subscribers' IND_bitlen,
	 * which might vary wildly. Instead, let hlr.c pass in an arbitrarily high number here, and the modulo does a
	 * round-robin if the IND pools that this subscriber has available. */
	auc_3g_ind &= (1U << aud3g.u.umts.ind_bitlen) - 1;
	aud3g.u.umts.ind = auc_3g_ind;

	/* the first bit (bit0) cannot be used as AMF anymore, but has been
	 * re-appropriated as the separation bit.  See 3GPP TS 33.102 Annex H
	 * together with 3GPP TS 33.401 / 33.402 / 33.501 */
	aud3g.u.umts.amf[0] = aud3g.u.umts.amf[0] & 0x7f;
	if (separation_bit)
		aud3g.u.umts.amf[0] |= 0x80;

	LOGAUC(imsi, LOGL_DEBUG, "Calling to generate %u vectors\n", num_vec);
	rc = auc_compute_vectors(vec, num_vec, &aud2g, &aud3g, rand_auts, auts);
	if (rc < 0) {
		num_vec = 0;
		ret = -1;
	} else {
		num_vec = rc;
		ret = num_vec;
	}
	LOGAUC(imsi, LOGL_INFO, "Generated %u vectors\n", num_vec);

	/* Update SQN in database, as needed */
	if (aud3g.algo) {
		LOGAUC(imsi, LOGL_DEBUG, "Updating SQN=%" PRIu64 " in DB\n",
		       aud3g.u.umts.sqn);
		rc = db_update_sqn(dbc, subscr_id, aud3g.u.umts.sqn);
		/* don't tell caller we generated any triplets in case of
		 * update error */
		if (rc < 0) {
			LOGAUC(imsi, LOGL_ERROR, "Error updating SQN: %d\n", rc);
			num_vec = 0;
			ret = -1;
		}
	}

	return ret;
}
