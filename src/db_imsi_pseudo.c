/* (C) 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <errno.h>
#include <inttypes.h>

#include <sqlite3.h>

#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/imsi_pseudo.h>

int db_get_imsi_pseudo_data(struct db_context *dbc, int64_t subscr_id, struct imsi_pseudo_data *data)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_PSEUDO_BY_ID];
	int i, rc, ret = 0;

	memset(data, 0, sizeof(*data));

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;

	/* Retrieve up to two allocated pseudo IMSIs in three sqlite3 steps */
	for (i = 0; i < 3; i++) {
		rc = sqlite3_step(stmt);
		switch (rc) {
		case SQLITE_ROW:
			data->alloc_count = i + 1;
			switch (i) {
			case 0:
				/* First entry is always current (ORDER BY in SQL statement) */
				copy_sqlite3_text_to_buf(data->current, stmt, 0);
				data->i = sqlite3_column_int(stmt, 1);
				break;
			case 1:
				copy_sqlite3_text_to_buf(data->previous, stmt, 0);
				break;
			case 2:
				LOGPSEUDO(subscr_id, LOGL_ERROR, "more than two pseudonymous IMSI allocated\n");
				ret = -EINVAL;
				goto out;
			}
			break;
		case SQLITE_DONE:
			goto out;
		default:
			LOGPSEUDO(subscr_id, LOGL_ERROR, "error executing SQL: %d\n", rc);
			ret = -EIO;
			goto out;
		}
	}
out:
	db_remove_reset(stmt);
	return ret;
}

int db_alloc_imsi_pseudo(struct db_context *dbc, int64_t subscr_id, const char *imsi_pseudo, int64_t imsi_pseudo_i)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_PSEUDO_INSERT];
	int rc, ret = 0;

	if (!db_bind_int64(stmt, "$subscriber_id", subscr_id))
		return -EIO;
	if (!db_bind_text(stmt, "$imsi_pseudo", imsi_pseudo))
		return -EIO;
	if (!db_bind_int64(stmt, "$imsi_pseudo_i", imsi_pseudo_i))
		return -EIO;

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGPSEUDO(subscr_id, LOGL_ERROR, "imsi_pseudo='%s', imsi_pseudo_i='%" PRId64 "': SQL error during"
			  " allocate: %d\n", imsi_pseudo, imsi_pseudo_i, rc);
		ret = -EIO;
	}
	db_remove_reset(stmt);
	return ret;
}

int db_dealloc_imsi_pseudo(struct db_context *dbc, const char *imsi_pseudo)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_PSEUDO_DELETE];
	int rc, ret = 0;

	if (!db_bind_text(stmt, "$imsi_pseudo", imsi_pseudo))
		return -EIO;

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		LOGP(DPSEUDO, LOGL_ERROR, "imsi_pseudo='%s': SQL error during deallocate: %d\n", imsi_pseudo, rc);
		ret = -EIO;
	}

	db_remove_reset(stmt);
	return ret;
}

/*! Get the next random free pseudo IMSI.
 *  \param[in] dbc database context.
 *  \param[out] imsi_pseudo buffer with length GSM23003_IMSI_MAX_DIGITS+1.
 *  \returns 0: success, -1: no next IMSI available, -2: SQL error. */
int db_get_imsi_pseudo_next(struct db_context *dbc, char *imsi_pseudo)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_PSEUDO_NEXT];
	const char *imsi;
	int rc, ret = 0;

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_ROW:
		/* Can't use copy_sqlite3_text_to_buf, as it assumes the wrong size for imsi_pseudo */
		imsi = (const char *)sqlite3_column_text(stmt, 0);
		osmo_strlcpy(imsi_pseudo, imsi, GSM23003_IMSI_MAX_DIGITS+1);
		break;
	case SQLITE_DONE:
		LOGP(DPSEUDO, LOGL_ERROR, "failed to get next pseudonymous IMSI: all IMSIs are already allocated as"
					  " pseudo IMSI\n");
		ret = -1;
		break;
	default:
		LOGP(DPSEUDO, LOGL_ERROR, "failed to get next pseudonymous IMSI, SQL error: %d\n", rc);
		ret = -2;
		break;
	}

	db_remove_reset(stmt);
	return ret;
}

/*! Resolve a pseudo IMSI to the real IMSI.
 *  \param[in] dbc database context.
 *  \param[in] imsi_pseudo the IMSI to be resolved
 *  \param[out] imsi buffer with length GSM23003_IMSI_MAX_DIGITS+1.
 *  \returns 0: success, -1: no associated real IMSI, -2: SQL error. */
int db_get_imsi_pseudo_resolve(struct db_context *dbc, const char *imsi_pseudo, char *imsi)
{
	sqlite3_stmt *stmt = dbc->stmt[DB_STMT_PSEUDO_RESOLVE];
	int rc, ret=0;

	if (!db_bind_text(stmt, "$imsi_pseudo", imsi_pseudo))
		return -EIO;

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_ROW:
		/* Can't use copy_sqlite3_text_to_buf, as it assumes the wrong size for imsi_pseudo */
		osmo_strlcpy(imsi, (const char *)sqlite3_column_text(stmt, 0), GSM23003_IMSI_MAX_DIGITS + 1);
		break;
	case SQLITE_DONE:
		LOGP(DPSEUDO, LOGL_NOTICE, "cannot resolve pseudonymous IMSI '%s': no associated real IMSI found\n",
		     imsi_pseudo);
		ret = -1;
		break;
	default:
		LOGP(DPSEUDO, LOGL_ERROR, "cannot resolve pseudonymous IMSI '%s': SQL error: %d\n", imsi_pseudo, rc);
		ret = -2;
		break;
	}

	db_remove_reset(stmt);
	return ret;
}
