/* OsmoHLR subscriber management VTY implementation */
/* (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
 */

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/core/utils.h>

#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/timestamp.h>

struct vty;

#define hexdump_buf(buf) osmo_hexdump_nospc((void*)buf, sizeof(buf))

static char *get_datestr(const time_t *t, char *buf, size_t bufsize)
{
	struct tm tm;
	gmtime_r(t, &tm);
	strftime(buf, bufsize, "%FT%T+00:00", &tm);
	return buf;
}

static void dump_last_lu_seen(struct vty *vty, const char *domain_label, time_t last_lu_seen)
{
	uint32_t age;
	char datebuf[32];
	if (!last_lu_seen)
		return;
	vty_out(vty, "    last LU seen on %s: %s", domain_label, get_datestr(&last_lu_seen, datebuf, sizeof(datebuf)));
	if (!timestamp_age(&last_lu_seen, &age))
		vty_out(vty, " (invalid timestamp)%s", VTY_NEWLINE);
	else {
		vty_out(vty, " (");
#define UNIT_AGO(UNITNAME, UNITVAL) \
		if (age >= (UNITVAL)) { \
			vty_out(vty, "%u%s", age / (UNITVAL), UNITNAME); \
			age = age % (UNITVAL); \
		}
		UNIT_AGO("d", 60*60*24);
		UNIT_AGO("h", 60*60);
		UNIT_AGO("m", 60);
		UNIT_AGO("s", 1);
		vty_out(vty, " ago)%s", VTY_NEWLINE);
#undef UNIT_AGO
	}
}

static void subscr_dump_full_vty(struct vty *vty, struct hlr_subscriber *subscr)
{
	int rc;
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;

	vty_out(vty, "    ID: %"PRIu64"%s", subscr->id, VTY_NEWLINE);

	vty_out(vty, "    IMSI: %s%s", *subscr->imsi ? subscr->imsi : "none", VTY_NEWLINE);
	vty_out(vty, "    MSISDN: %s%s", *subscr->msisdn ? subscr->msisdn : "none", VTY_NEWLINE);

	if (*subscr->imei) {
		char checksum = osmo_luhn(subscr->imei, 14);
		if (checksum == -EINVAL)
			vty_out(vty, "    IMEI: %s (INVALID LENGTH!)%s", subscr->imei, VTY_NEWLINE);
		else
			vty_out(vty, "    IMEI: %s%c%s", subscr->imei, checksum, VTY_NEWLINE);
	}

	if (*subscr->vlr_number)
		vty_out(vty, "    VLR number: %s%s", subscr->vlr_number, VTY_NEWLINE);
	if (*subscr->sgsn_number)
		vty_out(vty, "    SGSN number: %s%s", subscr->sgsn_number, VTY_NEWLINE);
	if (*subscr->sgsn_address)
		vty_out(vty, "    SGSN address: %s%s", subscr->sgsn_address, VTY_NEWLINE);
	if (subscr->periodic_lu_timer)
		vty_out(vty, "    Periodic LU timer: %u%s", subscr->periodic_lu_timer, VTY_NEWLINE);
	if (subscr->periodic_rau_tau_timer)
		vty_out(vty, "    Periodic RAU/TAU timer: %u%s", subscr->periodic_rau_tau_timer, VTY_NEWLINE);
	if (subscr->lmsi)
		vty_out(vty, "    LMSI: %x%s", subscr->lmsi, VTY_NEWLINE);
	if (!subscr->nam_cs)
		vty_out(vty, "    CS disabled%s", VTY_NEWLINE);
	if (subscr->ms_purged_cs)
		vty_out(vty, "    CS purged%s", VTY_NEWLINE);
	if (!subscr->nam_ps)
		vty_out(vty, "    PS disabled%s", VTY_NEWLINE);
	if (subscr->ms_purged_ps)
		vty_out(vty, "    PS purged%s", VTY_NEWLINE);
	dump_last_lu_seen(vty, "CS", subscr->last_lu_seen);
	dump_last_lu_seen(vty, "PS", subscr->last_lu_seen_ps);

	if (!*subscr->imsi)
		return;

	OSMO_ASSERT(g_hlr);
	rc = db_get_auth_data(g_hlr->dbc, subscr->imsi, &aud2g, &aud3g, NULL);

	switch (rc) {
	case 0:
		break;
	case -ENOENT:
	case -ENOKEY:
		aud2g.algo = OSMO_AUTH_ALG_NONE;
		aud3g.algo = OSMO_AUTH_ALG_NONE;
		break;
	default:
		vty_out(vty, "%% Error retrieving data from database (%d)%s", rc, VTY_NEWLINE);
		return;
	}

	if (aud2g.type != OSMO_AUTH_TYPE_NONE && aud2g.type != OSMO_AUTH_TYPE_GSM) {
		vty_out(vty, "%% Error: 2G auth data is not of type 'GSM'%s", VTY_NEWLINE);
		aud2g = (struct osmo_sub_auth_data){};
	}

	if (aud3g.type != OSMO_AUTH_TYPE_NONE && aud3g.type != OSMO_AUTH_TYPE_UMTS) {
		vty_out(vty, "%% Error: 3G auth data is not of type 'UMTS'%s", VTY_NEWLINE);
		aud3g = (struct osmo_sub_auth_data){};
	}

	if (aud2g.algo != OSMO_AUTH_ALG_NONE && aud2g.type != OSMO_AUTH_TYPE_NONE) {
		vty_out(vty, "    2G auth: %s%s",
			osmo_auth_alg_name(aud2g.algo), VTY_NEWLINE);
		vty_out(vty, "             KI=%s%s",
			hexdump_buf(aud2g.u.gsm.ki), VTY_NEWLINE);
	}

	if (aud3g.algo != OSMO_AUTH_ALG_NONE && aud3g.type != OSMO_AUTH_TYPE_NONE) {
		vty_out(vty, "    3G auth: %s%s", osmo_auth_alg_name(aud3g.algo), VTY_NEWLINE);
		vty_out(vty, "             K=%s%s", hexdump_buf(aud3g.u.umts.k), VTY_NEWLINE);
		vty_out(vty, "             %s=%s%s", aud3g.u.umts.opc_is_op? "OP" : "OPC",
			hexdump_buf(aud3g.u.umts.opc), VTY_NEWLINE);
		vty_out(vty, "             IND-bitlen=%u", aud3g.u.umts.ind_bitlen);
		if (aud3g.u.umts.sqn)
			vty_out(vty, " last-SQN=%"PRIu64, aud3g.u.umts.sqn);
		vty_out(vty, VTY_NEWLINE);
	}
}

static int get_subscr_by_argv(struct vty *vty, const char *type, const char *id, struct hlr_subscriber *subscr)
{
	char imei_buf[GSM23003_IMEI_NUM_DIGITS_NO_CHK+1];
	int rc = -1;
	if (strcmp(type, "imsi") == 0)
		rc = db_subscr_get_by_imsi(g_hlr->dbc, id, subscr);
	else if (strcmp(type, "msisdn") == 0)
		rc = db_subscr_get_by_msisdn(g_hlr->dbc, id, subscr);
	else if (strcmp(type, "id") == 0)
		rc = db_subscr_get_by_id(g_hlr->dbc, atoll(id), subscr);
	else if (strcmp(type, "imei") == 0) {
		/* Verify IMEI with checksum digit */
		if (osmo_imei_str_valid(id, true)) {
			/* Cut the checksum off */
			osmo_strlcpy(imei_buf, id, sizeof(imei_buf));
			id = imei_buf;
			vty_out(vty, "%% Checksum validated and stripped for search: imei = '%s'%s", id,
				VTY_NEWLINE);
		}
		rc = db_subscr_get_by_imei(g_hlr->dbc, id, subscr);
	}
	if (rc)
		vty_out(vty, "%% No subscriber for %s = '%s'%s",
			type, id, VTY_NEWLINE);
	return rc;
}

#define SUBSCR_CMD "subscriber "
#define SUBSCR_CMD_HELP "Subscriber management commands\n"

#define SUBSCR_ID "(imsi|msisdn|id|imei) IDENT"
#define SUBSCR_ID_HELP \
	"Identify subscriber by IMSI\n" \
	"Identify subscriber by MSISDN (phone number)\n" \
	"Identify subscriber by database ID\n" \
	"Identify subscriber by IMEI\n" \
	"IMSI/MSISDN/ID/IMEI of the subscriber\n"

#define SUBSCR 		SUBSCR_CMD SUBSCR_ID " "
#define SUBSCR_HELP	SUBSCR_CMD_HELP SUBSCR_ID_HELP

#define SUBSCR_UPDATE		SUBSCR "update "
#define SUBSCR_UPDATE_HELP	SUBSCR_HELP "Set or update subscriber data\n"
#define SUBSCR_MSISDN_HELP	"Set MSISDN (phone number) of the subscriber\n"

DEFUN(subscriber_show,
      subscriber_show_cmd,
      SUBSCR "show",
      SUBSCR_HELP "Show subscriber information\n")
{
	struct hlr_subscriber subscr;
	const char *id_type = argv[0];
	const char *id = argv[1];

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	subscr_dump_full_vty(vty, &subscr);
	return CMD_SUCCESS;
}

ALIAS(subscriber_show, show_subscriber_cmd,
      "show " SUBSCR_CMD SUBSCR_ID,
      SHOW_STR SUBSCR_CMD_HELP SUBSCR_ID_HELP);

DEFUN(subscriber_create,
      subscriber_create_cmd,
      SUBSCR_CMD "imsi IDENT create",
      SUBSCR_CMD_HELP
      "Identify subscriber by IMSI\n"
      "IMSI/MSISDN/ID of the subscriber\n"
      "Create subscriber by IMSI\n")
{
	int rc;
	struct hlr_subscriber subscr;
	const char *imsi = argv[0];
	
	if (!osmo_imsi_str_valid(imsi)) {
		vty_out(vty, "%% Not a valid IMSI: %s%s", imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = db_subscr_create(g_hlr->dbc, imsi, DB_SUBSCR_FLAG_NAM_CS | DB_SUBSCR_FLAG_NAM_PS);

	if (rc) {
		if (rc == -EEXIST)
			vty_out(vty, "%% Subscriber already exists for IMSI = %s%s",
				imsi, VTY_NEWLINE);
		else
			vty_out(vty, "%% Error (rc=%d): cannot create subscriber for IMSI = %s%s",
				rc, imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = db_subscr_get_by_imsi(g_hlr->dbc, imsi, &subscr);
	vty_out(vty, "%% Created subscriber %s%s", imsi, VTY_NEWLINE);

	subscr_dump_full_vty(vty, &subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_delete,
      subscriber_delete_cmd,
      SUBSCR "delete",
      SUBSCR_HELP "Delete subscriber from database\n")
{
	struct hlr_subscriber subscr;
	int rc;
	const char *id_type = argv[0];
	const char *id = argv[1];

	/* Find out the IMSI regardless of which way the caller decided to
	 * identify the subscriber by. */
	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	rc = db_subscr_delete_by_id(g_hlr->dbc, subscr.id);
	if (rc) {
		vty_out(vty, "%% Error: Failed to remove subscriber for IMSI '%s'%s",
			subscr.imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% Deleted subscriber for IMSI '%s'%s", subscr.imsi, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(subscriber_msisdn,
      subscriber_msisdn_cmd,
      SUBSCR_UPDATE "msisdn (none|MSISDN)",
      SUBSCR_UPDATE_HELP SUBSCR_MSISDN_HELP
      "Remove MSISDN (phone number)\n"
      "New MSISDN (phone number)\n")
{
	struct hlr_subscriber subscr;
	const char *id_type = argv[0];
	const char *id = argv[1];
	const char *msisdn = argv[2];

	if (strcmp(msisdn, "none") == 0)
		msisdn = NULL;
	else {
		if (strlen(msisdn) > sizeof(subscr.msisdn) - 1) {
			vty_out(vty, "%% MSISDN is too long, max. %zu characters are allowed%s",
				sizeof(subscr.msisdn)-1, VTY_NEWLINE);
			return CMD_WARNING;
		}

		if (!osmo_msisdn_str_valid(msisdn)) {
			vty_out(vty, "%% MSISDN invalid: '%s'%s", msisdn, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	if (db_subscr_update_msisdn_by_imsi(g_hlr->dbc, subscr.imsi, msisdn)) {
		vty_out(vty, "%% Error: cannot update MSISDN for subscriber IMSI='%s'%s",
			subscr.imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (msisdn) {
		vty_out(vty, "%% Updated subscriber IMSI='%s' to MSISDN='%s'%s",
			subscr.imsi, msisdn, VTY_NEWLINE);

		if (db_subscr_get_by_msisdn(g_hlr->dbc, msisdn, &subscr) == 0)
			osmo_hlr_subscriber_update_notify(&subscr);
	} else {
		vty_out(vty, "%% Updated subscriber IMSI='%s': removed MSISDN%s",
			subscr.imsi, VTY_NEWLINE);

		osmo_hlr_subscriber_update_notify(&subscr);
	}

	return CMD_SUCCESS;
}

static bool is_hexkey_valid(struct vty *vty, const char *label,
			    const char *hex_str, int minlen, int maxlen)
{
	if (osmo_is_hexstr(hex_str, minlen * 2, maxlen * 2, true))
		return true;
	vty_out(vty, "%% Invalid value for %s: '%s'%s", label, hex_str, VTY_NEWLINE);
	return false;
}

#define AUTH_ALG_TYPES_2G "(comp128v1|comp128v2|comp128v3|xor)"
#define AUTH_ALG_TYPES_2G_HELP \
	"Use COMP128v1 algorithm\n" \
	"Use COMP128v2 algorithm\n" \
	"Use COMP128v3 algorithm\n" \
	"Use XOR algorithm\n"

#define AUTH_ALG_TYPES_3G "milenage"
#define AUTH_ALG_TYPES_3G_HELP \
	"Use Milenage algorithm\n"

#define A38_XOR_MIN_KEY_LEN	12
#define A38_XOR_MAX_KEY_LEN	16
#define A38_COMP128_KEY_LEN	16

#define MILENAGE_KEY_LEN 16

static bool auth_algo_parse(const char *alg_str, enum osmo_auth_algo *algo,
			    int *minlen, int *maxlen)
{
	if (!strcasecmp(alg_str, "none")) {
		*algo = OSMO_AUTH_ALG_NONE;
		*minlen = *maxlen = 0;
	} else if (!strcasecmp(alg_str, "comp128v1")) {
		*algo = OSMO_AUTH_ALG_COMP128v1;
		*minlen = *maxlen = A38_COMP128_KEY_LEN;
	} else if (!strcasecmp(alg_str, "comp128v2")) {
		*algo = OSMO_AUTH_ALG_COMP128v2;
		*minlen = *maxlen = A38_COMP128_KEY_LEN;
	} else if (!strcasecmp(alg_str, "comp128v3")) {
		*algo = OSMO_AUTH_ALG_COMP128v3;
		*minlen = *maxlen = A38_COMP128_KEY_LEN;
	} else if (!strcasecmp(alg_str, "xor")) {
		*algo = OSMO_AUTH_ALG_XOR;
		*minlen = A38_XOR_MIN_KEY_LEN;
		*maxlen = A38_XOR_MAX_KEY_LEN;
	} else if (!strcasecmp(alg_str, "milenage")) {
		*algo = OSMO_AUTH_ALG_MILENAGE;
		*minlen = *maxlen = MILENAGE_KEY_LEN;
	} else
		return false;
	return true;
}

DEFUN(subscriber_no_aud2g,
      subscriber_no_aud2g_cmd,
      SUBSCR_UPDATE "aud2g none",
      SUBSCR_UPDATE_HELP
      "Set 2G authentication data\n"
      "Delete 2G authentication data\n")
{
	struct hlr_subscriber subscr;
	int rc;
	const char *id_type = argv[0];
	const char *id = argv[1];
	struct sub_auth_data_str aud = {
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_NONE,
	};

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	rc = db_subscr_update_aud_by_id(g_hlr->dbc, subscr.id, &aud);

	if (rc && rc != -ENOENT) {
		vty_out(vty, "%% Error: cannot disable 2G auth data for IMSI='%s'%s",
			subscr.imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(subscriber_aud2g,
      subscriber_aud2g_cmd,
      SUBSCR_UPDATE "aud2g " AUTH_ALG_TYPES_2G " ki KI",
      SUBSCR_UPDATE_HELP
      "Set 2G authentication data\n"
      AUTH_ALG_TYPES_2G_HELP
      "Set Ki Encryption Key\n" "Ki as 32 hexadecimal characters\n")
{
	struct hlr_subscriber subscr;
	int rc;
	int minlen = 0;
	int maxlen = 0;
	const char *id_type = argv[0];
	const char *id = argv[1];
	const char *alg_type = argv[2];
	const char *ki = argv[3];
	struct sub_auth_data_str aud2g = {
		.type = OSMO_AUTH_TYPE_GSM,
		.u.gsm.ki = ki,
	};

	if (!auth_algo_parse(alg_type, &aud2g.algo, &minlen, &maxlen)) {
		vty_out(vty, "%% Unknown auth algorithm: '%s'%s", alg_type, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_hexkey_valid(vty, "KI", aud2g.u.gsm.ki, minlen, maxlen))
		return CMD_WARNING;

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	rc = db_subscr_update_aud_by_id(g_hlr->dbc, subscr.id, &aud2g);

	if (rc) {
		vty_out(vty, "%% Error: cannot set 2G auth data for IMSI='%s'%s",
			subscr.imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(subscriber_no_aud3g,
      subscriber_no_aud3g_cmd,
      SUBSCR_UPDATE "aud3g none",
      SUBSCR_UPDATE_HELP
      "Set UMTS authentication data (3G, and 2G with UMTS AKA)\n"
      "Delete 3G authentication data\n")
{
	struct hlr_subscriber subscr;
	int rc;
	const char *id_type = argv[0];
	const char *id = argv[1];
	struct sub_auth_data_str aud = {
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_NONE,
	};

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	rc = db_subscr_update_aud_by_id(g_hlr->dbc, subscr.id, &aud);

	if (rc && rc != -ENOENT) {
		vty_out(vty, "%% Error: cannot disable 3G auth data for IMSI='%s'%s",
			subscr.imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(subscriber_aud3g,
      subscriber_aud3g_cmd,
      SUBSCR_UPDATE "aud3g " AUTH_ALG_TYPES_3G
      " k K"
      " (op|opc) OP_C"
      " [ind-bitlen] [<0-28>]",
      SUBSCR_UPDATE_HELP
      "Set UMTS authentication data (3G, and 2G with UMTS AKA)\n"
      AUTH_ALG_TYPES_3G_HELP
      "Set Encryption Key K\n" "K as 32 hexadecimal characters\n"
      "Set OP key\n" "Set OPC key\n" "OP or OPC as 32 hexadecimal characters\n"
      "Set IND bit length\n" "IND bit length value (default: 5)\n")
{
	struct hlr_subscriber subscr;
	int minlen = 0;
	int maxlen = 0;
	int rc;
	const char *id_type = argv[0];
	const char *id = argv[1];
	const char *alg_type = AUTH_ALG_TYPES_3G;
	const char *k = argv[2];
	bool opc_is_op = (strcasecmp("op", argv[3]) == 0);
	const char *op_opc = argv[4];
	int ind_bitlen = argc > 6? atoi(argv[6]) : 5;
	struct sub_auth_data_str aud3g = {
		.type = OSMO_AUTH_TYPE_UMTS,
		.u.umts = {
			.k = k,
			.opc_is_op = opc_is_op,
			.opc = op_opc,
			.ind_bitlen = ind_bitlen,
		},
	};
	
	if (!auth_algo_parse(alg_type, &aud3g.algo, &minlen, &maxlen)) {
		vty_out(vty, "%% Unknown auth algorithm: '%s'%s", alg_type, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_hexkey_valid(vty, "K", aud3g.u.umts.k, minlen, maxlen))
		return CMD_WARNING;

	if (!is_hexkey_valid(vty, opc_is_op ? "OP" : "OPC", aud3g.u.umts.opc,
			     MILENAGE_KEY_LEN, MILENAGE_KEY_LEN))
		return CMD_WARNING;

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	rc = db_subscr_update_aud_by_id(g_hlr->dbc, subscr.id, &aud3g);

	if (rc) {
		vty_out(vty, "%% Error: cannot set 3G auth data for IMSI='%s'%s",
			subscr.imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(subscriber_imei,
      subscriber_imei_cmd,
      SUBSCR_UPDATE "imei (none|IMEI)",
      SUBSCR_UPDATE_HELP
      "Set IMEI of the subscriber (normally populated from MSC, no need to set this manually)\n"
      "Forget IMEI\n"
      "Set IMEI (use for debug only!)\n")
{
	struct hlr_subscriber subscr;
	const char *id_type = argv[0];
	const char *id = argv[1];
	const char *imei = argv[2];
	char imei_buf[GSM23003_IMEI_NUM_DIGITS_NO_CHK+1];

	if (strcmp(imei, "none") == 0)
		imei = NULL;
	else {
		/* Verify IMEI with checksum digit */
		if (osmo_imei_str_valid(imei, true)) {
			/* Cut the checksum off */
			osmo_strlcpy(imei_buf, imei, sizeof(imei_buf));
			imei = imei_buf;
		} else if (!osmo_imei_str_valid(imei, false)) {
			vty_out(vty, "%% IMEI invalid: '%s'%s", imei, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	if (db_subscr_update_imei_by_imsi(g_hlr->dbc, subscr.imsi, imei)) {
		vty_out(vty, "%% Error: cannot update IMEI for subscriber IMSI='%s'%s",
			subscr.imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (imei)
		vty_out(vty, "%% Updated subscriber IMSI='%s' to IMEI='%s'%s",
			subscr.imsi, imei, VTY_NEWLINE);
	else
		vty_out(vty, "%% Updated subscriber IMSI='%s': removed IMEI%s",
			subscr.imsi, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(subscriber_nam,
      subscriber_nam_cmd,
      SUBSCR_UPDATE "network-access-mode (none|cs|ps|cs+ps)",
      SUBSCR_UPDATE_HELP
      "Set Network Access Mode (NAM) of the subscriber\n"
      "Do not allow access to circuit switched or packet switched services\n"
      "Allow access to circuit switched services only\n"
      "Allow access to packet switched services only\n"
      "Allow access to both circuit and packet switched services\n")
{
	struct hlr_subscriber subscr;
	const char *id_type = argv[0];
	const char *id = argv[1];
	bool nam_cs = strstr(argv[2], "cs");
	bool nam_ps = strstr(argv[2], "ps");

	if (get_subscr_by_argv(vty, id_type, id, &subscr))
		return CMD_WARNING;

	if (nam_cs != subscr.nam_cs)
		hlr_subscr_nam(g_hlr, &subscr, nam_cs, 0);
	if (nam_ps != subscr.nam_ps)
		hlr_subscr_nam(g_hlr, &subscr, nam_ps, 1);

	return CMD_SUCCESS;
}


void hlr_vty_subscriber_init(void)
{
	install_element_ve(&subscriber_show_cmd);
	install_element_ve(&show_subscriber_cmd);
	install_element(ENABLE_NODE, &subscriber_create_cmd);
	install_element(ENABLE_NODE, &subscriber_delete_cmd);
	install_element(ENABLE_NODE, &subscriber_msisdn_cmd);
	install_element(ENABLE_NODE, &subscriber_no_aud2g_cmd);
	install_element(ENABLE_NODE, &subscriber_aud2g_cmd);
	install_element(ENABLE_NODE, &subscriber_no_aud3g_cmd);
	install_element(ENABLE_NODE, &subscriber_aud3g_cmd);
	install_element(ENABLE_NODE, &subscriber_imei_cmd);
	install_element(ENABLE_NODE, &subscriber_nam_cmd);
}
