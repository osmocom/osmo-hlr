/* OsmoHLR Control Interface implementation */

/* (C) 2017 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Max Suraev <msuraev@sysmocom.de>
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

#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <osmocom/gsm/gsm23003.h>
#include <osmocom/ctrl/ports.h>

#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/ctrl.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/hlr_vty.h>

#define SEL_BY "by-"
#define SEL_BY_IMSI SEL_BY "imsi-"
#define SEL_BY_MSISDN SEL_BY "msisdn-"
#define SEL_BY_ID SEL_BY "id-"

extern bool auth_algo_parse(const char *alg_str, enum osmo_auth_algo *algo,
			    int *minlen, int *maxlen);

#define hexdump_buf(buf) osmo_hexdump_nospc((void*)buf, sizeof(buf))

static bool startswith(const char *str, const char *start)
{
	return strncmp(str, start, strlen(start)) == 0;
}

static int _get_subscriber(struct db_context *dbc,
			   const char *by_selector,
			   struct hlr_subscriber *subscr)
{
	const char *val;
	if (startswith(by_selector, SEL_BY_IMSI)) {
		val = by_selector + strlen(SEL_BY_IMSI);
		if (!osmo_imsi_str_valid(val))
			return -EINVAL;
		return db_subscr_get_by_imsi(dbc, val, subscr);
	}
	if (startswith(by_selector, SEL_BY_MSISDN)) {
		val = by_selector + strlen(SEL_BY_MSISDN);
		if (!osmo_msisdn_str_valid(val))
			return -EINVAL;
		return db_subscr_get_by_msisdn(dbc, val, subscr);
	}
	if (startswith(by_selector, SEL_BY_ID)) {
		int64_t id;
		char *endptr;
		val = by_selector + strlen(SEL_BY_ID);
		if (*val == '+')
			return -EINVAL;
		errno = 0;
		id = strtoll(val, &endptr, 10);
		if (errno || *endptr)
			return -EINVAL;
		return db_subscr_get_by_id(dbc, id, subscr);
	}
	return -ENOTSUP;
}

static bool get_subscriber(struct db_context *dbc,
			   const char *by_selector,
			   struct hlr_subscriber *subscr,
			   struct ctrl_cmd *cmd)
{
	int rc = _get_subscriber(dbc, by_selector, subscr);
	switch (rc) {
	case 0:
		return true;
	case -ENOTSUP:
		cmd->reply = "Not a known subscriber 'by-xxx-' selector.";
		return false;
	case -EINVAL:
		cmd->reply = "Invalid value part of 'by-xxx-value' selector.";
		return false;
	case -ENOENT:
		cmd->reply = "No such subscriber.";
		return false;
	default:
		cmd->reply = "An unknown error has occurred during get_subscriber().";
		return false;
	}
}

/* Optimization: if a subscriber operation is requested by-imsi, just return
 * the IMSI right back. */
static const char *get_subscriber_imsi(struct db_context *dbc,
				       const char *by_selector,
				       struct ctrl_cmd *cmd)
{
	static struct hlr_subscriber subscr;

	if (startswith(by_selector, SEL_BY_IMSI))
		return by_selector + strlen(SEL_BY_IMSI);
	if (!get_subscriber(dbc, by_selector, &subscr, cmd))
		return NULL;
	return subscr.imsi;
}

/* printf fmt and arg to completely omit a string if it is empty. */
#define FMT_S "%s%s%s%s"
#define ARG_S(name, val) \
	(val) && *(val) ? "\n" : "", \
	(val) && *(val) ? name : "", \
	(val) && *(val) ? "\t" : "", \
	(val) && *(val) ? (val) : "" \

/* printf fmt and arg to completely omit bool of given value. */
#define FMT_BOOL "%s"
#define ARG_BOOL(name, val) \
	val ? "\n" name "\t1" : "\n" name "\t0"

static void print_subscr_info(struct ctrl_cmd *cmd,
			      struct hlr_subscriber *subscr)
{
	ctrl_cmd_reply_printf(cmd,
		"\nid\t%" PRIu64
		FMT_S
		FMT_S
		FMT_BOOL
		FMT_BOOL
		FMT_S
		FMT_S
		FMT_S
		FMT_BOOL
		FMT_BOOL
		"\nperiodic_lu_timer\t%u"
		"\nperiodic_rau_tau_timer\t%u"
		"\nlmsi\t%08x"
		,
		subscr->id,
		ARG_S("imsi", subscr->imsi),
		ARG_S("msisdn", subscr->msisdn),
		ARG_BOOL("nam_cs", subscr->nam_cs),
		ARG_BOOL("nam_ps", subscr->nam_ps),
		ARG_S("vlr_number", subscr->vlr_number),
		ARG_S("sgsn_number", subscr->sgsn_number),
		ARG_S("sgsn_address", subscr->sgsn_address),
		ARG_BOOL("ms_purged_cs", subscr->ms_purged_cs),
		ARG_BOOL("ms_purged_ps", subscr->ms_purged_ps),
		subscr->periodic_lu_timer,
		subscr->periodic_rau_tau_timer,
		subscr->lmsi
		);
}

static void print_subscr_info_aud2g(struct ctrl_cmd *cmd, struct osmo_sub_auth_data *aud)
{
	if (aud->algo == OSMO_AUTH_ALG_NONE)
		return;
	ctrl_cmd_reply_printf(cmd,
		"\naud2g.algo\t%s"
		"\naud2g.ki\t%s"
		,
		osmo_auth_alg_name(aud->algo),
		hexdump_buf(aud->u.gsm.ki));
}

static void print_subscr_info_aud3g(struct ctrl_cmd *cmd, struct osmo_sub_auth_data *aud)
{
	if (aud->algo == OSMO_AUTH_ALG_NONE)
		return;
	ctrl_cmd_reply_printf(cmd,
		"\naud3g.algo\t%s"
		"\naud3g.k\t%s"
		,
		osmo_auth_alg_name(aud->algo),
		hexdump_buf(aud->u.umts.k));
	/* hexdump uses a static string buffer, hence only one hexdump per
	 * printf(). */
	ctrl_cmd_reply_printf(cmd,
		"\naud3g.%s\t%s"
		"\naud3g.ind_bitlen\t%u"
		"\naud3g.sqn\t%" PRIu64
		,
		aud->u.umts.opc_is_op? "op" : "opc",
		hexdump_buf(aud->u.umts.opc),
		aud->u.umts.ind_bitlen,
		aud->u.umts.sqn);
}

CTRL_CMD_DEFINE_WO_NOVRF(subscr_create, "create");
static int set_subscr_create(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *imsi = cmd->value;
	int rc;

	if (!osmo_imsi_str_valid(imsi)) {
		cmd->reply = "Invalid IMSI value.";
		return CTRL_CMD_ERROR;
	}

	/* Create the subscriber in the DB */
	rc = db_subscr_create(g_hlr->dbc, imsi, DB_SUBSCR_FLAG_NAM_CS | DB_SUBSCR_FLAG_NAM_PS);
	if (rc) {
		if (rc == -EEXIST)
			cmd->reply = "Subscriber already exists.";
		else
			cmd->reply = "Cannot create subscriber.";
		return CTRL_CMD_ERROR;
	}

	LOGP(DCTRL, LOGL_INFO, "Created subscriber IMSI='%s'\n",
	     imsi);

	/* Retrieve data of newly created subscriber: */
	rc = db_subscr_get_by_imsi(hlr->dbc, imsi, &subscr);
	if (rc < 0) {
		cmd->reply = "Failed retrieving ID of newly created subscriber.";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = talloc_asprintf(cmd, "%" PRIu64, subscr.id);
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(subscr_delete, "delete");
static int set_subscr_delete(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *imsi = cmd->value;
	int rc;

	if (!osmo_imsi_str_valid(imsi)) {
		cmd->reply = "Invalid IMSI value.";
		return CTRL_CMD_ERROR;
	}

	/* Retrieve data of newly created subscriber: */
	rc = db_subscr_get_by_imsi(hlr->dbc, imsi, &subscr);
	if (rc < 0) {
		cmd->reply = "Subscriber doesn't exist.";
		return CTRL_CMD_ERROR;
	}

	/* Create the subscriber in the DB */
	rc = db_subscr_delete_by_id(g_hlr->dbc, subscr.id);
	if (rc) {
		cmd->reply = "Cannot delete subscriber.";
		return CTRL_CMD_ERROR;
	}

	LOGP(DCTRL, LOGL_INFO, "Deleted subscriber IMSI='%s'\n",
	     imsi);

	cmd->reply = talloc_asprintf(cmd, "%" PRIu64, subscr.id);
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(subscr_info, "info");
static int get_subscr_info(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	print_subscr_info(cmd, &subscr);

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(subscr_info_aud, "info-aud");
static int get_subscr_info_aud(struct ctrl_cmd *cmd, void *data)
{
	const char *imsi;
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;
	int rc;

	imsi = get_subscriber_imsi(hlr->dbc, by_selector, cmd);
	if (!imsi)
		return CTRL_CMD_ERROR;

	rc = db_get_auth_data(hlr->dbc, imsi, &aud2g, &aud3g, NULL);

	switch (rc) {
	case 0:
		break;
	case -ENOENT:
	case -ENOKEY:
		/* No auth data found, tell the print*() functions about it. */
		aud2g.algo = OSMO_AUTH_ALG_NONE;
		aud3g.algo = OSMO_AUTH_ALG_NONE;
		break;
	default:
		cmd->reply = "Error retrieving authentication data.";
		return CTRL_CMD_ERROR;
	}

	print_subscr_info_aud2g(cmd, &aud2g);
	print_subscr_info_aud3g(cmd, &aud3g);

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(subscr_info_all, "info-all");
static int get_subscr_info_all(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;
	int rc;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	rc = db_get_auth_data(hlr->dbc, subscr.imsi, &aud2g, &aud3g, NULL);

	switch (rc) {
	case 0:
		break;
	case -ENOENT:
	case -ENOKEY:
		/* No auth data found, tell the print*() functions about it. */
		aud2g.algo = OSMO_AUTH_ALG_NONE;
		aud3g.algo = OSMO_AUTH_ALG_NONE;
		break;
	default:
		cmd->reply = "Error retrieving authentication data.";
		return CTRL_CMD_ERROR;
	}

	print_subscr_info(cmd, &subscr);
	print_subscr_info_aud2g(cmd, &aud2g);
	print_subscr_info_aud3g(cmd, &aud3g);

	return CTRL_CMD_REPLY;
}

static int verify_subscr_cs_ps_enabled(struct ctrl_cmd *cmd, const char *value, void *data)
{
	if (!value || !*value
	    || (strcmp(value, "0") && strcmp(value, "1")))
		return 1;
	return 0;
}

static int get_subscr_cs_ps_enabled(struct ctrl_cmd *cmd, void *data,
				    bool is_ps)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	cmd->reply = (is_ps ? subscr.nam_ps : subscr.nam_cs)
		     ? "1" : "0";
	return CTRL_CMD_REPLY;
}

static int set_subscr_cs_ps_enabled(struct ctrl_cmd *cmd, void *data,
				    bool is_ps)
{
	const char *imsi;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;

	imsi = get_subscriber_imsi(hlr->dbc, by_selector, cmd);
	if (!imsi)
		return CTRL_CMD_ERROR;
	if (db_subscr_nam(hlr->dbc, imsi, strcmp(cmd->value, "1") == 0, is_ps))
		return CTRL_CMD_ERROR;
	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(subscr_ps_enabled, "ps-enabled");
static int verify_subscr_ps_enabled(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return verify_subscr_cs_ps_enabled(cmd, value, data);
}
static int get_subscr_ps_enabled(struct ctrl_cmd *cmd, void *data)
{
	return get_subscr_cs_ps_enabled(cmd, data, true);
}
static int set_subscr_ps_enabled(struct ctrl_cmd *cmd, void *data)
{
	return set_subscr_cs_ps_enabled(cmd, data, true);
}

CTRL_CMD_DEFINE(subscr_cs_enabled, "cs-enabled");
static int verify_subscr_cs_enabled(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return verify_subscr_cs_ps_enabled(cmd, value, data);
}
static int get_subscr_cs_enabled(struct ctrl_cmd *cmd, void *data)
{
	return get_subscr_cs_ps_enabled(cmd, data, false);
}
static int set_subscr_cs_enabled(struct ctrl_cmd *cmd, void *data)
{
	return set_subscr_cs_ps_enabled(cmd, data, false);
}

CTRL_CMD_DEFINE(subscr_msisdn, "msisdn");
static int verify_subscr_msisdn(struct ctrl_cmd *cmd, const char *value, void *data)
{
	struct hlr_subscriber subscr;
	if (!value)
		return 1;
	if (strlen(value) > sizeof(subscr.msisdn) - 1)
		return 1;
	if (strcmp(value, "none") != 0 && !osmo_msisdn_str_valid(value))
		return 1;
	return 0;
}
static int get_subscr_msisdn(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	if (strlen(subscr.msisdn) == 0)
		snprintf(subscr.msisdn, sizeof(subscr.msisdn), "none");

	cmd->reply = talloc_asprintf(cmd, "%s", subscr.msisdn);
	return CTRL_CMD_REPLY;
}
static int set_subscr_msisdn(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;
	const char *msisdn;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	if (strcmp(cmd->value, "none") == 0)
		msisdn = NULL;
	else
		msisdn = cmd->value;

	if (db_subscr_update_msisdn_by_imsi(g_hlr->dbc, subscr.imsi, msisdn)) {
		cmd->reply = "Update MSISDN failed";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* value format: <algo[,KI]> */
CTRL_CMD_DEFINE(subscr_aud2g, "aud2g");
static int verify_subscr_aud2g(struct ctrl_cmd *cmd, const char *value, void *data)
{
	if (!value)
		return 1;
	if (strcasecmp(value, "none") != 0 && !strchr(value, ','))
		return 1;
	return 0;
}
static int get_subscr_aud2g(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g_unused;
	int rc;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	rc = db_get_auth_data(hlr->dbc, subscr.imsi, &aud2g, &aud3g_unused, NULL);
	switch (rc) {
	case 0:
		break;
	case -ENOENT:
	case -ENOKEY:
		aud2g.algo = OSMO_AUTH_ALG_NONE;
		break;
	default:
		cmd->reply = "Error retrieving data from database.";
		return CTRL_CMD_ERROR;
	}

	if (aud2g.algo ==  OSMO_AUTH_ALG_NONE) {
		cmd->reply = "none";
		return CTRL_CMD_REPLY;
	}

	cmd->reply = talloc_asprintf(cmd, "%s,%s", osmo_auth_alg_name(aud2g.algo),
				     hexdump_buf(aud2g.u.gsm.ki));
	return CTRL_CMD_REPLY;
}
static int set_subscr_aud2g(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;
	char *tmp = NULL, *tok, *saveptr;
	int minlen = 0;
	int maxlen = 0;
	struct sub_auth_data_str aud2g = {
		.type = OSMO_AUTH_TYPE_GSM
	};

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	/* Parse alg_type: */
	tok = strtok_r(tmp, ",", &saveptr);
	if (!tok) {
		cmd->reply = "Invalid format";
		return CTRL_CMD_ERROR;
	}
	if (strcmp(tok, "none") == 0) {
		aud2g.algo = OSMO_AUTH_ALG_NONE;
	} else if (!auth_algo_parse(tok, &aud2g.algo, &minlen, &maxlen)) {
		cmd->reply = "Unknown auth algorithm.";
		return CTRL_CMD_ERROR;
	}

	if (aud2g.algo != OSMO_AUTH_ALG_NONE) {
		tok = strtok_r(NULL, "\0", &saveptr);
		if (!tok) {
			cmd->reply = "Invalid format.";
			return CTRL_CMD_ERROR;
		}
		aud2g.u.gsm.ki = tok;
		if (!osmo_is_hexstr(aud2g.u.gsm.ki, minlen * 2, maxlen * 2, true)) {
			cmd->reply = "Invalid KI.";
			return CTRL_CMD_ERROR;
		}
	}

	if (db_subscr_update_aud_by_id(g_hlr->dbc, subscr.id, &aud2g)) {
		cmd->reply = "Update aud2g failed.";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

/* value format: <algo[,KI,(op|opc),OP_C[,ind_bitlen]]> */
CTRL_CMD_DEFINE(subscr_aud3g, "aud3g");
static int verify_subscr_aud3g(struct ctrl_cmd *cmd, const char *value, void *data)
{
	if (!value)
		return 1;
	if (strcasecmp(value, "none") != 0 && !strchr(value, ','))
		return 1;
	return 0;
}
static int get_subscr_aud3g(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;
	struct osmo_sub_auth_data aud2g_unused;
	struct osmo_sub_auth_data aud3g;
	int rc;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	rc = db_get_auth_data(hlr->dbc, subscr.imsi, &aud2g_unused, &aud3g, NULL);
	switch (rc) {
	case 0:
		break;
	case -ENOENT:
	case -ENOKEY:
		aud3g.algo = OSMO_AUTH_ALG_NONE;
		break;
	default:
		cmd->reply = "Error retrieving data from database.";
		return CTRL_CMD_ERROR;
	}

	if (aud3g.algo ==  OSMO_AUTH_ALG_NONE) {
		cmd->reply = "none";
		return CTRL_CMD_REPLY;
	}

	cmd->reply = talloc_asprintf(cmd, "%s,%s,%s,%s,%u", osmo_auth_alg_name(aud3g.algo),
				     osmo_hexdump_nospc_c(cmd, aud3g.u.umts.k, sizeof(aud3g.u.umts.k)),
				     aud3g.u.umts.opc_is_op ? "OP" : "OPC",
				     osmo_hexdump_nospc_c(cmd, aud3g.u.umts.opc, sizeof(aud3g.u.umts.opc)),
				     aud3g.u.umts.ind_bitlen);
	return CTRL_CMD_REPLY;
}
static int set_subscr_aud3g(struct ctrl_cmd *cmd, void *data)
{
	struct hlr_subscriber subscr;
	struct hlr *hlr = data;
	const char *by_selector = cmd->node;
	char *tmp = NULL, *tok, *saveptr;
	int minlen = 0;
	int maxlen = 0;
	struct sub_auth_data_str aud3g = {
		.type = OSMO_AUTH_TYPE_UMTS,
		.u.umts = {
			.ind_bitlen = 5,
		},
	};
	bool ind_bitlen_present;

	if (!get_subscriber(hlr->dbc, by_selector, &subscr, cmd))
		return CTRL_CMD_ERROR;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	/* Parse alg_type: */
	tok = strtok_r(tmp, ",", &saveptr);
	if (!tok) {
		cmd->reply = "Invalid format.";
		return CTRL_CMD_ERROR;
	}
	if (strcmp(tok, "none") == 0) {
		aud3g.algo = OSMO_AUTH_ALG_NONE;
	} else if (!auth_algo_parse(tok, &aud3g.algo, &minlen, &maxlen)) {
		cmd->reply = "Unknown auth algorithm.";
		return CTRL_CMD_ERROR;
	}

	if (aud3g.algo != OSMO_AUTH_ALG_NONE) {
		/* Parse K */
		tok = strtok_r(NULL, ",", &saveptr);
		if (!tok) {
			cmd->reply = "Invalid format.";
			return CTRL_CMD_ERROR;
		}
		aud3g.u.umts.k = tok;
		if (!osmo_is_hexstr(aud3g.u.umts.k, minlen * 2, maxlen * 2, true)) {
			cmd->reply = "Invalid KI.";
			return CTRL_CMD_ERROR;
		}

		/* Parse OP/OPC choice */
		tok = strtok_r(NULL, ",", &saveptr);
		if (!tok) {
			cmd->reply = "Invalid format.";
			return CTRL_CMD_ERROR;
		}
		if (strcasecmp(tok, "op") == 0) {
			aud3g.u.umts.opc_is_op = true;
		} else if (strcasecmp(tok, "opc") == 0) {
			aud3g.u.umts.opc_is_op = false;
		} else {
			cmd->reply = "Invalid format.";
			return CTRL_CMD_ERROR;
		}

		/* Parse OP/OPC value */
		ind_bitlen_present = !!strchr(saveptr, ',');
		tok = strtok_r(NULL, ind_bitlen_present ? "," : "\0", &saveptr);
		if (!tok) {
			cmd->reply = "Invalid format.";
			return CTRL_CMD_ERROR;
		}

		aud3g.u.umts.opc = tok;
		if (!osmo_is_hexstr(aud3g.u.umts.opc, MILENAGE_KEY_LEN * 2, MILENAGE_KEY_LEN * 2, true)) {
			cmd->reply = talloc_asprintf(cmd, "Invalid OP/OPC.");
			return CTRL_CMD_ERROR;
		}

		if (ind_bitlen_present) {
			/* Parse bitlen_ind */
			tok = strtok_r(NULL, "\0", &saveptr);
			if (!tok || tok[0] == '\0') {
				cmd->reply = "Invalid format.";
				return CTRL_CMD_ERROR;
			}
			aud3g.u.umts.ind_bitlen = atoi(tok);
		}
	}

	if (db_subscr_update_aud_by_id(g_hlr->dbc, subscr.id, &aud3g)) {
		cmd->reply = "Update aud3g failed.";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

static int hlr_ctrl_node_lookup(void *data, vector vline, int *node_type,
				void **node_data, int *i)
{
	const char *token = vector_slot(vline, *i);

	switch (*node_type) {
	case CTRL_NODE_ROOT:
		if (strcmp(token, "subscriber") != 0)
			return 0;
		*node_data = NULL;
		*node_type = CTRL_NODE_SUBSCR;
		break;
	case CTRL_NODE_SUBSCR:
		if (!startswith(token, "by-"))
			return 0;
		*node_data = (void*)token;
		*node_type = CTRL_NODE_SUBSCR_BY;
		break;
	default:
		return 0;
	}

	return 1;
}

static int hlr_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR, &cmd_subscr_create);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR, &cmd_subscr_delete);

	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_info);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_info_aud);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_info_all);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_ps_enabled);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_cs_enabled);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_msisdn);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_aud2g);
	rc |= ctrl_cmd_install(CTRL_NODE_SUBSCR_BY, &cmd_subscr_aud3g);

	return rc;
}

struct ctrl_handle *hlr_controlif_setup(struct hlr *hlr)
{
	int rc;
	struct ctrl_handle *hdl = ctrl_interface_setup_dynip2(hlr,
							      hlr->ctrl_bind_addr,
							      OSMO_CTRL_PORT_HLR,
							      hlr_ctrl_node_lookup,
							      _LAST_CTRL_NODE_HLR);
	if (!hdl)
		return NULL;

	rc = hlr_ctrl_cmds_install();
	if (rc) /* FIXME: close control interface? */
		return NULL;

	return hdl;
}
