/* OsmoHLR VTY implementation */

/* (C) 2016 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 * (C) 2018 Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * (C) 2018 Harald Welte <laforge@gnumonks.org>
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
#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/apn.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/abis/ipa.h>

#include <osmocom/hlr/db.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/hlr_vty.h>
#include <osmocom/hlr/hlr_vty_subscr.h>
#include <osmocom/hlr/hlr_ussd.h>
#include <osmocom/hlr/hlr_sms.h>
#include <osmocom/hlr/gsup_server.h>

static const struct value_string gsm48_gmm_cause_vty_names[] = {
	{ GMM_CAUSE_IMSI_UNKNOWN,	"imsi-unknown" },
	{ GMM_CAUSE_ILLEGAL_MS,		"illegal-ms" },
	{ GMM_CAUSE_PLMN_NOTALLOWED,	"plmn-not-allowed" },
	{ GMM_CAUSE_LA_NOTALLOWED,	"la-not-allowed" },
	{ GMM_CAUSE_ROAMING_NOTALLOWED,	"roaming-not-allowed" },
	{ GMM_CAUSE_NO_SUIT_CELL_IN_LA,	"no-suitable-cell-in-la" },
	{ GMM_CAUSE_NET_FAIL,		"net-fail" },
	{ GMM_CAUSE_CONGESTION,		"congestion" },
	{ GMM_CAUSE_GSM_AUTH_UNACCEPT,	"auth-unacceptable" },
	{ GMM_CAUSE_PROTO_ERR_UNSPEC,	"proto-error-unspec" },
	{ 0, NULL },
};

/* TS 24.008 4.4.4.7 */
static const struct value_string gsm48_gmm_cause_vty_descs[] = {
	{ GMM_CAUSE_IMSI_UNKNOWN,	" #02: (IMSI unknown in HLR)" },
	{ GMM_CAUSE_ILLEGAL_MS,		" #03  (Illegal MS)" },
	{ GMM_CAUSE_PLMN_NOTALLOWED,	" #11: (PLMN not allowed)" },
	{ GMM_CAUSE_LA_NOTALLOWED,	" #12: (Location Area not allowed)" },
	{ GMM_CAUSE_ROAMING_NOTALLOWED,	" #13: (Roaming not allowed in this location area)" },
	{ GMM_CAUSE_NO_SUIT_CELL_IN_LA,	" #15: (No Suitable Cells In Location Area [continue search in PLMN])." },
	{ GMM_CAUSE_NET_FAIL,		" #17: (Network Failure)" },
	{ GMM_CAUSE_CONGESTION,		" #22: (Congestion)" },
	{ GMM_CAUSE_GSM_AUTH_UNACCEPT,	" #23: (GSM authentication unacceptable [UMTS])" },
	{ GMM_CAUSE_PROTO_ERR_UNSPEC,	"#111: (Protocol error, unspecified)" },
	{ 0, NULL },
};


struct cmd_node hlr_node = {
	HLR_NODE,
	"%s(config-hlr)# ",
	1,
};

DEFUN(cfg_hlr,
      cfg_hlr_cmd,
      "hlr",
      "Configure the HLR")
{
	vty->node = HLR_NODE;
	return CMD_SUCCESS;
}

struct cmd_node gsup_node = {
	GSUP_NODE,
	"%s(config-hlr-gsup)# ",
	1,
};

DEFUN(cfg_gsup,
      cfg_gsup_cmd,
      "gsup",
      "Configure GSUP options")
{
	vty->node = GSUP_NODE;
	return CMD_SUCCESS;
}

struct cmd_node ps_node = {
	PS_NODE,
	"%s(config-hlr-ps)# ",
	1,
};

DEFUN(cfg_ps,
      cfg_ps_cmd,
      "ps",
      "Configure the PS options")
{
	vty->node = PS_NODE;
	return CMD_SUCCESS;
}

struct cmd_node ps_pdp_profiles_node = {
	PS_PDP_PROFILES_NODE,
	"%s(config-hlr-ps-pdp-profiles)# ",
	1,
};

DEFUN(cfg_ps_pdp_profiles,
      cfg_ps_pdp_profiles_cmd,
      "pdp-profiles default",
      "Define a PDP profile set.\n"
      "Define the global default profile.\n")
{
	g_hlr->ps.pdp_profile.enabled = true;

	vty->node = PS_PDP_PROFILES_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_ps_pdp_profiles,
      cfg_no_ps_pdp_profiles_cmd,
      "no pdp-profiles default",
      NO_STR
      "Delete PDP profile.\n"
      "Unique identifier for this PDP profile set.\n")
{
	g_hlr->ps.pdp_profile.enabled = false;
	return CMD_SUCCESS;
}



struct cmd_node ps_pdp_profiles_profile_node = {
	PS_PDP_PROFILES_PROFILE_NODE,
	"%s(config-hlr-ps-pdp-profile)# ",
	1,
};


/* context_id == 0 means the slot is free */
struct osmo_gsup_pdp_info *get_pdp_profile(uint8_t context_id)
{
	for (int i = 0; i < OSMO_GSUP_MAX_NUM_PDP_INFO; i++) {
		struct osmo_gsup_pdp_info *info = &g_hlr->ps.pdp_profile.pdp_infos[i];
		if (info->context_id == context_id)
			return info;
	}

	return NULL;
}

struct osmo_gsup_pdp_info *create_pdp_profile(uint8_t context_id)
{
	struct osmo_gsup_pdp_info *info = get_pdp_profile(0);
	if (!info)
		return NULL;

	memset(info, 0, sizeof(*info));
	info->context_id = context_id;
	info->have_info = 1;

	g_hlr->ps.pdp_profile.num_pdp_infos++;
	return info;
}

void destroy_pdp_profile(struct osmo_gsup_pdp_info *info)
{
	info->context_id = 0;
	if (info->apn_enc)
		talloc_free((void *) info->apn_enc);

	g_hlr->ps.pdp_profile.num_pdp_infos--;
	memset(info, 0, sizeof(*info));
}

DEFUN(cfg_ps_pdp_profiles_profile,
      cfg_ps_pdp_profiles_profile_cmd,
      "profile <1-10>",
      "Configure a PDP profile\n"
      "Unique PDP context identifier. The lowest profile will be used as default context.\n")
{
	struct osmo_gsup_pdp_info *info;
	uint8_t context_id = atoi(argv[0]);

	info = get_pdp_profile(context_id);
	if (!info) {
		info = create_pdp_profile(context_id);
		if (!info) {
			vty_out(vty, "Failed to create profile %d!%s", context_id, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	vty->node = PS_PDP_PROFILES_PROFILE_NODE;
	vty->index = info;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_ps_pdp_profiles_profile,
      cfg_no_ps_pdp_profiles_profile_cmd,
      "no profile <1-10>",
      NO_STR
      "Delete a PDP profile\n"
      "Unique PDP context identifier. The lowest profile will be used as default context.\n")
{
	struct osmo_gsup_pdp_info *info;
	uint8_t context_id = atoi(argv[0]);

	info = get_pdp_profile(context_id);
	if (info)
		destroy_pdp_profile(info);

	return CMD_SUCCESS;
}

DEFUN(cfg_ps_pdp_profile_apn, cfg_ps_pdp_profile_apn_cmd,
	"apn ID",
	"Configure the APN.\n"
	"APN name or * for wildcard apn.\n")
{
	struct osmo_gsup_pdp_info *info = vty->index;
	const char *apn_name = argv[0];

	/* apn encoded takes one more byte than strlen() */
	size_t apn_enc_len = strlen(apn_name) + 1;
	uint8_t *apn_enc;
	int ret;

	if (apn_enc_len > APN_MAXLEN) {
		vty_out(vty, "APN name is too long '%s'. Max is %d!%s", apn_name, APN_MAXLEN, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	info->apn_enc = apn_enc = (uint8_t *) talloc_zero_size(g_hlr, apn_enc_len);
	ret = info->apn_enc_len = osmo_apn_from_str(apn_enc, apn_enc_len, apn_name);
	if (ret < 0) {
		talloc_free(apn_enc);
		info->apn_enc = NULL;
		info->apn_enc_len = 0;
		vty_out(vty, "Invalid APN name %s!", apn_name);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_no_ps_pdp_profile_apn, cfg_no_ps_pdp_profile_apn_cmd,
      "no apn",
      NO_STR
      "Delete the APN.\n")
{
	struct osmo_gsup_pdp_info *info = vty->index;
	if (info->apn_enc) {
		talloc_free((void *) info->apn_enc);
		info->apn_enc = NULL;
		info->apn_enc_len = 0;
	}

	return CMD_SUCCESS;
}

static void config_write_subscr_create_on_demand(struct vty *vty)
{
	const uint8_t flags = g_hlr->subscr_create_on_demand.flags;
	const char *flags_str;

	switch (g_hlr->subscr_create_on_demand.mode) {
	case SUBSCR_COD_MODE_MSISDN_FROM_IMSI:
		vty_out(vty, " subscriber-create-on-demand msisdn-from-imsi");
		break;
	case SUBSCR_COD_MODE_RAND_MSISDN:
		vty_out(vty, " subscriber-create-on-demand %u",
			g_hlr->subscr_create_on_demand.rand_msisdn_len);
		break;
	case SUBSCR_COD_MODE_NO_MSISDN:
		vty_out(vty, " subscriber-create-on-demand no-msisdn");
		break;
	case SUBSCR_COD_MODE_DISABLED:
	default:
		vty_out(vty, " no subscriber-create-on-demand%s", VTY_NEWLINE);
		return;
	}

	if ((flags & DB_SUBSCR_FLAG_NAM_CS) && (flags & DB_SUBSCR_FLAG_NAM_PS))
		flags_str = "cs+ps";
	else if (flags & DB_SUBSCR_FLAG_NAM_CS)
		flags_str = "cs";
	else if (flags & DB_SUBSCR_FLAG_NAM_PS)
		flags_str = "ps";
	else
		flags_str = "none";
	vty_out(vty, " %s%s", flags_str, VTY_NEWLINE);
}


static int config_write_hlr(struct vty *vty)
{
	vty_out(vty, "hlr%s", VTY_NEWLINE);

	vty_out(vty, " reject-cause not-found %s%s",
		get_value_string_or_null(gsm48_gmm_cause_vty_names,
					 (uint32_t) g_hlr->reject_cause), VTY_NEWLINE);
	vty_out(vty, " reject-cause no-proxy %s%s",
		get_value_string_or_null(gsm48_gmm_cause_vty_names,
					 (uint32_t) g_hlr->no_proxy_reject_cause), VTY_NEWLINE);
	if (g_hlr->store_imei)
		vty_out(vty, " store-imei%s", VTY_NEWLINE);
	if (g_hlr->db_file_path && strcmp(g_hlr->db_file_path, HLR_DEFAULT_DB_FILE_PATH))
		vty_out(vty, " database %s%s", g_hlr->db_file_path, VTY_NEWLINE);
	config_write_subscr_create_on_demand(vty);
	return CMD_SUCCESS;
}

static int config_write_hlr_gsup(struct vty *vty)
{
	vty_out(vty, " gsup%s", VTY_NEWLINE);
	if (g_hlr->gsup_bind_addr)
		vty_out(vty, "  bind ip %s%s", g_hlr->gsup_bind_addr, VTY_NEWLINE);
	if (g_hlr->gsup_unit_name.serno)
		vty_out(vty, "  ipa-name %s%s", g_hlr->gsup_unit_name.serno, VTY_NEWLINE);
	return CMD_SUCCESS;
}

static int config_write_hlr_ps(struct vty *vty)
{
	vty_out(vty, " ps%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

static int config_write_hlr_ps_pdp_profiles(struct vty *vty)
{
	char apn[APN_MAXLEN + 1] = {};

	if (!g_hlr->ps.pdp_profile.enabled)
		return CMD_SUCCESS;

	vty_out(vty, "  pdp-profiles default%s", VTY_NEWLINE);
	for (int i = 0; i < g_hlr->ps.pdp_profile.num_pdp_infos; i++) {
		struct osmo_gsup_pdp_info *pdp_info = &g_hlr->ps.pdp_profile.pdp_infos[i];
		if (!pdp_info->context_id)
			continue;

		vty_out(vty, "   profile %d%s", pdp_info->context_id, VTY_NEWLINE);
		if (!pdp_info->have_info)
			continue;

		if (pdp_info->apn_enc && pdp_info->apn_enc_len) {
			osmo_apn_to_str(apn, pdp_info->apn_enc, pdp_info->apn_enc_len);
			vty_out(vty, "    apn %s%s", apn, VTY_NEWLINE);
		}
	}
	return CMD_SUCCESS;
}

static void show_one_conn(struct vty *vty, const struct osmo_gsup_conn *conn)
{
	const struct ipa_server_conn *isc = conn->conn;
	char *name;
	int rc;

	rc = osmo_gsup_conn_ccm_get(conn, (uint8_t **) &name, IPAC_IDTAG_SERNR);
	OSMO_ASSERT(rc);

	vty_out(vty, " '%s' from %s:%5u, CS=%u, PS=%u%s",
		name, isc->addr, isc->port, conn->supports_cs, conn->supports_ps,
		VTY_NEWLINE);
}

DEFUN(show_gsup_conn, show_gsup_conn_cmd,
	"show gsup-connections",
	SHOW_STR "GSUP Connections from VLRs, SGSNs, EUSEs\n")
{
	struct osmo_gsup_server *gs = g_hlr->gs;
	struct osmo_gsup_conn *conn;

	llist_for_each_entry(conn, &gs->clients, list)
		show_one_conn(vty, conn);

	return CMD_SUCCESS;
}

DEFUN(cfg_hlr_gsup_bind_ip,
      cfg_hlr_gsup_bind_ip_cmd,
      "bind ip A.B.C.D",
      "Listen/Bind related socket option\n"
      IP_STR
      "IPv4 Address to bind the GSUP interface to\n")
{
	if(g_hlr->gsup_bind_addr)
		talloc_free(g_hlr->gsup_bind_addr);
	g_hlr->gsup_bind_addr = talloc_strdup(g_hlr, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_hlr_gsup_ipa_name,
      cfg_hlr_gsup_ipa_name_cmd,
      "ipa-name NAME",
      "Set the IPA name of this HLR, for proxying to remote HLRs\n"
      "A globally unique name for this HLR. For example: PLMN + redundancy server number: HLR-901-70-0. "
      "This name is used for GSUP routing and must be set if multiple HLRs interconnect (e.g. mslookup "
      "for Distributed GSM).\n")
{
	if (vty->type != VTY_FILE) {
		vty_out(vty, "gsup/ipa-name: The GSUP IPA name cannot be changed at run-time; "
			"It can only be set in the configuration file.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hlr->gsup_unit_name.serno = talloc_strdup(g_hlr, argv[0]);
	return CMD_SUCCESS;
}

/***********************************************************************
 * USSD Entity
 ***********************************************************************/

#define USSD_STR "USSD Configuration\n"
#define UROUTE_STR "Routing Configuration\n"
#define PREFIX_STR "Prefix-Matching Route\n" "USSD Prefix\n"

#define INT_CHOICE "(own-msisdn|own-imsi|test-idle|get-ran)"
#define INT_STR "Internal USSD Handler\n" \
		"Respond with subscribers' own MSISDN\n" \
		"Respond with subscribers' own IMSI\n" \
		"Keep the session idle (useful for testing)\n" \
		"Respond with available RAN types\n"

#define EXT_STR "External USSD Handler\n" \
		"Name of External USSD Handler (IPA CCM ID)\n"

DEFUN(cfg_ussd_route_pfx_int, cfg_ussd_route_pfx_int_cmd,
	"ussd route prefix PREFIX internal " INT_CHOICE,
	USSD_STR UROUTE_STR PREFIX_STR INT_STR)
{
	const struct hlr_iuse *iuse = iuse_find(argv[1]);
	struct hlr_ussd_route *rt = ussd_route_find_prefix(g_hlr, argv[0]);
	if (rt) {
		vty_out(vty, "%% Cannot add [another?] route for prefix %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	ussd_route_prefix_alloc_int(g_hlr, argv[0], iuse);

	return CMD_SUCCESS;
}

DEFUN(cfg_ussd_route_pfx_ext, cfg_ussd_route_pfx_ext_cmd,
	"ussd route prefix PREFIX external EUSE",
	USSD_STR UROUTE_STR PREFIX_STR EXT_STR)
{
	struct hlr_euse *euse = euse_find(g_hlr, argv[1]);
	struct hlr_ussd_route *rt = ussd_route_find_prefix(g_hlr, argv[0]);
	if (rt) {
		vty_out(vty, "%% Cannot add [another?] route for prefix %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!euse) {
		vty_out(vty, "%% Cannot find euse '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	ussd_route_prefix_alloc_ext(g_hlr, argv[0], euse);

	return CMD_SUCCESS;
}

DEFUN(cfg_ussd_no_route_pfx, cfg_ussd_no_route_pfx_cmd,
	"no ussd route prefix PREFIX",
	NO_STR USSD_STR UROUTE_STR PREFIX_STR)
{
	struct hlr_ussd_route *rt = ussd_route_find_prefix(g_hlr, argv[0]);
	if (!rt) {
		vty_out(vty, "%% Cannot find route for prefix %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	ussd_route_del(rt);

	return CMD_SUCCESS;
}

DEFUN(cfg_ussd_defaultroute, cfg_ussd_defaultroute_cmd,
	"ussd default-route external EUSE",
	USSD_STR "Configure default-route for all USSD to unknown destinations\n"
	EXT_STR)
{
	struct hlr_euse *euse;

	euse = euse_find(g_hlr, argv[0]);
	if (!euse) {
		vty_out(vty, "%% Cannot find EUSE %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (g_hlr->euse_default != euse) {
		vty_out(vty, "Switching default route from %s to %s%s",
			g_hlr->euse_default ? g_hlr->euse_default->name : "<none>",
			euse->name, VTY_NEWLINE);
		g_hlr->euse_default = euse;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_ussd_no_defaultroute, cfg_ussd_no_defaultroute_cmd,
	"no ussd default-route",
	NO_STR USSD_STR "Remove the default-route for all USSD to unknown destinations\n")
{
	g_hlr->euse_default = NULL;

	return CMD_SUCCESS;
}

DEFUN(cfg_database, cfg_database_cmd,
	"database PATH",
	"Set the path to the HLR database file\n"
	"Relative or absolute file system path to the database file (default is '" HLR_DEFAULT_DB_FILE_PATH "')\n")
{
	osmo_talloc_replace_string(g_hlr, &g_hlr->db_file_path, argv[0]);
	return CMD_SUCCESS;
}

struct cmd_node euse_node = {
	EUSE_NODE,
	"%s(config-hlr-euse)# ",
	1,
};

DEFUN(cfg_euse, cfg_euse_cmd,
	"euse NAME",
	"Configure a particular External USSD Entity\n"
	"Alphanumeric name of the External USSD Entity\n")
{
	struct hlr_euse *euse;
	const char *id = argv[0];

	euse = euse_find(g_hlr, id);
	if (!euse) {
		euse = euse_alloc(g_hlr, id);
		if (!euse)
			return CMD_WARNING;
	}
	vty->index = euse;
	vty->index_sub = &euse->description;
	vty->node = EUSE_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_euse, cfg_no_euse_cmd,
	"no euse NAME",
	NO_STR "Remove a particular External USSD Entity\n"
	"Alphanumeric name of the External USSD Entity\n")
{
	struct hlr_euse *euse = euse_find(g_hlr, argv[0]);
	if (!euse) {
		vty_out(vty, "%% Cannot remove non-existent EUSE %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (g_hlr->euse_default == euse) {
		vty_out(vty, "%% Cannot remove EUSE %s, it is the default route%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	euse_del(euse);
	return CMD_SUCCESS;
}

static void dump_one_euse(struct vty *vty, struct hlr_euse *euse)
{
	vty_out(vty, " euse %s%s", euse->name, VTY_NEWLINE);
}

static int config_write_euse(struct vty *vty)
{
	struct hlr_euse *euse;
	struct hlr_ussd_route *rt;

	llist_for_each_entry(euse, &g_hlr->euse_list, list)
		dump_one_euse(vty, euse);

	llist_for_each_entry(rt, &g_hlr->ussd_routes, list) {
		vty_out(vty, " ussd route prefix %s %s %s%s", rt->prefix,
			rt->is_external ? "external" : "internal",
			rt->is_external ? rt->u.euse->name : rt->u.iuse->name,
			VTY_NEWLINE);
	}

	if (g_hlr->euse_default)
		vty_out(vty, " ussd default-route external %s%s", g_hlr->euse_default->name, VTY_NEWLINE);

	if (g_hlr->ncss_guard_timeout != NCSS_GUARD_TIMEOUT_DEFAULT)
		vty_out(vty, " ncss-guard-timeout %i%s",
			g_hlr->ncss_guard_timeout, VTY_NEWLINE);

	return 0;
}

DEFUN(cfg_ncss_guard_timeout, cfg_ncss_guard_timeout_cmd,
	"ncss-guard-timeout <0-255>",
	"Set guard timer for NCSS (call independent SS) session activity\n"
	"Guard timer value (sec.), or 0 to disable")
{
	g_hlr->ncss_guard_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

/***********************************************************************
 * Routing of SM-RL to GSUP-attached SMSCs
 ***********************************************************************/

#define SMSC_STR "Configuration of GSUP routing to SMSCs\n"

struct cmd_node smsc_node = {
	SMSC_NODE,
	"%s(config-hlr-smsc)# ",
	1,
};

DEFUN(cfg_smsc_entity, cfg_smsc_entity_cmd,
	"smsc entity NAME",
	SMSC_STR
	"Configure a particular external SMSC\n"
	"IPA name of the external SMSC\n")
{
	struct hlr_smsc *smsc;
	const char *id = argv[0];

	smsc = smsc_find(g_hlr, id);
	if (!smsc) {
		smsc = smsc_alloc(g_hlr, id);
		if (!smsc)
			return CMD_WARNING;
	}
	vty->index = smsc;
	vty->index_sub = &smsc->description;
	vty->node = SMSC_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_smsc_entity, cfg_no_smsc_entity_cmd,
	"no smsc entity NAME",
	NO_STR SMSC_STR "Remove a particular external SMSC\n"
	"IPA name of the external SMSC\n")
{
	struct hlr_smsc *smsc = smsc_find(g_hlr, argv[0]);
	if (!smsc) {
		vty_out(vty, "%% Cannot remove non-existent SMSC %s%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (g_hlr->smsc_default == smsc) {
		vty_out(vty,
			"%% Cannot remove SMSC %s, it is the default route%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	smsc_free(smsc);
	return CMD_SUCCESS;
}

DEFUN(cfg_smsc_route, cfg_smsc_route_cmd,
	"smsc route NUMBER NAME",
	SMSC_STR
	"Configure GSUP route to a particular SMSC\n"
	"Numeric address of this SMSC, must match EF.SMSP programming in SIMs\n"
	"IPA name of the external SMSC\n")
{
	struct hlr_smsc *smsc = smsc_find(g_hlr, argv[1]);
	struct hlr_smsc_route *rt = smsc_route_find(g_hlr, argv[0]);
	if (rt) {
		vty_out(vty,
			"%% Cannot add [another?] route for SMSC address %s%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!smsc) {
		vty_out(vty, "%% Cannot find SMSC '%s'%s", argv[1],
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	smsc_route_alloc(g_hlr, argv[0], smsc);

	return CMD_SUCCESS;
}

DEFUN(cfg_no_smsc_route, cfg_no_smsc_route_cmd,
	"no smsc route NUMBER",
	NO_STR SMSC_STR "Remove GSUP route to a particular SMSC\n"
	"Numeric address of the SMSC\n")
{
	struct hlr_smsc_route *rt = smsc_route_find(g_hlr, argv[0]);
	if (!rt) {
		vty_out(vty, "%% Cannot find route for SMSC address %s%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	smsc_route_free(rt);

	return CMD_SUCCESS;
}

DEFUN(cfg_smsc_defroute, cfg_smsc_defroute_cmd,
	"smsc default-route NAME",
	SMSC_STR
	"Configure default SMSC route for unknown SMSC numeric addresses\n"
	"IPA name of the external SMSC\n")
{
	struct hlr_smsc *smsc;

	smsc = smsc_find(g_hlr, argv[0]);
	if (!smsc) {
		vty_out(vty, "%% Cannot find SMSC %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (g_hlr->smsc_default != smsc) {
		vty_out(vty, "Switching default route from %s to %s%s",
			g_hlr->smsc_default ? g_hlr->smsc_default->name : "<none>",
			smsc->name, VTY_NEWLINE);
		g_hlr->smsc_default = smsc;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_no_smsc_defroute, cfg_no_smsc_defroute_cmd,
	"no smsc default-route",
	NO_STR SMSC_STR
	"Remove default SMSC route for unknown SMSC numeric addresses\n")
{
	g_hlr->smsc_default = NULL;

	return CMD_SUCCESS;
}

static void dump_one_smsc(struct vty *vty, struct hlr_smsc *smsc)
{
	vty_out(vty, " smsc entity %s%s", smsc->name, VTY_NEWLINE);
}

static int config_write_smsc(struct vty *vty)
{
	struct hlr_smsc *smsc;
	struct hlr_smsc_route *rt;

	llist_for_each_entry(smsc, &g_hlr->smsc_list, list)
		dump_one_smsc(vty, smsc);

	llist_for_each_entry(rt, &g_hlr->smsc_routes, list) {
		vty_out(vty, " smsc route %s %s%s", rt->num_addr,
			rt->smsc->name, VTY_NEWLINE);
	}

	if (g_hlr->smsc_default)
		vty_out(vty, " smsc default-route %s%s",
			g_hlr->smsc_default->name, VTY_NEWLINE);

	return 0;
}

DEFUN(cfg_reject_cause, cfg_reject_cause_cmd,
      "reject-cause TYPE CAUSE", "") /* Dynamically Generated */
{
	int cause_code = get_string_value(gsm48_gmm_cause_vty_names, argv[1]);
	OSMO_ASSERT(cause_code >= 0);

	if (strcmp(argv[0], "not-found") == 0)
		g_hlr->reject_cause = (enum gsm48_gmm_cause) cause_code;
	if (strcmp(argv[0], "no-proxy") == 0)
		g_hlr->no_proxy_reject_cause = (enum gsm48_gmm_cause) cause_code;

	return CMD_SUCCESS;
}

DEFUN(cfg_store_imei, cfg_store_imei_cmd,
	"store-imei",
	"Save the IMEI in the database when receiving Check IMEI requests. Note that an MSC does not necessarily send"
	" Check IMEI requests (for OsmoMSC, you may want to set 'check-imei-rqd 1').")
{
	g_hlr->store_imei = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_store_imei, cfg_no_store_imei_cmd,
	"no store-imei",
	"Do not save the IMEI in the database, when receiving Check IMEI requests.")
{
	g_hlr->store_imei = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_subscr_create_on_demand, cfg_subscr_create_on_demand_cmd,
	"subscriber-create-on-demand (no-msisdn|msisdn-from-imsi|<3-15>) (none|cs|ps|cs+ps)",
	"Make a new record when a subscriber is first seen.\n"
	"Do not automatically assign MSISDN.\n"
	"Assign MSISDN identical to subscriber's IMSI.\n"
	"Length of an automatically assigned MSISDN.\n"
	"Do not allow any NAM (Network Access Mode) by default.\n"
	"Allow access to circuit switched NAM by default.\n"
	"Allow access to packet switched NAM by default.\n"
	"Allow access to circuit and packet switched NAM by default.\n")
{
	enum subscr_create_on_demand_mode mode;
	unsigned int rand_msisdn_len = 0;
	uint8_t flags = 0x00;

	if (strcmp(argv[0], "no-msisdn") == 0) {
		mode = SUBSCR_COD_MODE_NO_MSISDN;
	} else if (strcmp(argv[0], "msisdn-from-imsi") == 0) {
		mode = SUBSCR_COD_MODE_MSISDN_FROM_IMSI;
	} else { /* random MSISDN */
		mode = SUBSCR_COD_MODE_RAND_MSISDN;
		rand_msisdn_len = atoi(argv[0]);
	}

	if (strstr(argv[1], "cs"))
		flags |= DB_SUBSCR_FLAG_NAM_CS;
	if (strstr(argv[1], "ps"))
		flags |= DB_SUBSCR_FLAG_NAM_PS;

	g_hlr->subscr_create_on_demand.mode = mode;
	g_hlr->subscr_create_on_demand.rand_msisdn_len = rand_msisdn_len;
	g_hlr->subscr_create_on_demand.flags = flags;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_subscr_create_on_demand, cfg_no_subscr_create_on_demand_cmd,
	"no subscriber-create-on-demand",
	"Do not make a new record when a subscriber is first seen.\n")
{
	g_hlr->subscr_create_on_demand.mode = SUBSCR_COD_MODE_DISABLED;
	return CMD_SUCCESS;
}

/***********************************************************************
 * Common Code
 ***********************************************************************/

int hlr_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case GSUP_NODE:
	case EUSE_NODE:
		vty->node = HLR_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	default:
	case HLR_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case CONFIG_NODE:
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		break;
	}

	return vty->node;
}

int hlr_vty_is_config_node(struct vty *vty, int node)
{
	switch (node) {
	/* add items that are not config */
	case CONFIG_NODE:
		return 0;

	default:
		return 1;
	}
}

void hlr_vty_init(void *hlr_ctx)
{
	cfg_reject_cause_cmd.string =
		vty_cmd_string_from_valstr(hlr_ctx,
					   gsm48_gmm_cause_vty_names,
					   "reject-cause (not-found|no-proxy) (", "|", ")",
					   VTY_DO_LOWER);

	cfg_reject_cause_cmd.doc =
		vty_cmd_string_from_valstr(hlr_ctx,
					   gsm48_gmm_cause_vty_descs,
					   "GSUP/GMM cause to be sent\n"
					   "in the case the IMSI could not be found in the database\n"
					   "in the case no remote HLR reponded to mslookup GSUP request\n",
					   "\n", "", 0);

	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();

	install_element_ve(&show_gsup_conn_cmd);

	install_element(CONFIG_NODE, &cfg_hlr_cmd);
	install_node(&hlr_node, config_write_hlr);

	install_element(HLR_NODE, &cfg_gsup_cmd);
	install_node(&gsup_node, config_write_hlr_gsup);

	install_element(GSUP_NODE, &cfg_hlr_gsup_bind_ip_cmd);
	install_element(GSUP_NODE, &cfg_hlr_gsup_ipa_name_cmd);

	/* PS */
	install_node(&ps_node, config_write_hlr_ps);
	install_element(HLR_NODE, &cfg_ps_cmd);

	install_node(&ps_pdp_profiles_node, config_write_hlr_ps_pdp_profiles);
	install_element(PS_NODE, &cfg_ps_pdp_profiles_cmd);
	install_element(PS_NODE, &cfg_no_ps_pdp_profiles_cmd);

	install_node(&ps_pdp_profiles_profile_node, NULL);
	install_element(PS_PDP_PROFILES_NODE, &cfg_ps_pdp_profiles_profile_cmd);
	install_element(PS_PDP_PROFILES_NODE, &cfg_no_ps_pdp_profiles_profile_cmd);
	install_element(PS_PDP_PROFILES_PROFILE_NODE, &cfg_ps_pdp_profile_apn_cmd);
	install_element(PS_PDP_PROFILES_PROFILE_NODE, &cfg_no_ps_pdp_profile_apn_cmd);

	install_element(HLR_NODE, &cfg_database_cmd);

	install_element(HLR_NODE, &cfg_euse_cmd);
	install_element(HLR_NODE, &cfg_no_euse_cmd);
	install_node(&euse_node, config_write_euse);
	install_element(HLR_NODE, &cfg_ussd_route_pfx_int_cmd);
	install_element(HLR_NODE, &cfg_ussd_route_pfx_ext_cmd);
	install_element(HLR_NODE, &cfg_ussd_no_route_pfx_cmd);
	install_element(HLR_NODE, &cfg_ussd_defaultroute_cmd);
	install_element(HLR_NODE, &cfg_ussd_no_defaultroute_cmd);
	install_element(HLR_NODE, &cfg_ncss_guard_timeout_cmd);

	install_node(&smsc_node, config_write_smsc);
	install_element(HLR_NODE, &cfg_smsc_entity_cmd);
	install_element(HLR_NODE, &cfg_no_smsc_entity_cmd);
	install_element(HLR_NODE, &cfg_smsc_route_cmd);
	install_element(HLR_NODE, &cfg_no_smsc_route_cmd);
	install_element(HLR_NODE, &cfg_smsc_defroute_cmd);
	install_element(HLR_NODE, &cfg_no_smsc_defroute_cmd);

	install_element(HLR_NODE, &cfg_reject_cause_cmd);
	install_element(HLR_NODE, &cfg_store_imei_cmd);
	install_element(HLR_NODE, &cfg_no_store_imei_cmd);
	install_element(HLR_NODE, &cfg_subscr_create_on_demand_cmd);
	install_element(HLR_NODE, &cfg_no_subscr_create_on_demand_cmd);

	hlr_vty_subscriber_init();
}
