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

#include <osmocom/core/talloc.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/abis/ipa.h>

#include "hlr.h"
#include "hlr_vty.h"
#include "hlr_vty_subscr.h"
#include "hlr_ussd.h"
#include "gsup_server.h"

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

static int config_write_hlr(struct vty *vty)
{
	vty_out(vty, "hlr%s", VTY_NEWLINE);
	if (g_hlr->store_imei)
		vty_out(vty, " store-imei%s", VTY_NEWLINE);
	if (g_hlr->db_file_path && strcmp(g_hlr->db_file_path, HLR_DEFAULT_DB_FILE_PATH))
		vty_out(vty, " database %s%s", g_hlr->db_file_path, VTY_NEWLINE);
	return CMD_SUCCESS;
}

static int config_write_hlr_gsup(struct vty *vty)
{
	vty_out(vty, " gsup%s", VTY_NEWLINE);
	if (g_hlr->gsup_bind_addr)
		vty_out(vty, "  bind ip %s%s", g_hlr->gsup_bind_addr, VTY_NEWLINE);
	return CMD_SUCCESS;
}

static void show_one_conn(struct vty *vty, const struct osmo_gsup_conn *conn)
{
	const struct ipa_server_conn *isc = conn->conn;
	char *name;
	int rc;

	rc = osmo_gsup_conn_ccm_get(conn, (uint8_t **) &name, IPAC_IDTAG_SERNR);
	OSMO_ASSERT(rc);

	vty_out(vty, " '%s' from %s:%5u, CS=%u, PS=%u, 3G_IND=%u%s",
		name, isc->addr, isc->port, conn->supports_cs, conn->supports_ps, conn->auc_3g_ind,
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

/***********************************************************************
 * USSD Entity
 ***********************************************************************/

#include "hlr_ussd.h"

#define USSD_STR "USSD Configuration\n"
#define UROUTE_STR "Routing Configuration\n"
#define PREFIX_STR "Prefix-Matching Route\n" "USSD Prefix\n"

#define INT_CHOICE "(own-msisdn|own-imsi)"
#define INT_STR "Internal USSD Handler\n" \
		"Respond with subscribers' own MSISDN\n" \
		"Respond with subscribers' own IMSI\n"

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
		vty_out(vty, "%% Cannot remove non-existant EUSE %s%s", argv[0], VTY_NEWLINE);
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

void hlr_vty_init(const struct log_info *cat)
{
	logging_vty_add_cmds(cat);
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();

	install_element_ve(&show_gsup_conn_cmd);

	install_element(CONFIG_NODE, &cfg_hlr_cmd);
	install_node(&hlr_node, config_write_hlr);

	install_element(HLR_NODE, &cfg_gsup_cmd);
	install_node(&gsup_node, config_write_hlr_gsup);

	install_element(GSUP_NODE, &cfg_hlr_gsup_bind_ip_cmd);

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
	install_element(HLR_NODE, &cfg_store_imei_cmd);
	install_element(HLR_NODE, &cfg_no_store_imei_cmd);

	hlr_vty_subscriber_init();
}
