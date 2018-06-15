/* OsmoHLR VTY implementation */

/* (C) 2016 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 * (C) 2018 Harald Welte <laforge@gnumonks.org>
 * (C) 2018 by Vadim Yanitskiy <axilirator@gmail.com>
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
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/abis/ipa.h>

#include "hlr_vty.h"
#include "hlr_ss_ussd.h"
#include "hlr_vty_subscr.h"
#include "gsup_server.h"

static struct hlr *g_hlr = NULL;

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
	SHOW_STR "GSUP Connections from VLRs, SGSNs, EUSSEs\n")
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
 * Unstructured Supplementary Services processing Entity configuration
 ***********************************************************************/

static struct cmd_node iusse_node = {
	IUSSE_NODE,
	"%s(config-hlr-iusse)# ",
	1,
};

static struct cmd_node eusse_node = {
	EUSSE_NODE,
	"%s(config-hlr-eusse)# ",
	1,
};

#define VTY_USSE_NAME_DESC \
	"Internal USSD processing Entity\n" \
	"Alphanumeric name of an External USSE\n"

DEFUN(cfg_usse, cfg_usse_cmd,
	"usse (internal|NAME)",
	"Configure a particular USSE (USSD processing Entity)\n"
	VTY_USSE_NAME_DESC)
{
	const char *name = argv[0];
	struct hlr_usse *usse;

	usse = hlr_usse_find(g_hlr, name);
	if (!usse) {
		usse = hlr_usse_alloc(g_hlr, name);
		if (!usse)
			return CMD_WARNING;
	}

	vty->index_sub = &usse->description;
	vty->index = usse;

	/* IUSSE or EUSSE? */
	if (!strcmp(usse->name, "internal"))
		vty->node = IUSSE_NODE;
	else
		vty->node = EUSSE_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_usse, cfg_no_usse_cmd,
	"no usse (internal|NAME)",
	NO_STR "Remove a particular USSE (USSD processing Entity)\n"
	VTY_USSE_NAME_DESC)
{
	const char *name = argv[0];
	struct hlr_usse *usse;

	usse = hlr_usse_find(g_hlr, name);
	if (!usse) {
		vty_out(vty, "%% Cannot remove non-existent "
			"USSE '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (g_hlr->usse_default == usse) {
		vty_out(vty, "%% Cannot remove USSE '%s', "
			"it is the default route%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	hlr_usse_del(usse);
	return CMD_SUCCESS;
}

DEFUN(cfg_usse_default, cfg_usse_default_cmd,
	"usse-default (internal|NAME)",
	"Default USSD processing Entity\n"
	VTY_USSE_NAME_DESC)
{
	const char *name = argv[0];
	struct hlr_usse *usse;

	usse = hlr_usse_find(g_hlr, name);
	if (!usse) {
		vty_out(vty, "%% Cannot find USSE '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (g_hlr->usse_default == usse) {
		vty_out(vty, "%% USSE '%s' is already "
			"used by default%s", usse->name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hlr->usse_default = usse;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_usse_default, cfg_no_usse_default_cmd,
	"no usse-default",
	NO_STR "No default USSD processing Entity "
	"(drop all unmatched requests)\n")
{
	g_hlr->usse_default = NULL;
	return CMD_SUCCESS;
}

#define VTY_USSE_PATTERN_CMD \
	"pattern (code|regexp|prefix) PATTERN"

#define VTY_USSE_PATTERN_DESC \
	"Match USSD-request codes by exact value (e.g. '*#100#')\n" \
	"Match USSD-request codes by regular expression (e.g. '^\\*[5-7]+'\\*)\n" \
	"Match USSD-request codes by prefix (e.g. '*#' or '*110*')\n" \
	"Matching pattern\n"

static int _cfg_usse_pattern(struct vty *vty, int argc, const char **argv)
{
	struct hlr_usse *usse = vty->index;
	enum hlr_usse_pattern_type type;
	struct hlr_usse_pattern *pt;
	bool is_iusse;

	/* Determine which kind of matching pattern required */
	switch (argv[0][0]) {
	case 'c':
		type = HLR_USSE_PATTERN_CODE;
		break;
	case 'r':
		type = HLR_USSE_PATTERN_REGEXP;
		break;
	case 'p':
		type = HLR_USSE_PATTERN_PREFIX;
		break;
	default:
		/* Shouldn't happen, but let's make sure */
		return CMD_WARNING;
	}

	/* IUSSE or EUSSE? */
	is_iusse = !strcmp(usse->name, "internal");

	/* Attempt to find pattern */
	pt = hlr_usse_pattern_find(usse, type, argv[1]);
	if (pt && !is_iusse) {
		/* Response modification is only actual for IUSSE */
		vty_out(vty, "%% Pattern already exists!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Allocate if required */
	if (!pt) {
		pt = hlr_usse_pattern_add(usse, type, argv[1]);
		if (!pt) {
			vty_out(vty, "%% Cannot add pattern '%s' of type '%s'%s",
				argv[1], argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	/* Response string for IUSSE */
	if (is_iusse) {
		if (pt->rsp_fmt)
			talloc_free(pt->rsp_fmt);
		pt->rsp_fmt = talloc_strdup(pt, argv_concat(argv, argc, 2));
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_iusse_pattern, cfg_iusse_pattern_cmd,
	VTY_USSE_PATTERN_CMD " response .RESPONSE",
	"Add or modify a USSD-code matching pattern\n"
	VTY_USSE_PATTERN_DESC
	"Response format string (e.g. 'Your MSISDN is %m')\n")
{
	return _cfg_usse_pattern(vty, argc, argv);
}

DEFUN(cfg_eusse_pattern, cfg_eusse_pattern_cmd,
	VTY_USSE_PATTERN_CMD,
	"Add a new USSD-code matching pattern\n"
	VTY_USSE_PATTERN_DESC)
{
	return _cfg_usse_pattern(vty, argc, argv);
}

DEFUN(cfg_usse_no_pattern, cfg_usse_no_pattern_cmd,
	"no " VTY_USSE_PATTERN_CMD,
	NO_STR "Remove an existing USSD-code matching pattern\n"
	VTY_USSE_PATTERN_DESC)
{
	struct hlr_usse *usse = vty->index;
	enum hlr_usse_pattern_type type;
	struct hlr_usse_pattern *pt;

	/* Determine which kind of matching pattern required */
	switch (argv[0][0]) {
	case 'c':
		type = HLR_USSE_PATTERN_CODE;
		break;
	case 'r':
		type = HLR_USSE_PATTERN_REGEXP;
		break;
	case 'p':
		type = HLR_USSE_PATTERN_PREFIX;
		break;
	default:
		/* Shouldn't happen, but let's make sure */
		return CMD_WARNING;
	}

	pt = hlr_usse_pattern_find(usse, type, argv[1]);
	if (!pt) {
		vty_out(vty, "%% Cannot remove non-existent pattern '%s' "
			"of type '%s'%s", argv[1], argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	hlr_usse_pattern_del(pt);
	return CMD_SUCCESS;
}

static void dump_one_usse(struct vty *vty, struct hlr_usse *usse)
{
	struct hlr_usse_pattern *pt;
	const char *pt_type;

	vty_out(vty, " usse %s%s", usse->name, VTY_NEWLINE);
	// FIXME: what about usse->description?

	llist_for_each_entry(pt, &usse->patterns, list) {
		/* Stringify pattern type */
		switch (pt->type) {
		case HLR_USSE_PATTERN_CODE:
			pt_type = "code";
			break;
		case HLR_USSE_PATTERN_REGEXP:
			pt_type = "regexp";
			break;
		case HLR_USSE_PATTERN_PREFIX:
			pt_type = "prefix";
			break;
		default:
			/* Should not happen */
			OSMO_ASSERT(0);
		}

		if (pt->rsp_fmt != NULL)
			vty_out(vty, "  pattern %s %s response %s%s", pt_type,
				pt->pattern, pt->rsp_fmt, VTY_NEWLINE);
		else
			vty_out(vty, "  pattern %s %s%s", pt_type,
				pt->pattern, VTY_NEWLINE);
	}
}

static int config_write_usse(struct vty *vty)
{
	struct hlr_usse *usse;

	if (g_hlr->usse_default == NULL)
		vty_out(vty, " no usse-default%s", VTY_NEWLINE);
	else
		vty_out(vty, " usse-default %s%s",
			g_hlr->usse_default->name, VTY_NEWLINE);

	llist_for_each_entry(usse, &g_hlr->usse_list, list)
		dump_one_usse(vty, usse);

	return CMD_SUCCESS;
}

/***********************************************************************
 * Common Code
 ***********************************************************************/

int hlr_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case GSUP_NODE:
	case IUSSE_NODE:
	case EUSSE_NODE:
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

void hlr_vty_init(struct hlr *hlr, const struct log_info *cat)
{
	g_hlr = hlr;

	logging_vty_add_cmds(cat);
	osmo_talloc_vty_add_cmds();

	install_element_ve(&show_gsup_conn_cmd);

	install_element(CONFIG_NODE, &cfg_hlr_cmd);
	install_node(&hlr_node, config_write_hlr);

	install_element(HLR_NODE, &cfg_gsup_cmd);
	install_node(&gsup_node, config_write_hlr_gsup);

	install_element(GSUP_NODE, &cfg_hlr_gsup_bind_ip_cmd);

	install_element(HLR_NODE, &cfg_usse_cmd);
	install_element(HLR_NODE, &cfg_no_usse_cmd);
	install_element(HLR_NODE, &cfg_usse_default_cmd);
	install_element(HLR_NODE, &cfg_no_usse_default_cmd);
	install_node(&eusse_node, config_write_usse);
	install_element(EUSSE_NODE, &cfg_eusse_pattern_cmd);
	install_element(EUSSE_NODE, &cfg_usse_no_pattern_cmd);
	install_node(&iusse_node, NULL);
	install_element(IUSSE_NODE, &cfg_iusse_pattern_cmd);
	install_element(IUSSE_NODE, &cfg_usse_no_pattern_cmd);

	hlr_vty_subscriber_init(hlr);
}
