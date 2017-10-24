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

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>

#include "gsup_server.h"
#include "logging.h"
#include "db.h"
#include "hlr.h"
#include "luop.h"
#include "ctrl.h"

static int handle_cmd_ps(struct hlr *ctx, struct ctrl_cmd *cmd, bool enable)
{
	struct hlr_subscriber subscr;

	if (db_subscr_get_by_imsi(ctx->dbc, cmd->value, &subscr) < 0) {
		cmd->reply = "Subscriber Unknown in HLR";
		return CTRL_CMD_ERROR;
	}

	if (hlr_subscr_nam(ctx, &subscr, enable, true) < 0) {
		cmd->reply = "Error updating DB";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(enable_ps, "enable-ps");
static int set_enable_ps(struct ctrl_cmd *cmd, void *data)
{
	return handle_cmd_ps(data, cmd, true);
}

CTRL_CMD_DEFINE_WO_NOVRF(disable_ps, "disable-ps");
static int set_disable_ps(struct ctrl_cmd *cmd, void *data)
{
	return handle_cmd_ps(data, cmd, false);
}

CTRL_CMD_DEFINE_WO_NOVRF(status_ps, "status-ps");
static int set_status_ps(struct ctrl_cmd *cmd, void *data)
{
	struct hlr *ctx = data;
	struct lu_operation *luop = lu_op_alloc(ctx->gs);
	if (!luop) {
		cmd->reply = "Internal HLR error";
		return CTRL_CMD_ERROR;
	}

	if (!lu_op_fill_subscr(luop, ctx->dbc, cmd->value)) {
		cmd->reply = "Subscriber Unknown in HLR";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = luop->subscr.nam_ps ? "1" : "0";

	return CTRL_CMD_REPLY;
}

int hlr_ctrl_cmds_install()
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_enable_ps);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_disable_ps);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_status_ps);

	return rc;
}

struct ctrl_handle *hlr_controlif_setup(struct hlr *hlr)
{
	int rc;
	struct ctrl_handle *hdl = ctrl_interface_setup_dynip2(hlr,
							      hlr->ctrl_bind_addr,
							      OSMO_CTRL_PORT_HLR,
							      NULL,
							      0);
	if (!hdl)
		return NULL;

	rc = hlr_ctrl_cmds_install();
	if (rc) /* FIXME: close control interface? */
		return NULL;

	return hdl;
}
