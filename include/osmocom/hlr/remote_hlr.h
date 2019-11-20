/* Copyright 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#pragma once

#include <stdbool.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/sockaddr_str.h>

struct osmo_gsup_client;
struct osmo_gsup_message;
struct osmo_gsup_req;
struct msgb;

#define LOG_REMOTE_HLR(remote_hlr, level, fmt, args...) \
	LOGP(DDGSM, level, "(Proxy HLR-" OSMO_SOCKADDR_STR_FMT ") " fmt, \
	     OSMO_SOCKADDR_STR_FMT_ARGS((remote_hlr) ? &(remote_hlr)->addr : NULL), ##args)

#define LOG_REMOTE_HLR_MSG(remote_hlr, gsup_msg, level, fmt, args...) \
	LOG_REMOTE_HLR(remote_hlr, level, "%s: " fmt, osmo_gsup_message_type_name((gsup_msg)->message_type), ##args)

/* GSUP client link for proxying to a remote HLR. */
struct remote_hlr {
	struct llist_head entry;
	struct osmo_sockaddr_str addr;
	struct osmo_gsup_client *gsupc;
};

struct remote_hlr *remote_hlr_get(const struct osmo_sockaddr_str *addr, bool create);
void remote_hlr_destroy(struct remote_hlr *remote_hlr);
int remote_hlr_msgb_send(struct remote_hlr *remote_hlr, struct msgb *msg);
void remote_hlr_gsup_forward_to_remote_hlr(struct remote_hlr *remote_hlr, struct osmo_gsup_req *req);
