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

#include <osmocom/mslookup/mslookup.h>
#include <osmocom/hlr/gsup_server.h>
#include <osmocom/gsupclient/gsup_peer_id.h>
#include <osmocom/gsupclient/gsup_req.h>

#define LOG_DGSM(imsi, level, fmt, args...) \
	LOGP(DDGSM, level, "(IMSI-%s) " fmt, imsi, ##args)

struct vty;
struct remote_hlr;
struct hlr_subscriber;

extern void *dgsm_ctx;

void dgsm_init(void *ctx);
void dgsm_start(void *ctx);
void dgsm_stop();

bool dgsm_check_forward_gsup_msg(struct osmo_gsup_req *req);

void dgsm_vty_init();
void dgsm_mdns_client_config_apply(void);

bool hlr_subscr_lu_age(const struct hlr_subscriber *subscr, uint32_t *age_p);
