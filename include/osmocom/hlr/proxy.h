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

#include <time.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsupclient/gsup_peer_id.h>
#include <osmocom/hlr/timestamp.h>

struct osmo_gsup_req;
struct remote_hlr;

struct proxy_pending_gsup_req {
	struct llist_head entry;
	struct osmo_gsup_req *req;
	timestamp_t received_at;
};

struct proxy {
	struct llist_head subscr_list;
	struct llist_head pending_gsup_reqs;

	/* When messages arrive back from a remote HLR that this is the proxy for, reach the VLR to forward the response
	 * to via this osmo_gsup_server. */
	struct osmo_gsup_server *gsup_server_to_vlr;

	/* How long to keep proxy entries without a refresh, in seconds. */
	uint32_t fresh_time;

	/* How often to garbage collect the proxy cache, period in seconds.
	 * To change this and take effect immediately, rather use proxy_set_gc_period(). */
	uint32_t gc_period;

	struct osmo_timer_list gc_timer;
};

struct proxy_subscr_domain_state {
	struct osmo_ipa_name vlr_name;
	timestamp_t last_lu;

	/* The name from which an Update Location Request was received. Copied to vlr_name as soon as the LU is
	 * completed successfully. */
	struct osmo_ipa_name vlr_name_preliminary;

	/* Set if this is a middle proxy, i.e. a proxy behind another proxy.
	 * That is mostly to know whether the MS is attached at a local MSC/SGSN or further away.
	 * It could be a boolean, but store the full name for logging. Set only at successful LU acceptance. */
	struct osmo_ipa_name vlr_via_proxy;
};

struct proxy_subscr {
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	char msisdn[GSM23003_MSISDN_MAX_DIGITS+1];
	struct osmo_sockaddr_str remote_hlr_addr;
	struct proxy_subscr_domain_state cs, ps;
};

void proxy_init(struct osmo_gsup_server *gsup_server_to_vlr);
void proxy_del(struct proxy *proxy);
void proxy_set_gc_period(struct proxy *proxy, uint32_t gc_period);

/* The API to access / modify proxy entries keeps the implementation opaque, to make sure that we can easily move proxy
 * storage to SQLite db. */
int proxy_subscr_get_by_imsi(struct proxy_subscr *dst, struct proxy *proxy, const char *imsi);
int proxy_subscr_get_by_msisdn(struct proxy_subscr *dst, struct proxy *proxy, const char *msisdn);
void proxy_subscrs_get_by_remote_hlr(struct proxy *proxy, const struct osmo_sockaddr_str *remote_hlr_addr,
				     bool (*yield)(struct proxy *proxy, const struct proxy_subscr *subscr, void *data),
				     void *data);
int proxy_subscr_create_or_update(struct proxy *proxy, const struct proxy_subscr *proxy_subscr);
int proxy_subscr_del(struct proxy *proxy, const char *imsi);

void proxy_subscr_forward_to_remote_hlr(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
					struct osmo_gsup_req *req);
void proxy_subscr_forward_to_remote_hlr_resolved(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
						 struct remote_hlr *remote_hlr, struct osmo_gsup_req *req);

int proxy_subscr_forward_to_vlr(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
				const struct osmo_gsup_message *gsup, struct remote_hlr *from_remote_hlr);

void proxy_subscr_remote_hlr_resolved(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
				      struct remote_hlr *remote_hlr);
void proxy_subscr_remote_hlr_up(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
				struct remote_hlr *remote_hlr);
