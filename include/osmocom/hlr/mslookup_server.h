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

#include <osmocom/gsupclient/cni_peer_id.h>
#include <osmocom/mslookup/mslookup.h>

struct osmo_mslookup_query;
struct osmo_mslookup_result;

/*! mslookup service name used for roaming/proxying between osmo-hlr instances. */
#define OSMO_MSLOOKUP_SERVICE_HLR_GSUP "gsup.hlr"

/*! What addresses to return to mslookup queries when a subscriber is attached at the local site.
 * Mapping of service name to IP address and port. This corresponds to the VTY config for
 * 'mslookup' / 'server' [/ 'msc MSC-1-2-3'] / 'service sip.voice at 1.2.3.4 1234'.
 */
struct mslookup_service_host {
	struct llist_head entry;
	char service[OSMO_MSLOOKUP_SERVICE_MAXLEN+1];
	struct osmo_sockaddr_str host_v4;
	struct osmo_sockaddr_str host_v6;
};

/*! Sets of mslookup_service_host per connected MSC.
 * When there are more than one MSC connected to this osmo-hlr, this allows keeping separate sets of service addresses
 * for each MSC. The entry with mslookup_server_msc_wildcard as MSC name is used for all MSCs (if no match for that
 * particular MSC is found). This corresponds to the VTY config for
 * 'mslookup' / 'server' / 'msc MSC-1-2-3'.
 */
struct mslookup_server_msc_cfg {
	struct llist_head entry;
	struct osmo_ipa_name name;
	struct llist_head service_hosts;
};

struct mslookup_service_host *mslookup_server_service_get(const struct osmo_ipa_name *msc_name, const char *service);

struct mslookup_service_host *mslookup_server_msc_service_get(struct mslookup_server_msc_cfg *msc, const char *service,
							      bool create);
int mslookup_server_msc_service_set(struct mslookup_server_msc_cfg *msc, const char *service,
				    const struct osmo_sockaddr_str *addr);
int mslookup_server_msc_service_del(struct mslookup_server_msc_cfg *msc, const char *service,
				    const struct osmo_sockaddr_str *addr);

extern const struct osmo_ipa_name mslookup_server_msc_wildcard;
struct mslookup_server_msc_cfg *mslookup_server_msc_get(const struct osmo_ipa_name *msc_name, bool create);

const struct mslookup_service_host *mslookup_server_get_local_gsup_addr();
void mslookup_server_rx(const struct osmo_mslookup_query *query,
			     struct osmo_mslookup_result *result);
