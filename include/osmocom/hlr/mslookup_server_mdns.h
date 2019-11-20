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
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mslookup/mdns_sock.h>

struct osmo_mslookup_server_mdns {
	struct osmo_mslookup_server *mslookup;
	struct osmo_sockaddr_str bind_addr;
	char *domain_suffix;
	struct osmo_mdns_sock *sock;
};

struct osmo_mslookup_server_mdns *osmo_mslookup_server_mdns_start(void *ctx, const struct osmo_sockaddr_str *bind_addr,
								  const char *domain_suffix);
void osmo_mslookup_server_mdns_stop(struct osmo_mslookup_server_mdns *server);
void mslookup_server_mdns_config_apply();
