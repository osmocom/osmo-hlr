/* Copyright 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>

struct osmo_mslookup_client;
struct osmo_mslookup_client_method;

/*! MS Lookup mDNS server bind default IP. Taken from the Administratevly Scoped block, particularly the Organizational
 * Scoped range, https://tools.ietf.org/html/rfc2365 . */
#define OSMO_MSLOOKUP_MDNS_IP4 "239.192.23.42"
#define OSMO_MSLOOKUP_MDNS_IP6 "ff08::23:42" // <-- TODO: sane?
#define OSMO_MSLOOKUP_MDNS_PORT 4266

struct osmo_mslookup_client_method *osmo_mslookup_client_add_mdns(struct osmo_mslookup_client *client, const char *ip,
								  uint16_t port, int initial_packet_id,
								  const char *domain_suffix);

const struct osmo_sockaddr_str *osmo_mslookup_client_method_mdns_get_bind_addr(struct osmo_mslookup_client_method *dns_method);

const char *osmo_mslookup_client_method_mdns_get_domain_suffix(struct osmo_mslookup_client_method *dns_method);
