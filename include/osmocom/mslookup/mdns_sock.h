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
#include <netdb.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

struct osmo_mdns_sock {
	struct osmo_fd osmo_fd;
	struct addrinfo *ai;
};

struct osmo_mdns_sock *osmo_mdns_sock_init(void *ctx, const char *ip, unsigned int port,
					   int (*cb)(struct osmo_fd *fd, unsigned int what),
					   void *data, unsigned int priv_nr);
int osmo_mdns_sock_send(const struct osmo_mdns_sock *mdns_sock, struct msgb *msg);
void osmo_mdns_sock_cleanup(struct osmo_mdns_sock *mdns_sock);
