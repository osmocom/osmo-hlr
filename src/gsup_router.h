#pragma once

#include <stdint.h>
#include "gsup_server.h"

struct gsup_route {
	struct llist_head list;

	uint8_t *addr;
	struct osmo_gsup_conn *conn;
};

struct osmo_gsup_conn *gsup_route_find(struct osmo_gsup_server *gs,
					const uint8_t *addr, size_t addrlen);

struct gsup_route *gsup_route_find_by_conn(const struct osmo_gsup_conn *conn);

/* add a new route for the given address to the given conn */
int gsup_route_add(struct osmo_gsup_conn *conn, const uint8_t *addr, size_t addrlen);

/* delete all routes for the given connection */
int gsup_route_del_conn(struct osmo_gsup_conn *conn);

int osmo_gsup_addr_send(struct osmo_gsup_server *gs,
			const uint8_t *addr, size_t addrlen,
			struct msgb *msg);
