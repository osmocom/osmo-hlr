/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
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


#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>

#include "logging.h"
#include "gsup_server.h"
#include "gsup_router.h"

/*! Find a route for the given address.
 * \param[in] gs gsup server
 * \param[in] addr IPA name of the client (SGSN, MSC/VLR). Although this is passed like a blob, together with the
 *                 length, it must be nul-terminated! This is for legacy reasons, see the discussion here:
 *                 https://gerrit.osmocom.org/#/c/osmo-hlr/+/13048/
 * \param[in] addrlen length of addr, *including the nul-byte* (strlen(addr) + 1).
 */
struct osmo_gsup_conn *gsup_route_find(struct osmo_gsup_server *gs,
					const uint8_t *addr, size_t addrlen)
{
	struct gsup_route *gr;

	llist_for_each_entry(gr, &gs->routes, list) {
		size_t gr_addrlen = talloc_total_size(gr->addr); /* gr->addr is a nul-terminated string */

		/* FIXME: despite passing addrlen, a lot of code assumes that addr is also nul-terminated */
		if (gr_addrlen == addrlen && !memcmp(gr->addr, addr, addrlen))
			return gr->conn;

		/* Compare addr as non-nul-terminated blob */
		if (gr_addrlen - 1 == addrlen && !memcmp(gr->addr, addr, addrlen))
			return gr->conn;
	}
	return NULL;
}

/*! Find a GSUP connection's route (to read the IPA address from the route).
 * \param[in] conn GSUP connection
 * \return GSUP route
 */
struct gsup_route *gsup_route_find_by_conn(const struct osmo_gsup_conn *conn)
{
	struct gsup_route *gr;

	llist_for_each_entry(gr, &conn->server->routes, list) {
		if (gr->conn == conn)
			return gr;
	}

	return NULL;
}

/* add a new route for the given address to the given conn */
int gsup_route_add(struct osmo_gsup_conn *conn, const uint8_t *addr, size_t addrlen)
{
	struct gsup_route *gr;

	/* Check if we already have a route for this address */
	if (gsup_route_find(conn->server, addr, addrlen))
		return -EEXIST;

	/* allocate new route and populate it */
	gr = talloc_zero(conn->server, struct gsup_route);
	if (!gr)
		return -ENOMEM;

	LOGP(DMAIN, LOGL_INFO, "Adding GSUP route for %s via %s:%u\n", addr, conn->conn->addr, conn->conn->port);

	gr->addr = talloc_memdup(gr, addr, addrlen);
	gr->conn = conn;
	llist_add_tail(&gr->list, &conn->server->routes);

	return 0;
}

/* delete all routes for the given connection */
int gsup_route_del_conn(struct osmo_gsup_conn *conn)
{
	struct gsup_route *gr, *gr2;
	unsigned int num_deleted = 0;

	llist_for_each_entry_safe(gr, gr2, &conn->server->routes, list) {
		if (gr->conn == conn) {
			LOGP(DMAIN, LOGL_INFO, "Removing GSUP route for %s (GSUP disconnect)\n",
			     gr->addr);
			llist_del(&gr->list);
			talloc_free(gr);
			num_deleted++;
		}
	}

	return num_deleted;
}
