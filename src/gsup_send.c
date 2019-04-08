/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

/* This is kept separate to be able to override the actual sending functions from unit tests. */

#include <errno.h>

#include "gsup_server.h"
#include "gsup_router.h"

#include <osmocom/core/logging.h>

/*! Send a msgb to a given address using routing.
 * \param[in] gs gsup server
 * \param[in] addr IPA name of the client (SGSN, MSC/VLR). Although this is passed like a blob, together with the
 *                 length, it must be nul-terminated! This is for legacy reasons, see the discussion here:
 *                 https://gerrit.osmocom.org/#/c/osmo-hlr/+/13048/
 * \param[in] addrlen length of addr, *including the nul-byte* (strlen(addr) + 1).
 * \param[in] msg message buffer
 */
int osmo_gsup_addr_send(struct osmo_gsup_server *gs,
			const uint8_t *addr, size_t addrlen,
			struct msgb *msg)
{
	struct osmo_gsup_conn *conn;

	conn = gsup_route_find(gs, addr, addrlen);
	if (!conn) {
		DEBUGP(DLGSUP, "Cannot find route for addr %s\n", addr);
		msgb_free(msg);
		return -ENODEV;
	}

	return osmo_gsup_conn_send(conn, msg);
}

