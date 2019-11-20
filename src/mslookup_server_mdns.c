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

#include <stdlib.h>
#include <unistd.h>

#include <osmocom/mslookup/mslookup.h>
#include <osmocom/mslookup/mdns.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/mslookup_server.h>
#include <osmocom/hlr/mslookup_server_mdns.h>

static void osmo_mslookup_server_mdns_tx(struct osmo_mslookup_server_mdns *server,
					 uint16_t packet_id,
					 const struct osmo_mslookup_query *query,
					 const struct osmo_mslookup_result *result)
{
	struct msgb *msg;
	const char *errmsg = NULL;
	void *ctx = talloc_named_const(server, 0, __func__);

	msg = osmo_mdns_result_encode(ctx, packet_id, query, result);
	if (!msg)
		errmsg = "Error encoding mDNS answer packet";
	else if (osmo_mdns_sock_send(server->sock, msg))
		errmsg = "Error sending mDNS answer";
	if (errmsg)
		LOGP(DMSLOOKUP, LOGL_ERROR, "%s: mDNS: %s\n", osmo_mslookup_result_name_c(ctx, query, result), errmsg);
	talloc_free(ctx);
}

static void osmo_mslookup_server_mdns_handle_request(uint16_t packet_id,
						     struct osmo_mslookup_server_mdns *server,
						     const struct osmo_mslookup_query *query)
{
	struct osmo_mslookup_result result;

	mslookup_server_rx(query, &result);
	/* Error logging already happens in mslookup_server_rx() */
	if (result.rc != OSMO_MSLOOKUP_RC_RESULT)
		return;

	osmo_mslookup_server_mdns_tx(server, packet_id, query, &result);
}

static int osmo_mslookup_server_mdns_rx(struct osmo_fd *osmo_fd, unsigned int what)
{
	struct osmo_mslookup_server_mdns *server = osmo_fd->data;
	struct osmo_mslookup_query *query;
	uint16_t packet_id;
	int n;
	uint8_t buffer[1024];
	void *ctx;

	/* Parse the message and print it */
	n = read(osmo_fd->fd, buffer, sizeof(buffer));
	if (n < 0)
		return n;

	ctx = talloc_named_const(server, 0, __func__);
	query = osmo_mdns_query_decode(ctx, buffer, n, &packet_id);
	if (!query) {
		talloc_free(ctx);
		return -1;
	}

	osmo_mslookup_id_name_buf((char *)buffer, sizeof(buffer), &query->id);
	LOGP(DMSLOOKUP, LOGL_DEBUG, "mDNS rx request: %s.%s\n", query->service, buffer);
	osmo_mslookup_server_mdns_handle_request(packet_id, server, query);
	talloc_free(ctx);
	return n;
}

struct osmo_mslookup_server_mdns *osmo_mslookup_server_mdns_start(void *ctx, const struct osmo_sockaddr_str *bind_addr)
{
	struct osmo_mslookup_server_mdns *server = talloc_zero(ctx, struct osmo_mslookup_server_mdns);
	OSMO_ASSERT(server);
	*server = (struct osmo_mslookup_server_mdns){
		.bind_addr = *bind_addr,
	};

	server->sock = osmo_mdns_sock_init(server,
					   bind_addr->ip, bind_addr->port,
					   osmo_mslookup_server_mdns_rx,
					   server, 0);
	if (!server->sock) {
		LOGP(DMSLOOKUP, LOGL_ERROR,
		     "mslookup mDNS server: error initializing multicast bind on " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(bind_addr));
		talloc_free(server);
		return NULL;
	}

	return server;
}

void osmo_mslookup_server_mdns_stop(struct osmo_mslookup_server_mdns *server)
{
	if (!server)
		return;
	osmo_mdns_sock_cleanup(server->sock);
	talloc_free(server);
}

void mslookup_server_mdns_config_apply()
{
	/* Check whether to start/stop/restart mDNS server */
	bool should_run;
	bool should_stop;

	should_run = g_hlr->mslookup.allow_startup
		&& g_hlr->mslookup.server.enable && g_hlr->mslookup.server.mdns.enable;
	should_stop = g_hlr->mslookup.server.mdns.running
		&& (!should_run
		    || osmo_sockaddr_str_cmp(&g_hlr->mslookup.server.mdns.bind_addr,
					     &g_hlr->mslookup.server.mdns.running->bind_addr));

	if (should_stop) {
		osmo_mslookup_server_mdns_stop(g_hlr->mslookup.server.mdns.running);
		g_hlr->mslookup.server.mdns.running = NULL;
		LOGP(DMSLOOKUP, LOGL_NOTICE, "Stopped mslookup mDNS server\n");
	}

	if (should_run && !g_hlr->mslookup.server.mdns.running) {
		g_hlr->mslookup.server.mdns.running =
			osmo_mslookup_server_mdns_start(g_hlr, &g_hlr->mslookup.server.mdns.bind_addr);
		if (!g_hlr->mslookup.server.mdns.running)
			LOGP(DMSLOOKUP, LOGL_ERROR, "Failed to start mslookup mDNS server on " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.server.mdns.running->bind_addr));
		else
			LOGP(DMSLOOKUP, LOGL_NOTICE, "Started mslookup mDNS server, receiving mDNS requests at multicast "
			     OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.server.mdns.running->bind_addr));
	}
}
