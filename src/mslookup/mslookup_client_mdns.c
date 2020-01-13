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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/mslookup/mdns.h>
#include <osmocom/mslookup/mdns_sock.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>

struct osmo_mdns_method_state {
	/* Parameters passed by _add_method_dns() */
	struct osmo_sockaddr_str bind_addr;
	const char *domain_suffix;

	struct osmo_mdns_sock *mc;

	struct osmo_mslookup_client *client;
	struct llist_head requests;
	uint16_t next_packet_id;
};

struct osmo_mdns_method_request {
	struct llist_head entry;
	uint32_t request_handle;
	struct osmo_mslookup_query query;
	uint16_t packet_id;
};

static int request_handle_by_query(uint32_t *request_handle, struct osmo_mdns_method_state *state,
				   struct osmo_mslookup_query *query, uint16_t packet_id)
{
	struct osmo_mdns_method_request *request;

	llist_for_each_entry(request, &state->requests, entry) {
		if (strcmp(request->query.service, query->service) != 0)
			continue;
		if (osmo_mslookup_id_cmp(&request->query.id, &query->id) != 0)
			continue;

		/* Match! */
		*request_handle = request->request_handle;
		return 0;
	}
	return -1;
}

static int mdns_method_recv(struct osmo_fd *osmo_fd, unsigned int what)
{
	struct osmo_mdns_method_state *state = osmo_fd->data;
	struct osmo_mslookup_result result;
	struct osmo_mslookup_query query;
	uint16_t packet_id;
	int n;
	uint8_t buffer[1024];
	uint32_t request_handle = 0;
	void *ctx = state;

	n = read(osmo_fd->fd, buffer, sizeof(buffer));
	if (n < 0) {
		LOGP(DMSLOOKUP, LOGL_ERROR, "failed to read from socket\n");
		return n;
	}

	if (osmo_mdns_result_decode(ctx, buffer, n, &packet_id, &query, &result, state->domain_suffix) < 0)
		return -EINVAL;

	if (request_handle_by_query(&request_handle, state, &query, packet_id) != 0)
		return -EINVAL;

	osmo_mslookup_client_rx_result(state->client, request_handle, &result);
	return n;
}

static void mdns_method_request(struct osmo_mslookup_client_method *method, const struct osmo_mslookup_query *query,
				uint32_t request_handle)
{
	char buf[256];
	struct osmo_mdns_method_state *state = method->priv;
	struct msgb *msg;
	struct osmo_mdns_method_request *r = talloc_zero(method->client, struct osmo_mdns_method_request);

	*r = (struct osmo_mdns_method_request){
		.request_handle = request_handle,
		.query = *query,
		.packet_id = state->next_packet_id,
	};
	llist_add(&r->entry, &state->requests);
	state->next_packet_id++;

	msg = osmo_mdns_query_encode(method->client, r->packet_id, query, state->domain_suffix);
	if (!msg) {
		LOGP(DMSLOOKUP, LOGL_ERROR, "Cannot encode request: %s\n",
		     osmo_mslookup_result_name_b(buf, sizeof(buf), query, NULL));
		return;
	}

	/* Send over the wire */
	LOGP(DMSLOOKUP, LOGL_DEBUG, "sending mDNS query: %s.%s\n", query->service,
	     osmo_mslookup_id_name_b(buf, sizeof(buf), &query->id));
	if (osmo_mdns_sock_send(state->mc, msg) == -1)
		LOGP(DMSLOOKUP, LOGL_ERROR, "sending mDNS query failed\n");
}

static void mdns_method_request_cleanup(struct osmo_mslookup_client_method *method, uint32_t request_handle)
{
	struct osmo_mdns_method_state *state = method->priv;

	/* Tear down any state associated with this handle. */
	struct osmo_mdns_method_request *r;
	llist_for_each_entry(r, &state->requests, entry) {
		if (r->request_handle != request_handle)
			continue;
		llist_del(&r->entry);
		talloc_free(r);
		return;
	}
}

static void mdns_method_destruct(struct osmo_mslookup_client_method *method)
{
	struct osmo_mdns_method_state *state = method->priv;
	struct osmo_mdns_method_request *e, *n;
	if (!state)
		return;

	/* Drop all DNS lookup request state. Triggering a timeout event and cleanup for mslookup client users will
	 * happen in the mslookup_client.c, we will simply stop responding from this lookup method. */
	llist_for_each_entry_safe(e, n, &state->requests, entry) {
		llist_del(&e->entry);
	}

	osmo_mdns_sock_cleanup(state->mc);
}

/*! Initialize the mDNS lookup method.
 * \param[in] client  the client to attach the method to.
 * \param[in] ip  IPv4 or IPv6 address string.
 * \param[in] port  The port to bind to.
 * \param[in] initial_packet_id  Used in the first mslookup query, then increased by one in each following query. All
 *				 servers answer to each query with the same packet ID. Set to -1 to use a random
 *				 initial ID (recommended unless you need deterministic output). This ID is for visually
 *				 distinguishing the packets in packet sniffers, the mslookup client uses not just the
 *				 ID, but all query parameters (service type, ID, ID type), to determine if a reply is
 *				 relevant.
 * \param[in] domain_suffix  is appended to each domain in the queries to avoid colliding with the top-level domains
 *                           administrated by IANA. Example: "mdns.osmocom.org" */
struct osmo_mslookup_client_method *osmo_mslookup_client_add_mdns(struct osmo_mslookup_client *client, const char *ip,
								  uint16_t port, int initial_packet_id,
								  const char *domain_suffix)
{
	struct osmo_mdns_method_state *state;
	struct osmo_mslookup_client_method *m;

	m = talloc_zero(client, struct osmo_mslookup_client_method);
	OSMO_ASSERT(m);

	state = talloc_zero(m, struct osmo_mdns_method_state);
	OSMO_ASSERT(state);
	INIT_LLIST_HEAD(&state->requests);
	if (osmo_sockaddr_str_from_str(&state->bind_addr, ip, port)) {
		LOGP(DMSLOOKUP, LOGL_ERROR, "mslookup mDNS: invalid address/port: %s %u\n",
		     ip, port);
		goto error_cleanup;
	}

	if (initial_packet_id == -1) {
		if (osmo_get_rand_id((uint8_t *)&state->next_packet_id, 2) < 0) {
			LOGP(DMSLOOKUP, LOGL_ERROR, "mslookup mDNS: failed to generate random initial packet ID\n");
			goto error_cleanup;
		}
	} else
		state->next_packet_id = initial_packet_id;

	state->client = client;
	state->domain_suffix = domain_suffix;

	state->mc = osmo_mdns_sock_init(state, ip, port, mdns_method_recv, state, 0);
	if (!state->mc)
		goto error_cleanup;

	*m = (struct osmo_mslookup_client_method){
		.name = "mDNS",
		.priv = state,
		.request = mdns_method_request,
		.request_cleanup = mdns_method_request_cleanup,
		.destruct = mdns_method_destruct,
	};

	osmo_mslookup_client_method_add(client, m);
	return m;

error_cleanup:
	talloc_free(m);
	return NULL;
}

const struct osmo_sockaddr_str *osmo_mslookup_client_method_mdns_get_bind_addr(struct osmo_mslookup_client_method *dns_method)
{
	struct osmo_mdns_method_state *state;
	if (!dns_method || !dns_method->priv)
		return NULL;
	state = dns_method->priv;
	return &state->bind_addr;
}

const char *osmo_mslookup_client_method_mdns_get_domain_suffix(struct osmo_mslookup_client_method *dns_method)
{
	struct osmo_mdns_method_state *state;
	if (!dns_method || !dns_method->priv)
		return NULL;
	state = dns_method->priv;
	return state->domain_suffix;
}
