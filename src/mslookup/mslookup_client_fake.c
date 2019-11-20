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

#include <osmocom/hlr/logging.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_fake.h>

#include <string.h>

/* Fake mslookup method */

struct fake_lookup_state {
	struct osmo_mslookup_client *client;
	struct llist_head requests;
	struct osmo_timer_list async_response_timer;
	struct osmo_mslookup_fake_response *responses;
	size_t responses_len;
};

struct fake_lookup_request {
	struct llist_head entry;
	uint32_t request_handle;
	struct osmo_mslookup_query query;
	struct timeval received_at;
};

/*! Args for osmo_timer_schedule: seconds and microseconds. */
#define ASYNC_RESPONSE_PERIOD 0, (1e6 / 10)
static void fake_lookup_async_response(void *state);

static void fake_lookup_request(struct osmo_mslookup_client_method *method,
				const struct osmo_mslookup_query *query,
				uint32_t request_handle)
{
	struct fake_lookup_state *state = method->priv;
	char buf[256];
	LOGP(DMSLOOKUP, LOGL_DEBUG, "%s(%s)\n", __func__, osmo_mslookup_result_name_b(buf, sizeof(buf), query, NULL));

	/* A real implementation would send packets to some remote server.
	 * Here this is simulated: add to the list of requests, which fake_lookup_async_response() will reply upon
	 * according to the test data listing the replies that the test wants to generate. */

	struct fake_lookup_request *r = talloc_zero(method->client, struct fake_lookup_request);
	*r = (struct fake_lookup_request){
		.request_handle = request_handle,
		.query = *query,
	};
	osmo_gettimeofday(&r->received_at, NULL);
	llist_add_tail(&r->entry, &state->requests);
}

static void fake_lookup_request_cleanup(struct osmo_mslookup_client_method *method,
					uint32_t request_handle)
{
	struct fake_lookup_state *state = method->priv;

	/* Tear down any state associated with this handle. */
	struct fake_lookup_request *r;
	llist_for_each_entry(r, &state->requests, entry) {
		if (r->request_handle != request_handle)
			continue;
		llist_del(&r->entry);
		talloc_free(r);
		LOGP(DMSLOOKUP, LOGL_DEBUG, "%s() ok\n", __func__);
		return;
	}
	LOGP(DMSLOOKUP, LOGL_DEBUG, "%s() FAILED\n", __func__);
}

static void fake_lookup_async_response(void *data)
{
	struct fake_lookup_state *state = data;
	struct fake_lookup_request *req, *n;
	struct timeval now;
	char str[256];

	osmo_gettimeofday(&now, NULL);

	llist_for_each_entry_safe(req, n, &state->requests, entry) {
		struct osmo_mslookup_fake_response *resp;

		for (resp = state->responses;
		     (resp - state->responses) < state->responses_len;
		     resp++) {
			struct timeval diff;

			if (resp->sent)
				continue;
			if (osmo_mslookup_id_cmp(&req->query.id, &resp->for_id) != 0)
				continue;
			if (strcmp(req->query.service, resp->for_service) != 0)
				continue;

			timersub(&now, &req->received_at, &diff);
			if (timercmp(&diff, &resp->time_to_reply, <))
				continue;

			/* It's time to reply to this request. */
			LOGP(DMSLOOKUP, LOGL_DEBUG, "osmo_mslookup_client_rx_result(): %s\n",
			     osmo_mslookup_result_name_b(str, sizeof(str), &req->query, &resp->result));
			osmo_mslookup_client_rx_result(state->client, req->request_handle, &resp->result);
			resp->sent = true;

			/* The req will have been cleaned up now, so we must not iterate over state->responses anymore
			 * with this req. */
			break;
		}
	}

	osmo_timer_schedule(&state->async_response_timer, ASYNC_RESPONSE_PERIOD);
}

struct osmo_mslookup_client_method *osmo_mslookup_client_add_fake(struct osmo_mslookup_client *client,
								  struct osmo_mslookup_fake_response *responses,
								  size_t responses_len)
{
	struct osmo_mslookup_client_method *method = talloc_zero(client, struct osmo_mslookup_client_method);
	OSMO_ASSERT(method);

	struct fake_lookup_state *state = talloc_zero(method, struct fake_lookup_state);
	OSMO_ASSERT(state);
	*state = (struct fake_lookup_state){
		.client = client,
		.responses = responses,
		.responses_len = responses_len,
	};
	INIT_LLIST_HEAD(&state->requests);

	*method = (struct osmo_mslookup_client_method){
		.name = "fake",
		.priv = state,
		.request = fake_lookup_request,
		.request_cleanup = fake_lookup_request_cleanup,
	};

	osmo_timer_setup(&state->async_response_timer, fake_lookup_async_response, state);
	osmo_mslookup_client_method_add(client, method);

	osmo_timer_schedule(&state->async_response_timer, ASYNC_RESPONSE_PERIOD);
	return method;
}
