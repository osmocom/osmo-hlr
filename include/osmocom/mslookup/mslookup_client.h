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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mslookup/mslookup.h>

struct osmo_mslookup_client;
struct osmo_mslookup_result;

typedef void (*osmo_mslookup_cb_t)(struct osmo_mslookup_client *client,
				   uint32_t request_handle,
				   const struct osmo_mslookup_query *query,
				   const struct osmo_mslookup_result *result);

/*! This handling information is passed along with a lookup request.
 * It tells the osmo_mslookup_client layer how to handle responses received from various mslookup methods (at the time
 * of writing only mDNS exists as a method, but the intention is to easily allow adding other methods in the future).
 * This query handling info is not seen by the individual method implementations, to clarify that it is the
 * osmo_mslookup_client layer that takes care of these details. */
struct osmo_mslookup_query_handling {
	bool search_all;

	/*! Wait at least this long before returning any results.
	 *
	 * If nonzero, result_cb will be called as soon as this delay has elapsed, either with the so far youngest age
	 * result, or with a "not found yet" result. After this delay has elapsed, receiving results will continue
	 * until result_timeout_milliseconds has elapsed.
	 *
	 * If zero, responses are fed to the result_cb right from the start, every time a younger aged result than
	 * before comes in.
	 *
	 * If a result with age == 0 is received, min_wait_milliseconds is ignored, the result is returned immediately
	 * and listening for responses ends.
	 *
	 * Rationale: If a subscriber has recently moved between sites, multiple results will arrive, and the youngest
	 * age wins. It can make sense to wait a minimum time for responses before determining the winning result.
	 *
	 * However, if no result or no valid result has arrived within a short period, the subscriber may be at a site
	 * that is far away or that is currently experiencing high latency. It is thus a good safety net to still
	 * receive results for an extended period of time.
	 *
	 * For some services, it is possible to establish links to every received result, and whichever link succeeds
	 * will be used (for example for SIP calls: first to pick up the call gets connected, the others are dropped
	 * silently).
	 */
	uint32_t min_wait_milliseconds;

	/*! Total time in milliseconds to listen for lookup responses.
	 *
	 * When this timeout elapses, osmo_mslookup_client_request_cancel() is called implicitly; Manually invoking
	 * osmo_mslookup_client_request_cancel() after result_timeout_milliseconds has elapsed is not necessary, but is
	 * still safe to do anyway.
	 *
	 * If zero, min_wait_milliseconds is also used as result_timeout_milliseconds; if that is also zero, a default
	 * timeout value is used.
	 *
	 * If result_timeout_milliseconds <= min_wait_milliseconds, then min_wait_milliseconds is used as
	 * result_timeout_milliseconds, i.e. the timeout triggers as soon as min_wait_milliseconds hits.
	 *
	 * osmo_mslookup_client_request_cancel() can be called any time to end the request.
	 */
	uint32_t result_timeout_milliseconds;

	/*! Invoked every time a result with a younger age than the previous result has arrived.
	 * To stop receiving results before result_timeout_milliseconds has elapsed, call
	 * osmo_mslookup_client_request_cancel().
	 */
	osmo_mslookup_cb_t result_cb;
};

uint32_t osmo_mslookup_client_request(struct osmo_mslookup_client *client,
				      const struct osmo_mslookup_query *query,
				      const struct osmo_mslookup_query_handling *handling);

void osmo_mslookup_client_request_cancel(struct osmo_mslookup_client *client, uint32_t request_handle);

struct osmo_mslookup_client *osmo_mslookup_client_new(void *ctx);
bool osmo_mslookup_client_active(struct osmo_mslookup_client *client);
void osmo_mslookup_client_free(struct osmo_mslookup_client *client);

/*! Describe a specific mslookup client method implementation. This struct is only useful for a lookup method
 * implementation to add itself to an osmo_mslookup_client, see for example osmo_mslookup_client_add_mdns(). */
struct osmo_mslookup_client_method {
	struct llist_head entry;

	/*! Human readable name of this lookup method. */
	const char *name;

	/*! Private data for the lookup method implementation. */
	void *priv;

	/*! Backpointer to the client this method is added to. */
	struct osmo_mslookup_client *client;

	/*! Launch a lookup query. Called from osmo_mslookup_client_request().
	 * The implementation returns results by calling osmo_mslookup_client_rx_result(). */
	void (*request)(struct osmo_mslookup_client_method *method,
			const struct osmo_mslookup_query *query,
			uint32_t request_handle);
	/*! End a lookup query. Called from osmo_mslookup_client_request_cancel(). It is guaranteed to be called
	 * exactly once per above request() invocation. (The API user is required to invoke
	 * osmo_mslookup_client_request_cancel() exactly once per osmo_mslookup_client_request().) */
	void (*request_cleanup)(struct osmo_mslookup_client_method *method,
				uint32_t request_handle);

	/*! The mslookup_client is removing this method, clean up all open requests, lists and allocations. */
	void (*destruct)(struct osmo_mslookup_client_method *method);
};

void osmo_mslookup_client_method_add(struct osmo_mslookup_client *client,
				     struct osmo_mslookup_client_method *method);
bool osmo_mslookup_client_method_del(struct osmo_mslookup_client *client,
				     struct osmo_mslookup_client_method *method);
void osmo_mslookup_client_rx_result(struct osmo_mslookup_client *client, uint32_t request_handle,
				    const struct osmo_mslookup_result *result);
