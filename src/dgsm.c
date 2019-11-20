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

#include <errno.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/gsupclient/gsup_peer_id.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/gsup_router.h>
#include <osmocom/hlr/gsup_server.h>
#include <osmocom/hlr/dgsm.h>
#include <osmocom/hlr/proxy.h>
#include <osmocom/hlr/remote_hlr.h>
#include <osmocom/hlr/mslookup_server.h>
#include <osmocom/hlr/mslookup_server_mdns.h>
#include <osmocom/hlr/dgsm.h>

void *dgsm_ctx = NULL;

static void resolve_hlr_result_cb(struct osmo_mslookup_client *client,
				  uint32_t request_handle,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result)
{
	struct proxy *proxy = g_hlr->gs->proxy;
	struct proxy_subscr proxy_subscr;
	const struct osmo_sockaddr_str *use_addr;
	struct remote_hlr *remote_hlr;

	/* A remote HLR is answering back, indicating that it is the home HLR for a given IMSI.
	 * There should be a mostly empty proxy entry for that IMSI.
	 * Add the remote address data in the proxy. */
	if (query->id.type != OSMO_MSLOOKUP_ID_IMSI) {
		LOGP(DDGSM, LOGL_ERROR, "Expected IMSI ID type in mslookup query+result: %s\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		return;
	}

	if (result->rc != OSMO_MSLOOKUP_RC_RESULT) {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "Failed to resolve remote HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		proxy_subscr_del(proxy, query->id.imsi);
		return;
	}

	if (osmo_sockaddr_str_is_nonzero(&result->host_v4))
		use_addr = &result->host_v4;
	else if (osmo_sockaddr_str_is_nonzero(&result->host_v6))
		use_addr = &result->host_v6;
	else {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "Invalid address for remote HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		proxy_subscr_del(proxy, query->id.imsi);
		return;
	}

	remote_hlr = remote_hlr_get(use_addr, true);
	if (!remote_hlr) {
		proxy_subscr_del(proxy, query->id.imsi);
		return;
	}

	if (proxy_subscr_get_by_imsi(&proxy_subscr, proxy, query->id.imsi)) {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "No proxy entry for mslookup result: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		return;
	}

	/* The remote HLR already exists and is connected. Messages for this IMSI were spooled because we did not know
	 * which remote HLR was responsible. Now we know, send this IMSI's messages now. */
	LOG_DGSM(query->id.imsi, LOGL_DEBUG, "Resolved remote HLR, sending spooled GSUP messages: %s\n",
		 osmo_mslookup_result_name_c(OTC_SELECT, query, result));

	proxy_subscr_remote_hlr_resolved(proxy, &proxy_subscr, remote_hlr);

	if (!remote_hlr->gsupc || !remote_hlr->gsupc->is_connected) {
		LOG_REMOTE_HLR(remote_hlr, LOGL_DEBUG, "Waiting for link-up\n");
		return;
	}
	proxy_subscr_remote_hlr_up(proxy, &proxy_subscr, remote_hlr);
}

/* Return true when the message has been handled by D-GSM. */
bool dgsm_check_forward_gsup_msg(struct osmo_gsup_req *req)
{
	struct proxy_subscr proxy_subscr;
	struct proxy *proxy = g_hlr->gs->proxy;
	struct osmo_mslookup_query query;
	struct osmo_mslookup_query_handling handling;
	uint32_t request_handle;

	/* If the IMSI is known in the local HLR, then we won't proxy. */
	if (db_subscr_exists_by_imsi(g_hlr->dbc, req->gsup.imsi) == 0)
		return false;

	/* Are we already forwarding this IMSI to a remote HLR? */
	if (proxy_subscr_get_by_imsi(&proxy_subscr, proxy, req->gsup.imsi) == 0)
		goto yes_we_are_proxying;

	/* The IMSI is not known locally, so we want to proxy to a remote HLR, but no proxy entry exists yet. We need to
	 * look up the subscriber in remote HLRs via D-GSM mslookup, forward GSUP and reply once a result is back from
	 * there.  Defer message and kick off MS lookup. */

	/* Add a proxy entry without a remote address to indicate that we are busy querying for a remote HLR. */
	proxy_subscr = (struct proxy_subscr){};
	OSMO_STRLCPY_ARRAY(proxy_subscr.imsi, req->gsup.imsi);
	if (proxy_subscr_create_or_update(proxy, &proxy_subscr)) {
		LOG_DGSM(req->gsup.imsi, LOGL_ERROR, "Failed to create proxy entry\n");
		return false;
	}

	/* Is a fixed gateway proxy configured? */
	if (osmo_sockaddr_str_is_nonzero(&g_hlr->mslookup.client.gsup_gateway_proxy)) {
		struct remote_hlr *gsup_gateway_proxy = remote_hlr_get(&g_hlr->mslookup.client.gsup_gateway_proxy, true);
		if (!gsup_gateway_proxy) {
			LOG_DGSM(req->gsup.imsi, LOGL_ERROR,
				 "Failed to set up fixed gateway proxy " OSMO_SOCKADDR_STR_FMT "\n",
				 OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.client.gsup_gateway_proxy));
			return false;
		}

		proxy_subscr_remote_hlr_resolved(proxy, &proxy_subscr, gsup_gateway_proxy);

		/* Update info */
		if (proxy_subscr_get_by_imsi(&proxy_subscr, proxy, req->gsup.imsi)) {
			LOG_DGSM(req->gsup.imsi, LOGL_ERROR, "Proxy entry disappeared\n");
			return false;
		}
		goto yes_we_are_proxying;
	}

	/* Kick off an mslookup for the remote HLR. */
	if (!g_hlr->mslookup.client.client) {
		LOG_GSUP_REQ(req, LOGL_DEBUG, "mslookup client not running, cannot query remote home HLR\n");
		return false;
	}

	query = (struct osmo_mslookup_query){
		.id = {
			.type = OSMO_MSLOOKUP_ID_IMSI,
		}
	};
	OSMO_STRLCPY_ARRAY(query.id.imsi, req->gsup.imsi);
	OSMO_STRLCPY_ARRAY(query.service, OSMO_MSLOOKUP_SERVICE_HLR_GSUP);
	handling = (struct osmo_mslookup_query_handling){
		.min_wait_milliseconds = g_hlr->mslookup.client.result_timeout_milliseconds,
		.result_cb = resolve_hlr_result_cb,
	};
	request_handle = osmo_mslookup_client_request(g_hlr->mslookup.client.client, &query, &handling);
	if (!request_handle) {
		LOG_DGSM(req->gsup.imsi, LOGL_ERROR, "Error dispatching mslookup query for home HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, &query, NULL));
		proxy_subscr_del(proxy, req->gsup.imsi);
		return false;
	}

yes_we_are_proxying:

	/* If the remote HLR is already known, directly forward the GSUP message; otherwise, spool the GSUP message
	 * until the remote HLR will respond / until timeout aborts. */
	proxy_subscr_forward_to_remote_hlr(proxy, &proxy_subscr, req);
	return true;
}

void dgsm_init(void *ctx)
{
	dgsm_ctx = talloc_named_const(ctx, 0, "dgsm");
	INIT_LLIST_HEAD(&g_hlr->mslookup.server.local_site_services);

	g_hlr->mslookup.server.local_attach_max_age = 60 * 60;

	g_hlr->mslookup.client.result_timeout_milliseconds = 2000;

	g_hlr->gsup_unit_name.unit_name = "HLR";
	g_hlr->gsup_unit_name.serno = "unnamed-HLR";
	g_hlr->gsup_unit_name.swversion = PACKAGE_NAME "-" PACKAGE_VERSION;

	osmo_sockaddr_str_from_str(&g_hlr->mslookup.server.mdns.bind_addr,
				   OSMO_MSLOOKUP_MDNS_IP4, OSMO_MSLOOKUP_MDNS_PORT);
	osmo_sockaddr_str_from_str(&g_hlr->mslookup.client.mdns.query_addr,
				   OSMO_MSLOOKUP_MDNS_IP4, OSMO_MSLOOKUP_MDNS_PORT);
}

void dgsm_start(void *ctx)
{
	g_hlr->mslookup.client.client = osmo_mslookup_client_new(dgsm_ctx);
	OSMO_ASSERT(g_hlr->mslookup.client.client);
	g_hlr->mslookup.allow_startup = true;
	mslookup_server_mdns_config_apply();
	dgsm_mdns_client_config_apply();
}

void dgsm_stop()
{
	g_hlr->mslookup.allow_startup = false;
	mslookup_server_mdns_config_apply();
	dgsm_mdns_client_config_apply();
}

void dgsm_mdns_client_config_apply(void)
{
	/* Check whether to start/stop/restart mDNS client */
	const struct osmo_sockaddr_str *current_bind_addr;
	const char *current_domain_suffix;
	current_bind_addr = osmo_mslookup_client_method_mdns_get_bind_addr(g_hlr->mslookup.client.mdns.running);
	current_domain_suffix = osmo_mslookup_client_method_mdns_get_domain_suffix(g_hlr->mslookup.client.mdns.running);

	bool should_run = g_hlr->mslookup.allow_startup
		&& g_hlr->mslookup.client.enable && g_hlr->mslookup.client.mdns.enable;

	bool should_stop = g_hlr->mslookup.client.mdns.running &&
		(!should_run
		 || osmo_sockaddr_str_cmp(&g_hlr->mslookup.client.mdns.query_addr,
					  current_bind_addr)
		 || strcmp(g_hlr->mslookup.client.mdns.domain_suffix,
			   current_domain_suffix));

	if (should_stop) {
		osmo_mslookup_client_method_del(g_hlr->mslookup.client.client, g_hlr->mslookup.client.mdns.running);
		g_hlr->mslookup.client.mdns.running = NULL;
		LOGP(DDGSM, LOGL_NOTICE, "Stopped mslookup mDNS client\n");
	}

	if (should_run && !g_hlr->mslookup.client.mdns.running) {
		g_hlr->mslookup.client.mdns.running =
			osmo_mslookup_client_add_mdns(g_hlr->mslookup.client.client,
						      g_hlr->mslookup.client.mdns.query_addr.ip,
						      g_hlr->mslookup.client.mdns.query_addr.port,
						      -1,
						      g_hlr->mslookup.client.mdns.domain_suffix);
		if (!g_hlr->mslookup.client.mdns.running)
			LOGP(DDGSM, LOGL_ERROR, "Failed to start mslookup mDNS client with target "
			     OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.client.mdns.query_addr));
		else
			LOGP(DDGSM, LOGL_NOTICE, "Started mslookup mDNS client, sending mDNS requests to multicast "
			     OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.client.mdns.query_addr));
	}

	if (g_hlr->mslookup.client.enable && osmo_sockaddr_str_is_nonzero(&g_hlr->mslookup.client.gsup_gateway_proxy))
			LOGP(DDGSM, LOGL_NOTICE,
			     "mslookup client: all GSUP requests for unknown IMSIs will be forwarded to"
			     " gateway-proxy " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.client.gsup_gateway_proxy));
}
