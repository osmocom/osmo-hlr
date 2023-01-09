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
#include <osmocom/gsupclient/cni_peer_id.h>
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
	const struct osmo_sockaddr_str *remote_hlr_addr;

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
		if (g_hlr->mslookup.client.subscr_create_on_demand_fallback &&
		    db_subscr_exists_by_imsi(g_hlr->dbc, query->id.imsi) != 0) {
			struct osmo_gsup_req *req = proxy_deferred_gsup_req_get_by_imsi(proxy, query->id.imsi);
			if (req && req->gsup.message_type == OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST)
				dgsm_fallback_to_hlr(req);
		}
		proxy_subscr_del(proxy, query->id.imsi);
		return;
	}

	if (osmo_sockaddr_str_is_nonzero(&result->host_v4))
		remote_hlr_addr = &result->host_v4;
	else if (osmo_sockaddr_str_is_nonzero(&result->host_v6))
		remote_hlr_addr = &result->host_v6;
	else {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "Invalid address for remote HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		proxy_subscr_del(proxy, query->id.imsi);
		return;
	}

	if (proxy_subscr_get_by_imsi(&proxy_subscr, proxy, query->id.imsi)) {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "No proxy entry for mslookup result: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		return;
	}

	proxy_subscr_remote_hlr_resolved(proxy, &proxy_subscr, remote_hlr_addr);
}

/* Return true when the message has been handled by D-GSM. */
bool dgsm_check_forward_gsup_msg(struct osmo_gsup_req *req)
{
	struct proxy_subscr proxy_subscr;
	struct proxy *proxy = g_hlr->gs->proxy;
	struct osmo_mslookup_query query;
	struct osmo_mslookup_query_handling handling;
	uint32_t request_handle;

	/* If the IMSI is authorized in the local HLR, then we won't proxy */
	if (db_subscr_authorized_by_imsi(g_hlr->dbc, req->gsup.imsi) == 0)
		return false;
	/* unless configuration tells us to do otherwise. */
	if (!g_hlr->mslookup.ignore_created_on_demand && !g_hlr->mslookup.auth_imsi_only &&
	    db_subscr_exists_by_imsi(g_hlr->dbc, req->gsup.imsi) == 0)
		return false;

	if (!g_hlr->mslookup.auth_imsi_only && !(g_hlr->mslookup.ignore_created_on_demand &&
	    db_subscr_is_created_on_demand_by_imsi(g_hlr->dbc, req->gsup.imsi,
						   g_hlr->subscr_create_on_demand.rand_msisdn_len) == 0))
		return false;

	/* Are we already forwarding this IMSI to a remote HLR? */
	if (proxy_subscr_get_by_imsi(&proxy_subscr, proxy, req->gsup.imsi) == 0) {
		proxy_subscr_forward_to_remote_hlr(proxy, &proxy_subscr, req);
		return true;
	}

	/* The IMSI is not known locally, so we want to proxy to a remote HLR, but no proxy entry exists yet. We need to
	 * look up the subscriber in remote HLRs via D-GSM mslookup, forward GSUP and reply once a result is back from
	 * there.  Defer message and kick off MS lookup. */

	/* Add a proxy entry without a remote address to indicate that we are busy querying for a remote HLR. */
	proxy_subscr = (struct proxy_subscr){};
	OSMO_STRLCPY_ARRAY(proxy_subscr.imsi, req->gsup.imsi);
	if (proxy_subscr_create_or_update(proxy, &proxy_subscr)) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "Failed to create proxy entry\n");
		return true;
	}

	/* Is a fixed gateway proxy configured? */
	if (osmo_sockaddr_str_is_nonzero(&g_hlr->mslookup.client.gsup_gateway_proxy)) {
		proxy_subscr_remote_hlr_resolved(proxy, &proxy_subscr, &g_hlr->mslookup.client.gsup_gateway_proxy);

		/* Proxy database modified, update info */
		if (proxy_subscr_get_by_imsi(&proxy_subscr, proxy, req->gsup.imsi)) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "Internal proxy error\n");
			return true;
		}

		proxy_subscr_forward_to_remote_hlr(proxy, &proxy_subscr, req);
		return true;
	}

	/* Kick off an mslookup for the remote HLR?  This check could be up first on the top, but do it only now so that
	 * if the mslookup client disconnected, we still continue to service open proxy entries. */
	if (!osmo_mslookup_client_active(g_hlr->mslookup.client.client)) {
		LOG_GSUP_REQ(req, LOGL_DEBUG, "mslookup client not running, cannot query remote home HLR\n");
		return false;
	}

	/* First spool message, then kick off mslookup. If the proxy denies this message type, then don't do anything. */
	if (proxy_subscr_forward_to_remote_hlr(proxy, &proxy_subscr, req)) {
		/* If the proxy denied forwarding, an error response was already generated. */
		return true;
	}

	query = (struct osmo_mslookup_query){
		.id = {
			.type = OSMO_MSLOOKUP_ID_IMSI,
		},
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
		/* mslookup seems to not be working. Try handling it locally. */
		return false;
	}

	return true;
}

void dgsm_init(void *ctx)
{
	dgsm_ctx = talloc_named_const(ctx, 0, "dgsm");
	INIT_LLIST_HEAD(&g_hlr->mslookup.server.local_site_services);

	g_hlr->mslookup.server.local_attach_max_age = OSMO_DGSM_DEFAULT_LOCAL_ATTACH_MAX_AGE;

	g_hlr->mslookup.client.result_timeout_milliseconds = OSMO_DGSM_DEFAULT_RESULT_TIMEOUT_MS;

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

void dgsm_stop(void)
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
