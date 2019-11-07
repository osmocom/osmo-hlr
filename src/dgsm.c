#include <errno.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>
#include <osmocom/gsupclient/gsup_client.h>
#include "logging.h"
#include "hlr.h"
#include "db.h"
#include "gsup_router.h"
#include "dgsm.h"
#include "proxy.h"
#include "remote_hlr.h"
#include "mslookup_server_mdns.h"
#include "global_title.h"

void *dgsm_ctx = NULL;

const struct global_title dgsm_config_msc_wildcard = {};

struct dgsm_msc_config *dgsm_config_msc_get(const struct global_title *msc_name, bool create)
{
	struct dgsm_msc_config *msc;

	if (!msc_name)
		return NULL;

	llist_for_each_entry(msc, &g_hlr->mslookup.vty.server.msc_configs, entry) {
		if (global_title_cmp(&msc->name, msc_name))
			continue;
		return msc;
	}
	if (!create)
		return NULL;

	msc = talloc_zero(dgsm_ctx, struct dgsm_msc_config);
	OSMO_ASSERT(msc);
	INIT_LLIST_HEAD(&msc->service_hosts);
	msc->name = *msc_name;
	return msc;
}

struct dgsm_service_host *dgsm_config_msc_service_get(struct dgsm_msc_config *msc, const char *service, bool create)
{
	struct dgsm_service_host *e;
	if (!msc)
		return NULL;

	llist_for_each_entry(e, &msc->service_hosts, entry) {
		if (!strcmp(e->service, service))
			return e;
	}

	if (!create)
		return NULL;

	e = talloc_zero(msc, struct dgsm_service_host);
	OSMO_ASSERT(e);
	OSMO_STRLCPY_ARRAY(e->service, service);
	llist_add_tail(&e->entry, &msc->service_hosts);
	return e;
}

struct dgsm_service_host *dgsm_config_service_get(const struct global_title *msc_name, const char *service)
{
	struct dgsm_msc_config *msc = dgsm_config_msc_get(msc_name, false);
	if (!msc)
		return NULL;
	return dgsm_config_msc_service_get(msc, service, false);
}

int dgsm_config_msc_service_set(struct dgsm_msc_config *msc, const char *service, const struct osmo_sockaddr_str *addr)
{
	struct dgsm_service_host *e;

	if (!service || !service[0]
	    || strlen(service) > OSMO_MSLOOKUP_SERVICE_MAXLEN)
		return -EINVAL;
	if (!addr || !osmo_sockaddr_str_is_nonzero(addr))
		return -EINVAL;

	e = dgsm_config_msc_service_get(msc, service, true);
	if (!e)
		return -EINVAL;

	switch (addr->af) {
	case AF_INET:
		e->host_v4 = *addr;
		break;
	case AF_INET6:
		e->host_v6 = *addr;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int dgsm_config_service_set(const struct global_title *msc_name, const char *service, const struct osmo_sockaddr_str *addr)
{
	struct dgsm_msc_config *msc;

	msc = dgsm_config_msc_get(msc_name, true);
	if (!msc)
		return -EINVAL;

	return dgsm_config_msc_service_set(msc, service, addr);
}

int dgsm_config_msc_service_del(struct dgsm_msc_config *msc, const char *service, const struct osmo_sockaddr_str *addr)
{
	struct dgsm_service_host *e, *n;

	if (!msc)
		return -ENOENT;

	llist_for_each_entry_safe(e, n, &msc->service_hosts, entry) {
		if (service && strcmp(service, e->service))
			continue;

		if (addr) {
			if (!osmo_sockaddr_str_cmp(addr, &e->host_v4)) {
				e->host_v4 = (struct osmo_sockaddr_str){};
				/* Removed one addr. If the other is still there, keep the entry. */
				if (osmo_sockaddr_str_is_nonzero(&e->host_v6))
					continue;
			} else if (!osmo_sockaddr_str_cmp(addr, &e->host_v6)) {
				e->host_v6 = (struct osmo_sockaddr_str){};
				/* Removed one addr. If the other is still there, keep the entry. */
				if (osmo_sockaddr_str_is_nonzero(&e->host_v4))
					continue;
			} else
				/* No addr match, keep the entry. */
				continue;
			/* Addr matched and none is left. Delete. */
		}
		llist_del(&e->entry);
		talloc_free(e);
	}
	return 0;
}

int dgsm_config_service_del(const struct global_title *msc_name,
			    const char *service, const struct osmo_sockaddr_str *addr)
{
	return dgsm_config_msc_service_del(dgsm_config_msc_get(msc_name, false),
					   service, addr);
}

static void *dgsm_pending_messages_ctx = NULL;

struct pending_gsup_message {
	struct llist_head entry;
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	struct msgb *gsup;
	struct timeval received_at;
};
static LLIST_HEAD(pending_gsup_messages);

/* Defer a GSUP message until we know a remote HLR to proxy to.
 * Where to send this GSUP message is indicated by its IMSI: as soon as an MS lookup has yielded the IMSI's home HLR,
 * that's where the message should go. */
static void defer_gsup_message(const struct osmo_gsup_message *gsup)
{
	struct pending_gsup_message *m;

	m = talloc_zero(dgsm_pending_messages_ctx, struct pending_gsup_message);
	OSMO_ASSERT(m);
	timestamp_update(&m->received_at);
	OSMO_STRLCPY_ARRAY(m->imsi, gsup->imsi);

	/* Since osmo_gsup_message has a lot of dangling external pointers, the only way to defer the message is to
	 * store it encoded. */
	m->gsup = osmo_gsup_msgb_alloc("GSUP proxy defer");
	if (osmo_gsup_encode(m->gsup, gsup)) {
		LOGP(DDGSM, LOGL_ERROR, "GSUP proxy defer: unable to encode GSUP message: %s %s\n",
		     osmo_gsup_message_type_name(gsup->message_type), osmo_quote_str(gsup->imsi, -1));
		msgb_free(m->gsup);
		talloc_free(m);
		return;
	}

	llist_add_tail(&m->entry, &pending_gsup_messages);
}

/* Unable to resolve remote HLR for this IMSI, Answer with error back to the sender. */
static void defer_gsup_message_err(struct pending_gsup_message *m)
{
	struct osmo_gsup_message gsup;
	struct osmo_gsup_conn *conn;

	printf("whaha %p %p\n", m, m->gsup);
	if (osmo_gsup_decode(m->gsup->data, m->gsup->len, &gsup)) {
		LOGP(DDGSM, LOGL_ERROR, "Unable to decode deferred GSUP message for %s\n", m->imsi);
		msgb_free(m->gsup);
		m->gsup = NULL;
		return;
	}

	conn = gsup_route_find(g_hlr->gs, gsup.source_name, gsup.source_name_len);
	if (!conn) {
		LOGP(DDGSM, LOGL_ERROR, "Unable to send error reply for %s %s, source_name is not known: %s\n",
		     osmo_gsup_message_type_name(gsup.message_type), gsup.imsi,
		     osmo_quote_str_c(OTC_SELECT, (char*)gsup.source_name, gsup.source_name_len));
		return;
	}
	osmo_gsup_conn_send_err_reply(conn, &gsup, GMM_CAUSE_IMSI_UNKNOWN);
	msgb_free(m->gsup);
	m->gsup = NULL;
}

/* Forward spooled message for this IMSI to remote HLR. */
static void defer_gsup_message_send(struct pending_gsup_message *m, struct remote_hlr *remote_hlr)
{
	/* To be able to log what we are forwarding, the spooled message needs to be decoded. Do that only if debug
	 * logging is enabled and decoding succeeds. If decoding fails, don't change anything about the code path, so
	 * that logging doesn't affect how osmo-hlr works. */
	if (log_check_level(DDGSM, LOGL_DEBUG)) {
		struct osmo_gsup_message gsup;
		if (osmo_gsup_decode(m->gsup->data, m->gsup->len, &gsup))
			LOGP(DDGSM, LOGL_ERROR, "Unable to decode deferred GSUP message for %s\n", m->imsi);
		else
			LOGP(DDGSM, LOGL_DEBUG,
			     "Forwarding deferred GSUP: %s %s from %s to " OSMO_SOCKADDR_STR_FMT "\n",
			     osmo_gsup_message_type_name(gsup.message_type), gsup.imsi,
			     osmo_quote_str_c(OTC_SELECT, (char*)gsup.source_name, gsup.source_name_len),
			     OSMO_SOCKADDR_STR_FMT_ARGS(&remote_hlr->addr));
	}

	/* If sending fails, still discard. */
	if (!remote_hlr->gsupc || !remote_hlr->gsupc->is_connected) {
		LOGP(DDGSM, LOGL_ERROR, "GSUP link to remote HLR is not connected: " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&remote_hlr->addr));
		defer_gsup_message_err(m);
		return;
	}

	remote_hlr_msgb_send(remote_hlr, m->gsup);
}

/* Result of looking for remote HLR. If it failed, pass remote_hlr as NULL. */
static void defer_gsup_message_pop(const char *imsi, struct remote_hlr *remote_hlr)
{
	struct pending_gsup_message *m, *n;

	if (remote_hlr) 
		LOG_DGSM(imsi, LOGL_DEBUG, "Sending spooled GSUP messages to remote HLR at " OSMO_SOCKADDR_STR_FMT "\n",
			 OSMO_SOCKADDR_STR_FMT_ARGS(&remote_hlr->addr));
	else
		LOG_DGSM(imsi, LOGL_ERROR, "No remote HLR found, dropping spooled GSUP messages\n");

	llist_for_each_entry_safe(m, n, &pending_gsup_messages, entry) {
		if (strcmp(m->imsi, imsi))
			continue;

		if (!remote_hlr)
			defer_gsup_message_err(m);
		else
			defer_gsup_message_send(m, remote_hlr);

		llist_del(&m->entry);
		talloc_free(m);
	}
}

void dgsm_send_to_remote_hlr(const struct proxy_subscr *proxy_subscr, const struct osmo_gsup_message *gsup)
{
	struct remote_hlr *remote_hlr;

	if (!osmo_sockaddr_str_is_nonzero(&proxy_subscr->remote_hlr_addr)) {
		/* We don't know the remote target yet. Still waiting for an MS lookup response. */
		LOG_DGSM(gsup->imsi, LOGL_DEBUG, "GSUP Proxy: deferring until remote proxy is known: %s\n",
			 osmo_gsup_message_type_name(gsup->message_type));
		defer_gsup_message(gsup);
		return;
	}

	LOG_DGSM(gsup->imsi, LOGL_DEBUG, "GSUP Proxy: forwarding to " OSMO_SOCKADDR_STR_FMT ": %s\n",
		 OSMO_SOCKADDR_STR_FMT_ARGS(&proxy_subscr->remote_hlr_addr),
		 osmo_gsup_message_type_name(gsup->message_type));
	
	remote_hlr = remote_hlr_get(&proxy_subscr->remote_hlr_addr, true);
	if (!remote_hlr) {
		LOG_DGSM(gsup->imsi, LOGL_ERROR, "Failed to establish connection to remote HLR " OSMO_SOCKADDR_STR_FMT
			 ", discarding GSUP: %s\n",
			 OSMO_SOCKADDR_STR_FMT_ARGS(&proxy_subscr->remote_hlr_addr),
			 osmo_gsup_message_type_name(gsup->message_type));
		return;
	}

	if (!remote_hlr->gsupc || !remote_hlr->gsupc->is_connected) {
		/* GSUP link is still busy establishing... */
		LOG_DGSM(gsup->imsi, LOGL_DEBUG, "GSUP Proxy: deferring until link to remote proxy is up: %s\n",
			 osmo_gsup_message_type_name(gsup->message_type));
		defer_gsup_message(gsup);
		return;
	}

	remote_hlr_gsup_send(remote_hlr, gsup);
}

static void resolve_hlr_result_cb(struct osmo_mslookup_client *client,
				  uint32_t request_handle,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result)
{
	struct proxy *proxy = g_hlr->gsup_proxy.cs;
	const struct proxy_subscr *proxy_subscr;
	struct proxy_subscr proxy_subscr_new;
	struct remote_hlr *remote_hlr;

	/* A remote HLR is answering back, indicating that it is the home HLR for a given IMSI.
	 * There should be a mostly empty proxy entry for that IMSI.
	 * Add the remote address data in the proxy. */
	if (query->id.type != OSMO_MSLOOKUP_ID_IMSI) {
		LOGP(DDGSM, LOGL_ERROR, "Expected IMSI ID type in mslookup query+result: %s\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		return;
	}

	proxy_subscr = proxy_subscr_get_by_imsi(proxy, query->id.imsi);
	if (!proxy_subscr) {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "No proxy entry for mslookup result: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		defer_gsup_message_pop(query->id.imsi, NULL);
		return;
	}

	if (result->rc != OSMO_MSLOOKUP_RC_OK) {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "Failed to resolve remote HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		defer_gsup_message_pop(query->id.imsi, NULL);
		proxy_subscr_del(proxy, proxy_subscr->imsi);
		return;
	}

	/* Store the address. Make a copy to modify. */
	proxy_subscr_new = *proxy_subscr;
	proxy_subscr = &proxy_subscr_new;
	if (osmo_sockaddr_str_is_nonzero(&result->host_v4))
		proxy_subscr_new.remote_hlr_addr = result->host_v4;
	else if (osmo_sockaddr_str_is_nonzero(&result->host_v6))
		proxy_subscr_new.remote_hlr_addr = result->host_v6;
	else {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "Invalid address for remote HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		defer_gsup_message_pop(query->id.imsi, NULL);
		proxy_subscr_del(proxy, proxy_subscr->imsi);
		return;
	}

	if (proxy_subscr_update(proxy, proxy_subscr)) {
		LOG_DGSM(query->id.imsi, LOGL_ERROR, "Failed to store proxy entry for remote HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		defer_gsup_message_pop(query->id.imsi, NULL);
		proxy_subscr_del(proxy, proxy_subscr->imsi);
		return;
	}
	LOG_DGSM(proxy_subscr->imsi, LOGL_DEBUG, "Stored remote hlr address for this IMSI: " OSMO_SOCKADDR_STR_FMT "\n",
		 OSMO_SOCKADDR_STR_FMT_ARGS(&proxy_subscr->remote_hlr_addr));

	remote_hlr = remote_hlr_get(&proxy_subscr->remote_hlr_addr, true);
	if (!remote_hlr) {
		defer_gsup_message_pop(query->id.imsi, NULL);
		proxy_subscr_del(proxy, proxy_subscr->imsi);
		return;
	}

	if (!remote_hlr->gsupc || !remote_hlr->gsupc->is_connected) {
		LOG_DGSM(query->id.imsi, LOGL_DEBUG, "Resolved remote HLR, waiting for link-up: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		return;
	}

	LOG_DGSM(query->id.imsi, LOGL_DEBUG, "Resolved remote HLR, sending spooled GSUP messages: %s\n",
		 osmo_mslookup_result_name_c(OTC_SELECT, query, result));
	defer_gsup_message_pop(query->id.imsi, remote_hlr);
}

static bool remote_hlr_up_yield(struct proxy *proxy, const struct proxy_subscr *proxy_subscr, void *data)
{
	struct remote_hlr *remote_hlr = data;
	defer_gsup_message_pop(proxy_subscr->imsi, remote_hlr);
	return true;
}

void dgsm_remote_hlr_up(struct remote_hlr *remote_hlr)
{
	LOGP(DDGSM, LOGL_NOTICE, "link to remote HLR is up, sending spooled GSUP messages: " OSMO_SOCKADDR_STR_FMT "\n",
	     OSMO_SOCKADDR_STR_FMT_ARGS(&remote_hlr->addr));
	/* Send all spooled GSUP messaged for IMSIs that are waiting for this link to establish. */
	proxy_subscrs_get_by_remote_hlr(g_hlr->gsup_proxy.cs, &remote_hlr->addr, remote_hlr_up_yield, remote_hlr);
}

/* Return true when the message has been handled by D-GSM. */
bool dgsm_check_forward_gsup_msg(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup)
{
	const struct proxy_subscr *proxy_subscr;
	struct proxy_subscr proxy_subscr_new;
	struct gsup_route *route;
	struct osmo_gsup_message gsup_copy;
	struct proxy *proxy;
	struct osmo_mslookup_query query;
	struct osmo_mslookup_query_handling handling;
	uint32_t request_handle;

	switch (gsup->cn_domain) {
	case OSMO_GSUP_CN_DOMAIN_CS:
		proxy = g_hlr->gsup_proxy.cs;
		break;
	case OSMO_GSUP_CN_DOMAIN_PS:
		proxy = g_hlr->gsup_proxy.ps;
		break;
	default:
		LOG_DGSM(gsup->imsi, LOGL_ERROR, "Unknown cn_domain: %d\n", gsup->cn_domain);
		osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	/* To forward to a remote HLR, we need to indicate the source MSC's name to make sure the reply can be routed
	 * back. Store the sender MSC in gsup->source_name -- the remote HLR is required to return this as
	 * gsup->destination_name so that the reply gets routed to the original MSC. */
	route = gsup_route_find_by_conn(conn);
	if (!route) {
		/* The conn has not sent its IPA unit name yet, and hence we won't be able to proxy responses back from
		 * a remote HLR. Send GSUP error and indicate that this message has been handled. */
		osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_NET_FAIL);
		return true;
	}

	/* If the IMSI is known in the local HLR, then we won't proxy. */
	if (db_subscr_exists_by_imsi(g_hlr->dbc, gsup->imsi) == 0)
		return false;

	/* Are we already forwarding this IMSI to a remote HLR? */
	proxy_subscr = proxy_subscr_get_by_imsi(proxy, gsup->imsi);
	if (proxy_subscr)
		goto yes_we_are_proxying;

	/* The IMSI is not known locally, so we want to proxy to a remote HLR, but no proxy entry exists yet. We need to
	 * look up the subscriber in remote HLRs via D-GSM mslookup, forward GSUP and reply once a result is back from
	 * there.  Defer message and kick off MS lookup. */

	/* Kick off an mslookup for the remote HLR. */
	if (!g_hlr->mslookup.client.client) {
		LOGP(DDGSM, LOGL_DEBUG, "mslookup client not running, cannot query remote home HLR for %s\n",
		     gsup->imsi);
		return false;
	}

	query = (struct osmo_mslookup_query){
		.id = {
			.type = OSMO_MSLOOKUP_ID_IMSI,
		}
	};
	OSMO_STRLCPY_ARRAY(query.id.imsi, gsup->imsi);
	OSMO_STRLCPY_ARRAY(query.service, OSMO_MSLOOKUP_SERVICE_HLR_GSUP);
	handling = (struct osmo_mslookup_query_handling){
		.result_timeout_milliseconds = g_hlr->mslookup.client.result_timeout_milliseconds,
		.result_cb = resolve_hlr_result_cb,
	};
	request_handle = osmo_mslookup_client_request(g_hlr->mslookup.client.client, &query, &handling);
	if (!request_handle) {
		LOG_DGSM(gsup->imsi, LOGL_ERROR, "Error dispatching mslookup query for home HLR: %s\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, &query, NULL));
		proxy_subscr_del(proxy, gsup->imsi);
		return false;
	}

	/* Add a proxy entry without a remote address to indicate that we are busy querying for a remote HLR. */
	proxy_subscr_new = (struct proxy_subscr){};
	OSMO_STRLCPY_ARRAY(proxy_subscr_new.imsi, gsup->imsi);
	global_title_set(&proxy_subscr_new.vlr_name, route->addr, talloc_total_size(route->addr));
	proxy_subscr = &proxy_subscr_new;
	proxy_subscr_update(proxy, proxy_subscr);

yes_we_are_proxying:
	OSMO_ASSERT(proxy_subscr);

	/* Be aware that osmo_gsup_message has a lot of external pointer references, so this is not a deep copy.
	 * dgsm_send_to_remote_hlr() may need to defer the GSUP message until the remote HLR has answered, in which case
	 * it will take care to deep copy (encode into a msgb), i.e. it is fine to pass a shallow copy. */
	gsup_copy = *gsup;
	gsup_copy.source_name = route->addr;
	gsup_copy.source_name_len = talloc_total_size(route->addr);

	/* If the remote HLR is already known, directly forward the GSUP message; otherwise, spool the GSUP message
	 * until the remote HLR will respond / until timeout aborts. */
	dgsm_send_to_remote_hlr(proxy_subscr, &gsup_copy);
	return true;
}


void dgsm_init(void *ctx)
{
	dgsm_ctx = talloc_named_const(ctx, 0, "dgsm");
	dgsm_pending_messages_ctx = talloc_named_const(dgsm_ctx, 0, "dgsm_pending_messages");
	INIT_LLIST_HEAD(&g_hlr->mslookup.vty.server.msc_configs);

	g_hlr->mslookup.server.max_age = 60 * 60;

	g_hlr->mslookup.client.result_timeout_milliseconds = 2000;

	g_hlr->gsup_proxy.gsup_client_name.unit_name = "HLR";
	g_hlr->gsup_proxy.gsup_client_name.serno = "unnamed-HLR";
	g_hlr->gsup_proxy.gsup_client_name.swversion = PACKAGE_NAME "-" PACKAGE_VERSION;

	osmo_sockaddr_str_from_str(&g_hlr->mslookup.vty.server.mdns.bind_addr,
				   OSMO_MSLOOKUP_MDNS_IP4, OSMO_MSLOOKUP_MDNS_PORT);
	osmo_sockaddr_str_from_str(&g_hlr->mslookup.vty.client.mdns.query_addr,
				   OSMO_MSLOOKUP_MDNS_IP4, OSMO_MSLOOKUP_MDNS_PORT);
}

void dgsm_start(void *ctx)
{
	g_hlr->mslookup.client.client = osmo_mslookup_client_new(dgsm_ctx);
	OSMO_ASSERT(g_hlr->mslookup.client.client);
	g_hlr->mslookup.allow_startup = true;
	dgsm_config_apply();
}

static void dgsm_mdns_server_config_apply()
{
	/* Check whether to start/stop/restart mDNS server */
	bool should_run;
	bool should_stop;
	if (!g_hlr->mslookup.allow_startup)
		return;

	should_run = g_hlr->mslookup.vty.server.enable && g_hlr->mslookup.vty.server.mdns.enable;
	should_stop = g_hlr->mslookup.server.mdns
		&& (!should_run
		    || osmo_sockaddr_str_cmp(&g_hlr->mslookup.vty.server.mdns.bind_addr,
					     &g_hlr->mslookup.server.mdns->bind_addr));

	if (should_stop) {
		osmo_mslookup_server_mdns_stop(g_hlr->mslookup.server.mdns);
		g_hlr->mslookup.server.mdns = NULL;
		LOGP(DDGSM, LOGL_NOTICE, "Stopped mslookup mDNS server\n");
	}

	if (should_run && !g_hlr->mslookup.server.mdns) {
		g_hlr->mslookup.server.mdns =
			osmo_mslookup_server_mdns_start(g_hlr, &g_hlr->mslookup.vty.server.mdns.bind_addr);
		if (!g_hlr->mslookup.server.mdns)
			LOGP(DDGSM, LOGL_ERROR, "Failed to start mslookup mDNS server on " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.server.mdns->bind_addr));
		else
			LOGP(DDGSM, LOGL_NOTICE, "Started mslookup mDNS server, receiving mDNS requests at multicast "
			     OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.server.mdns->bind_addr));
	}
}

static void dgsm_mdns_client_config_apply()
{
	if (!g_hlr->mslookup.allow_startup)
		return;

	/* Check whether to start/stop/restart mDNS client */
	const struct osmo_sockaddr_str *current_bind_addr;
	current_bind_addr = osmo_mslookup_client_method_mdns_get_bind_addr(g_hlr->mslookup.client.mdns);

	bool should_run = g_hlr->mslookup.vty.client.enable && g_hlr->mslookup.vty.client.mdns.enable;
	bool should_stop = g_hlr->mslookup.client.mdns &&
		(!should_run
		 || osmo_sockaddr_str_cmp(&g_hlr->mslookup.vty.client.mdns.query_addr,
					  current_bind_addr));

	if (should_stop) {
		osmo_mslookup_client_method_del(g_hlr->mslookup.client.client, g_hlr->mslookup.client.mdns);
		g_hlr->mslookup.client.mdns = NULL;
		LOGP(DDGSM, LOGL_NOTICE, "Stopped mslookup mDNS client\n");
	}

	if (should_run && !g_hlr->mslookup.client.mdns) {
		g_hlr->mslookup.client.mdns =
			osmo_mslookup_client_add_mdns(g_hlr->mslookup.client.client,
						      g_hlr->mslookup.vty.client.mdns.query_addr.ip,
						      g_hlr->mslookup.vty.client.mdns.query_addr.port,
						      true);
		if (!g_hlr->mslookup.client.mdns)
			LOGP(DDGSM, LOGL_ERROR, "Failed to start mslookup mDNS client with target "
			     OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.vty.client.mdns.query_addr));
		else
			LOGP(DDGSM, LOGL_NOTICE, "Started mslookup mDNS client, sending mDNS requests to multicast " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.vty.client.mdns.query_addr));
	}
}

void dgsm_config_apply()
{
	dgsm_mdns_server_config_apply();
	dgsm_mdns_client_config_apply();
}

