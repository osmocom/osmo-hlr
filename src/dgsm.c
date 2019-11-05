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

#define LOG_DGSM(imsi, level, fmt, args...) \
	LOGP(DDGSM, level, "(IMSI-%s) " fmt, imsi, ##args)

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
	osmo_gsup_encode(m->gsup, gsup);

	llist_add_tail(&m->entry, &pending_gsup_messages);
}

void dgsm_send_to_remote_hlr(const struct proxy_subscr *ps, const struct osmo_gsup_message *gsup)
{
	struct remote_hlr *remote_hlr;

	if (!osmo_sockaddr_str_is_nonzero(&ps->remote_hlr)) {
		/* We don't know the remote target yet. Still waiting for an MS lookup response. */
		LOG_DGSM(gsup->imsi, LOGL_DEBUG, "GSUP Proxy: deferring until remote proxy is known: %s\n",
			 osmo_gsup_message_type_name(gsup->message_type));
		defer_gsup_message(gsup);
		return;
	}

	LOG_DGSM(gsup->imsi, LOGL_DEBUG, "GSUP Proxy: forwarding to " OSMO_SOCKADDR_STR_FMT ": %s\n",
		 OSMO_SOCKADDR_STR_FMT_ARGS(&ps->remote_hlr), osmo_gsup_message_type_name(gsup->message_type));
	
	remote_hlr = remote_hlr_get(&ps->remote_hlr, true);
	if (!remote_hlr) {
		LOG_DGSM(gsup->imsi, LOGL_ERROR, "Failed to establish connection to remote HLR " OSMO_SOCKADDR_STR_FMT
			 ", discarding GSUP: %s\n",
			 OSMO_SOCKADDR_STR_FMT_ARGS(&ps->remote_hlr), osmo_gsup_message_type_name(gsup->message_type));
		return;
	}

	remote_hlr_gsup_send(remote_hlr, gsup);
}

/* Return true when the message has been handled by D-GSM. */
bool dgsm_check_forward_gsup_msg(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup)
{
	const struct proxy_subscr *proxy_subscr;
	struct proxy_subscr ps_new;
	struct gsup_route *r;
	struct osmo_gsup_message gsup_copy;
	struct proxy *proxy = g_hlr->gsup_proxy.cs;
	if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS)
		proxy = g_hlr->gsup_proxy.ps;

	proxy_subscr = proxy_subscr_get_by_imsi(proxy, gsup->imsi);
	if (proxy_subscr)
		goto yes_we_are_proxying;

	/* No proxy entry exists. If the IMSI is known in the local HLR, then we won't proxy. */
	if (db_subscr_exists_by_imsi(g_hlr->dbc, gsup->imsi) == 0)
		return false;

	/* The IMSI is not known locally, so we want to proxy to a remote HLR, but no proxy entry exists yet. We need to
	 * look up the subscriber in remote HLRs via D-GSM mslookup, forward GSUP and reply once a result is back from
	 * there.  Defer message and kick off MS lookup. */

	/* Add a proxy entry without a remote address to indicate that we are busy querying for a remote HLR. */
	ps_new = (struct proxy_subscr){};
	OSMO_STRLCPY_ARRAY(ps_new.imsi, gsup->imsi);
	proxy_subscr_update(proxy, &ps_new);
	proxy_subscr = &ps_new;

yes_we_are_proxying:
	OSMO_ASSERT(proxy_subscr);

	/* To forward to a remote HLR, we need to indicate the source MSC's name to make sure the reply can be routed
	 * back. Store the sender MSC in gsup->source_name -- the remote HLR is required to return this as
	 * gsup->destination_name so that the reply gets routed to the original MSC. */
	r = gsup_route_find_by_conn(conn);
	if (!r) {
		/* The conn has not sent its IPA unit name yet, and hence we won't be able to proxy responses back from
		 * a remote HLR. Send GSUP error and indicate that this message has been handled. */
		osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_NET_FAIL);
		return true;
	}

	/* Be aware that osmo_gsup_message has a lot of external pointer references, so this is not a deep copy. */
	gsup_copy = *gsup;
	gsup_copy.source_name = r->addr;
	gsup_copy.source_name_len = talloc_total_size(r->addr);

	dgsm_send_to_remote_hlr(proxy_subscr, &gsup_copy);
	return true;
}


void dgsm_init(void *ctx)
{
	dgsm_ctx = talloc_named_const(ctx, 0, "dgsm");
	dgsm_pending_messages_ctx = talloc_named_const(dgsm_ctx, 0, "dgsm_pending_messages");
	INIT_LLIST_HEAD(&g_hlr->mslookup.vty.server.msc_configs);
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

	g_hlr->mslookup.server.max_age = g_hlr->mslookup.vty.server.max_age;
	
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

