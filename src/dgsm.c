#include <errno.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_dns.h>
#include <osmocom/gsupclient/gsup_client.h>
#include "logging.h"
#include "hlr.h"
#include "db.h"
#include "gsup_router.h"
#include "dgsm.h"
#include "proxy.h"
#include "remote_hlr.h"
#include "mslookup_server.h"

#define LOG_DGSM(imsi, level, fmt, args...) \
	LOGP(DDGSM, level, "(IMSI-%s) " fmt, imsi, ##args)

void *dgsm_ctx = NULL;
struct dgsm_config dgsm_config = {
	.server = {
		.dns = {
			.multicast_bind_addr = {
				.ip = OSMO_MSLOOKUP_MDNS_IP4,
				.port = OSMO_MSLOOKUP_MDNS_PORT,
			},
		},
	},
};


struct dgsm_msc_config *dgsm_config_msc_get(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
					    bool create)
{
	struct dgsm_msc_config *msc;

	if (!ipa_unit_name)
		return NULL;

	llist_for_each_entry(msc, &dgsm_config.server.msc_configs, entry) {
		if (ipa_unit_name_len != msc->unit_name_len)
			continue;
		if (memcmp(ipa_unit_name, msc->unit_name, ipa_unit_name_len))
			continue;
		return msc;
	}
	if (!create)
		return NULL;

	msc = talloc_zero(dgsm_ctx, struct dgsm_msc_config);
	OSMO_ASSERT(msc);
	INIT_LLIST_HEAD(&msc->service_addrs);
	msc->unit_name = talloc_memdup(msc, ipa_unit_name, ipa_unit_name_len);
	OSMO_ASSERT(msc->unit_name);
	msc->unit_name_len = ipa_unit_name_len;
	return msc;
}

static struct dgsm_service_addr *dgsm_config_msc_service_get(struct dgsm_msc_config *msc, const char *service,
							     bool create)
{
	struct dgsm_service_addr *e;
	llist_for_each_entry(e, &msc->service_addrs, entry) {
		if (!strcmp(e->service, service))
			return e;
	}

	if (!create)
		return NULL;

	e = talloc_zero(msc, struct dgsm_service_addr);
	OSMO_ASSERT(e);
	OSMO_STRLCPY_ARRAY(e->service, service);
	llist_add_tail(&e->entry, &msc->service_addrs);
	return e;
}

struct dgsm_service_addr *dgsm_config_service_get(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
						  const char *service)
{
	struct dgsm_msc_config *msc = dgsm_config_msc_get(ipa_unit_name, ipa_unit_name_len, false);
	if (!msc)
		return NULL;
	return dgsm_config_msc_service_get(msc, service, false);
}

int dgsm_config_service_set(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
			    const char *service, const struct osmo_sockaddr_str *addr)
{
	struct dgsm_msc_config *msc;
	struct dgsm_service_addr *e;

	if (!service || !service[0]
	    || strlen(service) > OSMO_MSLOOKUP_SERVICE_MAXLEN)
		return -EINVAL;
	if (!addr || !osmo_sockaddr_str_is_nonzero(addr))
		return -EINVAL;

	msc = dgsm_config_msc_get(ipa_unit_name, ipa_unit_name_len, true);
	if (!msc)
		return -EINVAL;

	e = dgsm_config_msc_service_get(msc, service, true);
	if (!e)
		return -EINVAL;

	switch (addr->af) {
	case AF_INET:
		e->addr_v4 = *addr;
		break;
	case AF_INET6:
		e->addr_v6 = *addr;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

int dgsm_config_service_del(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
			    const char *service, const struct osmo_sockaddr_str *addr)
{
	struct dgsm_msc_config *msc;
	struct dgsm_service_addr *e, *n;

	msc = dgsm_config_msc_get(ipa_unit_name, ipa_unit_name_len, false);
	if (!msc)
		return -ENOENT;

	llist_for_each_entry_safe(e, n, &msc->service_addrs, entry) {
		if (service && strcmp(service, e->service))
			continue;

		if (addr) {
			if (!osmo_sockaddr_str_cmp(addr, &e->addr_v4)) {
				e->addr_v4 = (struct osmo_sockaddr_str){};
				/* Removed one addr. If the other is still there, keep the entry. */
				if (osmo_sockaddr_str_is_nonzero(&e->addr_v6))
					continue;
			} else if (!osmo_sockaddr_str_cmp(addr, &e->addr_v6)) {
				e->addr_v6 = (struct osmo_sockaddr_str){};
				/* Removed one addr. If the other is still there, keep the entry. */
				if (osmo_sockaddr_str_is_nonzero(&e->addr_v4))
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

static void *dgsm_pending_messages_ctx = NULL;
static struct osmo_mslookup_client *mslookup_client = NULL;

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
	const struct proxy_subscr *ps;
	struct proxy_subscr ps_new;
	struct gsup_route *r;
	struct osmo_gsup_message gsup_copy;

	ps = proxy_subscr_get(gsup->imsi);
	if (ps)
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
	proxy_subscr_update(&ps_new);
	ps = &ps_new;

yes_we_are_proxying:
	OSMO_ASSERT(ps);

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

	dgsm_send_to_remote_hlr(ps, &gsup_copy);
	return true;
}


void dgsm_init(void *ctx)
{
	dgsm_ctx = talloc_named_const(ctx, 0, "dgsm");
	dgsm_pending_messages_ctx = talloc_named_const(dgsm_ctx, 0, "dgsm_pending_messages");
	INIT_LLIST_HEAD(&dgsm_config.server.msc_configs);
}

void dgsm_start(void *ctx)
{
	mslookup_client = osmo_mslookup_client_new(dgsm_ctx);
	OSMO_ASSERT(mslookup_client);
}

void dgsm_dns_server_config_apply()
{
	/* Check whether to start/stop/restart DNS server */
	bool should_run = dgsm_config.server.enable && dgsm_config.server.dns.enable;
	bool should_stop = g_hlr->mslookup.server.dns
		&& (!should_run
		    || osmo_sockaddr_str_cmp(&dgsm_config.server.dns.multicast_bind_addr,
					     &g_hlr->mslookup.server.dns->multicast_bind_addr));

	if (should_stop) {
		osmo_mslookup_server_dns_stop(g_hlr->mslookup.server.dns);
		LOGP(DDGSM, LOGL_ERROR, "Stopped MS Lookup DNS server\n");
	}

	if (should_run) {
		g_hlr->mslookup.server.dns =
			osmo_mslookup_server_dns_start(&dgsm_config.server.dns.multicast_bind_addr);
		if (!g_hlr->mslookup.server.dns)
			LOGP(DDGSM, LOGL_ERROR, "Failed to start MS Lookup DNS server\n");
		else
			LOGP(DDGSM, LOGL_ERROR, "Started MS Lookup DNS server on " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&g_hlr->mslookup.server.dns->multicast_bind_addr));
	}
}

void dgsm_dns_client_config_apply()
{
	/* Check whether to start/stop/restart DNS client */
	struct osmo_mslookup_client_method *dns_method = g_hlr->mslookup.client.dns;
	const struct osmo_sockaddr_str *current_bind_addr = osmo_mslookup_client_method_dns_get_bind_addr(dns_method);

	bool should_run = dgsm_config.client.enable && dgsm_config.client.dns.enable;
	bool should_stop = dns_method &&
		(!should_run
		 || osmo_sockaddr_str_cmp(&dgsm_config.client.dns.multicast_query_addr,
					  current_bind_addr));

	if (should_stop) 
		osmo_mslookup_client_method_del(mslookup_client, dns_method);
	if (should_run) {
		if (osmo_mslookup_client_add_dns(mslookup_client,
						 dgsm_config.client.dns.multicast_query_addr.ip,
						 dgsm_config.client.dns.multicast_query_addr.port,
						 true))
			LOGP(DDGSM, LOGL_ERROR, "Failed to start MS Lookup DNS client\n");
		else
			LOGP(DDGSM, LOGL_ERROR, "Started MS Lookup DNS client with " OSMO_SOCKADDR_STR_FMT "\n",
			     OSMO_SOCKADDR_STR_FMT_ARGS(&dgsm_config.client.dns.multicast_query_addr));
	}
}
