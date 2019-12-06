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

#include <string.h>
#include <errno.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/mslookup/mslookup.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/timestamp.h>
#include <osmocom/hlr/mslookup_server.h>
#include <osmocom/hlr/proxy.h>

static const struct osmo_mslookup_result not_found = {
		.rc = OSMO_MSLOOKUP_RC_NOT_FOUND,
	};
const struct osmo_ipa_name mslookup_server_msc_wildcard = {};

static void set_result(struct osmo_mslookup_result *result,
		       const struct mslookup_service_host *service_host,
		       uint32_t age)
{
	if (!osmo_sockaddr_str_is_nonzero(&service_host->host_v4)
	    && !osmo_sockaddr_str_is_nonzero(&service_host->host_v6)) {
		*result = not_found;
		return;
	}
	result->rc = OSMO_MSLOOKUP_RC_RESULT;
	result->host_v4 = service_host->host_v4;
	result->host_v6 = service_host->host_v6;
	result->age = age;
}

const struct mslookup_service_host *mslookup_server_get_local_gsup_addr()
{
	static struct mslookup_service_host gsup_bind = {};
	struct mslookup_service_host *host;

	/* Find a HLR/GSUP service set for the server (no VLR unit name) */
	host = mslookup_server_service_get(&mslookup_server_msc_wildcard, OSMO_MSLOOKUP_SERVICE_HLR_GSUP);
	if (host)
		return host;

	/* Try to use the locally configured GSUP bind address */
	osmo_sockaddr_str_from_str(&gsup_bind.host_v4, g_hlr->gsup_bind_addr, OSMO_GSUP_PORT);
	if (gsup_bind.host_v4.af == AF_INET6) {
		gsup_bind.host_v6 = gsup_bind.host_v4;
		gsup_bind.host_v4 = (struct osmo_sockaddr_str){};
	}
	return &gsup_bind;
}

struct mslookup_server_msc_cfg *mslookup_server_msc_get(const struct osmo_ipa_name *msc_name, bool create)
{
	struct llist_head *c = &g_hlr->mslookup.server.local_site_services;
	struct mslookup_server_msc_cfg *msc;

	if (!msc_name)
		return NULL;

	llist_for_each_entry(msc, c, entry) {
		if (osmo_ipa_name_cmp(&msc->name, msc_name))
			continue;
		return msc;
	}
	if (!create)
		return NULL;

	msc = talloc_zero(g_hlr, struct mslookup_server_msc_cfg);
	OSMO_ASSERT(msc);
	INIT_LLIST_HEAD(&msc->service_hosts);
	msc->name = *msc_name;
	llist_add_tail(&msc->entry, c);
	return msc;
}

struct mslookup_service_host *mslookup_server_msc_service_get(struct mslookup_server_msc_cfg *msc, const char *service,
							      bool create)
{
	struct mslookup_service_host *e;
	if (!msc)
		return NULL;

	llist_for_each_entry(e, &msc->service_hosts, entry) {
		if (!strcmp(e->service, service))
			return e;
	}

	if (!create)
		return NULL;

	e = talloc_zero(msc, struct mslookup_service_host);
	OSMO_ASSERT(e);
	OSMO_STRLCPY_ARRAY(e->service, service);
	llist_add_tail(&e->entry, &msc->service_hosts);
	return e;
}

struct mslookup_service_host *mslookup_server_service_get(const struct osmo_ipa_name *msc_name, const char *service)
{
	struct mslookup_server_msc_cfg *msc = mslookup_server_msc_get(msc_name, false);
	if (!msc)
		return NULL;
	return mslookup_server_msc_service_get(msc, service, false);
}

int mslookup_server_msc_service_set(struct mslookup_server_msc_cfg *msc, const char *service,
				    const struct osmo_sockaddr_str *addr)
{
	struct mslookup_service_host *e;

	if (!service || !service[0]
	    || strlen(service) > OSMO_MSLOOKUP_SERVICE_MAXLEN)
		return -EINVAL;
	if (!addr || !osmo_sockaddr_str_is_nonzero(addr))
		return -EINVAL;

	e = mslookup_server_msc_service_get(msc, service, true);
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

int mslookup_server_msc_service_del(struct mslookup_server_msc_cfg *msc, const char *service,
				    const struct osmo_sockaddr_str *addr)
{
	struct mslookup_service_host *e, *n;
	int deleted = 0;

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
		deleted++;
	}
	return deleted;
}

/* A remote entity is asking us whether we are the home HLR of the given subscriber. */
static void mslookup_server_rx_hlr_gsup(const struct osmo_mslookup_query *query,
					struct osmo_mslookup_result *result)
{
	const struct mslookup_service_host *host;
	int rc;
	switch (query->id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		rc = db_subscr_exists_by_imsi(g_hlr->dbc, query->id.imsi);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		rc = db_subscr_exists_by_msisdn(g_hlr->dbc, query->id.msisdn);
		break;
	default:
		LOGP(DMSLOOKUP, LOGL_ERROR, "Unknown mslookup ID type: %d\n", query->id.type);
		*result = not_found;
		return;
	}

	if (rc) {
		LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: does not exist in local HLR\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		*result = not_found;
		return;
	}

	LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: found in local HLR\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));

	host = mslookup_server_get_local_gsup_addr();

	set_result(result, host, 0);
	if (result->rc != OSMO_MSLOOKUP_RC_RESULT) {
		LOGP(DMSLOOKUP, LOGL_ERROR,
		     "Subscriber found, but error in service '" OSMO_MSLOOKUP_SERVICE_HLR_GSUP "' config:"
		     " v4: " OSMO_SOCKADDR_STR_FMT "  v6: " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&host->host_v4),
		     OSMO_SOCKADDR_STR_FMT_ARGS(&host->host_v6));
	}
}

/* Look in the local HLR record: If the subscriber is "at home" in this HLR and is also currently located at a local
 * VLR, we will find a valid location updating with vlr_number, and no vlr_via_proxy entry. */
static bool subscriber_has_done_lu_here_hlr(const struct osmo_mslookup_query *query,
					    uint32_t *lu_age,
					    struct osmo_ipa_name *local_msc_name,
					    struct hlr_subscriber *ret_subscr)
{
	struct hlr_subscriber _subscr;
	int rc;
	uint32_t age;

	struct hlr_subscriber *subscr = ret_subscr ? : &_subscr;

	switch (query->id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		rc = db_subscr_get_by_imsi(g_hlr->dbc, query->id.imsi, subscr);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		rc = db_subscr_get_by_msisdn(g_hlr->dbc, query->id.msisdn, subscr);
		break;
	default:
		LOGP(DMSLOOKUP, LOGL_ERROR, "Unknown mslookup ID type: %d\n", query->id.type);
		return false;
	}

	if (rc) {
		LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: does not exist in local HLR\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}

	if (!subscr->vlr_number[0]) {
		LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: not attached (vlr_number unset)\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
	}

	if (subscr->vlr_via_proxy.len) {
		/* The VLR is behind a proxy, the subscriber is not attached to a local VLR but a remote one. That
		 * remote proxy should instead respond to the service lookup request. */
		LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: last attach is not at local VLR, but at VLR '%s' via proxy %s\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     subscr->vlr_number,
		     osmo_ipa_name_to_str(&subscr->vlr_via_proxy));
		return false;
	}

	if (!timestamp_age(&subscr->last_lu_seen, &age)) {
		LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: Invalid last_lu_seen timestamp for subscriber\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}
	if (age > g_hlr->mslookup.server.local_attach_max_age) {
		LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: last attach was here, but too long ago: %us > %us\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     age, g_hlr->mslookup.server.local_attach_max_age);
		return false;
	}

	*lu_age = age;
	osmo_ipa_name_set_str(local_msc_name, subscr->vlr_number);
	LOGP(DMSLOOKUP, LOGL_DEBUG, "%s: attached %u seconds ago at local VLR %s\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
	     age, osmo_ipa_name_to_str(local_msc_name));

	return true;
}


/* Determine whether the subscriber with the given ID has routed a Location Updating via this HLR as first hop. Return
 * true if it is attached at a local VLR, and we are serving as proxy for a remote home HLR.
 */
static bool subscriber_has_done_lu_here_proxy(const struct osmo_mslookup_query *query,
					      uint32_t *lu_age,
					      struct osmo_ipa_name *local_msc_name,
					      const struct proxy_subscr **ret_proxy_subscr)
{
	const struct proxy_subscr *proxy_subscr;
	uint32_t age;

	/* See the local HLR record. If the subscriber is "at home" in this HLR and is also currently located here, we
	 * will find a valid location updating and no vlr_via_proxy entry. */
	switch (query->id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		proxy_subscr = proxy_subscr_get_by_imsi(g_hlr->gs->proxy, query->id.imsi);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		proxy_subscr = proxy_subscr_get_by_msisdn(g_hlr->gs->proxy, query->id.msisdn);
		break;
	default:
		LOGP(DDGSM, LOGL_ERROR, "%s: unknown ID type\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}

	if (!proxy_subscr) {
		LOGP(DDGSM, LOGL_DEBUG, "%s: does not exist in GSUP proxy\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}

	/* We only need to care about CS LU, since only CS services need D-GSM routing. */
	if (!timestamp_age(&proxy_subscr->cs.last_lu, &age)
	    || age > g_hlr->mslookup.server.local_attach_max_age) {
		LOGP(DDGSM, LOGL_ERROR,
		     "%s: last attach was at local VLR (proxying for remote HLR), but too long ago: %us > %us\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     age, g_hlr->mslookup.server.local_attach_max_age);
		return false;
	}

	if (proxy_subscr->cs.vlr_via_proxy.len) {
		LOGP(DDGSM, LOGL_DEBUG, "%s: last attach is not at local VLR, but at VLR '%s' via proxy '%s'\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     osmo_ipa_name_to_str(&proxy_subscr->cs.vlr_name),
		     osmo_ipa_name_to_str(&proxy_subscr->cs.vlr_via_proxy));
		return false;
	}

	*lu_age = age;
	*local_msc_name = proxy_subscr->cs.vlr_name;
	LOGP(DDGSM, LOGL_DEBUG, "%s: attached %u seconds ago at local VLR %s; proxying for remote HLR "
	     OSMO_SOCKADDR_STR_FMT "\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
	     age, osmo_ipa_name_to_str(local_msc_name),
	     OSMO_SOCKADDR_STR_FMT_ARGS(&proxy_subscr->remote_hlr_addr));

	if (ret_proxy_subscr)
		*ret_proxy_subscr = proxy_subscr;
	return true;
}

bool subscriber_has_done_lu_here(const struct osmo_mslookup_query *query,
				 uint32_t *lu_age_p, struct osmo_ipa_name *local_msc_name,
				 char *ret_imsi, size_t ret_imsi_len)
{
	bool attached_here;
	uint32_t lu_age = 0;
	struct osmo_ipa_name msc_name = {};
	bool attached_here_proxy;
	uint32_t proxy_lu_age = 0;
	struct osmo_ipa_name proxy_msc_name = {};
	const struct proxy_subscr *proxy_subscr;
	struct hlr_subscriber db_subscr;


	/* First ask the local HLR db, but if the local proxy record indicates a more recent LU, use that instead.
	 * For all usual cases, only one of these will reflect a LU, even if a subscriber had more than one home HLR:
	 *   - if the subscriber is known here, we will never proxy.
	 *   - if the subscriber is not known here, this local HLR db will never record a LU.
	 * However, if a subscriber was being proxied to a remote home HLR, and if then the subscriber was also added to
	 * the local HLR database, there might occur a situation where both reflect a LU. So, to be safe against all
	 * situations, compare the two entries.
	 */
	attached_here = subscriber_has_done_lu_here_hlr(query, &lu_age, &msc_name, &db_subscr);
	attached_here_proxy = subscriber_has_done_lu_here_proxy(query, &proxy_lu_age, &proxy_msc_name, &proxy_subscr);

	/* If proxy has a younger lu, replace. */
	if (attached_here_proxy && (!attached_here || (proxy_lu_age < lu_age))) {
		attached_here = true;
		lu_age = proxy_lu_age;
		msc_name = proxy_msc_name;
		if (ret_imsi)
			osmo_strlcpy(ret_imsi, proxy_subscr->imsi, ret_imsi_len);
	} else if (attached_here) {
		if (ret_imsi)
			osmo_strlcpy(ret_imsi, db_subscr.imsi, ret_imsi_len);
	}

	if (attached_here && !msc_name.len) {
		LOGP(DMSLOOKUP, LOGL_ERROR, "%s: attached here, but no VLR name known\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}

	if (!attached_here) {
		/* Already logged "not attached" for both local-db and proxy attach */
		return false;
	}

	LOGP(DMSLOOKUP, LOGL_INFO, "%s: attached here, at VLR %s\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
	     osmo_ipa_name_to_str(&msc_name));
	*lu_age_p = lu_age;
	*local_msc_name = msc_name;
	return true;
}

/* A remote entity is asking us whether we are providing the given service for the given subscriber. */
void mslookup_server_rx(const struct osmo_mslookup_query *query,
			struct osmo_mslookup_result *result)
{
	const struct mslookup_service_host *service_host;
	uint32_t age;
	struct osmo_ipa_name msc_name;

	/* A request for a home HLR: answer exactly if this is the subscriber's home HLR, i.e. the IMSI is listed in the
	 * HLR database. */
	if (strcmp(query->service, OSMO_MSLOOKUP_SERVICE_HLR_GSUP) == 0)
		return mslookup_server_rx_hlr_gsup(query, result);

	/* All other service types: answer when the subscriber has done a LU that is either listed in the local HLR or
	 * in the GSUP proxy database: i.e. if the subscriber has done a Location Updating at an VLR belonging to this
	 * HLR. Respond with whichever services are configured in the osmo-hlr.cfg. */
	if (!subscriber_has_done_lu_here(query, &age, &msc_name, NULL, 0)) {
		*result = not_found;
		return;
	}

	/* We've detected a LU here. The VLR where the LU happened is stored in msc_unit_name, and the LU age is stored
	 * in 'age'. Figure out the address configured for that VLR and service name. */
	service_host = mslookup_server_service_get(&msc_name, query->service);

	if (!service_host) {
		/* Find such service set globally (no VLR unit name) */
		service_host = mslookup_server_service_get(&mslookup_server_msc_wildcard, query->service);
	}

	if (!service_host) {
		LOGP(DMSLOOKUP, LOGL_ERROR,
		     "%s: subscriber found, but no service %s configured, cannot service lookup request\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     osmo_quote_str_c(OTC_SELECT, query->service, -1));
		*result = not_found;
		return;
	}

	set_result(result, service_host, age);
}
