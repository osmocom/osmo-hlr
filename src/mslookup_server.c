#include <string.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mslookup/mslookup.h>
#include "logging.h"
#include "hlr.h"
#include "db.h"
#include "dgsm.h"
#include "mslookup_server.h"
#include "proxy.h"

static const struct osmo_mslookup_result not_found = {
		.rc = OSMO_MSLOOKUP_RC_NOT_FOUND,
	};

static void set_result(struct osmo_mslookup_result *result,
		       const struct dgsm_service_host *service_host,
		       uint32_t age)
{
	if (!osmo_sockaddr_str_is_nonzero(&service_host->host_v4)
	    && !osmo_sockaddr_str_is_nonzero(&service_host->host_v6)) {
		*result = not_found;
		return;
	}
	result->rc = OSMO_MSLOOKUP_RC_OK;
	result->host_v4 = service_host->host_v4;
	result->host_v6 = service_host->host_v6;
	result->age = age;
}

/* A remote entity is asking us whether we are the home HLR of the given subscriber. */
static void mslookup_server_rx_hlr_gsup(const struct osmo_mslookup_query *query,
					struct osmo_mslookup_result *result)
{
	struct dgsm_service_host *host;
	int rc;
	switch (query->id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		rc = db_subscr_exists_by_imsi(g_hlr->dbc, query->id.imsi);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		rc = db_subscr_exists_by_msisdn(g_hlr->dbc, query->id.msisdn);
		break;
	default:
		LOGP(DDGSM, LOGL_ERROR, "Unknown mslookup ID type: %d\n", query->id.type);
		*result = not_found;
		return;
	}

	if (rc) {
		LOGP(DDGSM, LOGL_DEBUG, "%s: does not exist in local HLR\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		*result = not_found;
		return;
	}

	LOGP(DDGSM, LOGL_DEBUG, "%s: found in local HLR\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));

	/* Find a HLR/GSUP service set for the server (no MSC unit name) */
	host = dgsm_config_service_get(&dgsm_config_msc_wildcard, OSMO_MSLOOKUP_SERVICE_HLR_GSUP);
	if (!host) {
		struct dgsm_service_host gsup_bind = {};
		/* Try to use the locally configured GSUP bind address */
		osmo_sockaddr_str_from_str(&gsup_bind.host_v4, g_hlr->gsup_bind_addr, OSMO_GSUP_PORT);
		if (gsup_bind.host_v4.af == AF_INET6) {
			gsup_bind.host_v6 = gsup_bind.host_v4;
			gsup_bind.host_v4 = (struct osmo_sockaddr_str){};
		}
		set_result(result, &gsup_bind, 0);
		if (result->rc != OSMO_MSLOOKUP_RC_OK) {
			LOGP(DDGSM, LOGL_ERROR,
			     "%s: subscriber found, but no service '" OSMO_MSLOOKUP_SERVICE_HLR_GSUP "' configured,"
			     " and cannot use configured GSUP bind address %s in mslookup response."
			     " Cannot service HLR lookup request\n",
			     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
			     osmo_quote_str(g_hlr->gsup_bind_addr, -1));
		}
		return;
	}

	set_result(result, host, 0);
	if (result->rc != OSMO_MSLOOKUP_RC_OK) {
		LOGP(DDGSM, LOGL_ERROR,
		     "Subscriber found, but error in service '" OSMO_MSLOOKUP_SERVICE_HLR_GSUP "' config:"
		     " v4: " OSMO_SOCKADDR_STR_FMT "  v6: " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&host->host_v4),
		     OSMO_SOCKADDR_STR_FMT_ARGS(&host->host_v6));
	}
}

/* Look in the local HLR record: If the subscriber is "at home" in this HLR and is also currently located at a local
 * MSC, we will find a valid location updating with vlr_number, and no vlr_via_proxy entry. */
static bool subscriber_has_done_lu_here_hlr(const struct osmo_mslookup_query *query,
					    uint32_t *lu_age,
					    struct global_title *local_msc_name)
{
	struct hlr_subscriber subscr;
	struct timeval age_tv;
	int rc;
	uint32_t age;

	switch (query->id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		rc = db_subscr_get_by_imsi(g_hlr->dbc, query->id.imsi, &subscr);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		rc = db_subscr_get_by_msisdn(g_hlr->dbc, query->id.msisdn, &subscr);
		break;
	default:
		LOGP(DDGSM, LOGL_ERROR, "Unknown mslookup ID type: %d\n", query->id.type);
		return false;
	}

	if (rc) {
		LOGP(DDGSM, LOGL_DEBUG, "%s: does not exist in local HLR\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}

	if (!subscr.vlr_number[0]) {
		LOGP(DDGSM, LOGL_DEBUG, "%s: not attached (vlr_number unset)\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
	}

	if (subscr.vlr_via_proxy.len) {
		/* The MSC is behind a proxy, the subscriber is not attached to a local MSC but a remote one. That
		 * remote proxy should instead respond to the service lookup request. */
		LOGP(DDGSM, LOGL_DEBUG, "%s: last attach is not at local MSC, but via proxy %s\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     global_title_name(&subscr.vlr_via_proxy));
		return false;
	}

	age_tv = (struct timeval){ .tv_sec = subscr.last_lu_seen };
	age = timestamp_age(&age_tv);

	if (age > g_hlr->mslookup.server.max_age) {
		LOGP(DDGSM, LOGL_ERROR, "%s: last attach was here, but too long ago: %us > %us\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     age, g_hlr->mslookup.server.max_age);
		return false;
	}

	*lu_age = age;
	global_title_set_str(local_msc_name, subscr.vlr_number);
	LOGP(DDGSM, LOGL_DEBUG, "%s: attached %u seconds ago at local MSC %s\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
	     age, global_title_name(local_msc_name));

	return true;
}


/* Determine whether the subscriber with the given ID has routed a Location Updating via this HLR as first hop. Return
 * true if it is attached at a local MSC, and we are serving as proxy for a remote home HLR.
 */
static bool subscriber_has_done_lu_here_proxy(const struct osmo_mslookup_query *query,
					      uint32_t *lu_age,
					      struct global_title *local_msc_name)
{
	const struct proxy_subscr *subscr;
	uint32_t age;

	/* See the local HLR record. If the subscriber is "at home" in this HLR and is also currently located here, we
	 * will find a valid location updating and no vlr_via_proxy entry. */
	subscr = proxy_subscr_get_by_imsi(g_hlr->proxy, query->id.imsi);

	if (!subscr) {
		LOGP(DDGSM, LOGL_DEBUG, "%s: does not exist in GSUP proxy\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}

	/* We only need to care about CS LU, since only CS services need D-GSM routing. */
	age = timestamp_age(&subscr->cs.last_lu);

	if (age > g_hlr->mslookup.server.max_age) {
		LOGP(DDGSM, LOGL_ERROR, "%s: last attach was here (proxy), but too long ago: %us > %us\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     age, g_hlr->mslookup.server.max_age);
		return false;
	}

	*lu_age = age;
	*local_msc_name = subscr->cs.vlr_name;
	LOGP(DDGSM, LOGL_DEBUG, "%s: attached %u seconds ago at local MSC %s; proxying for remote HLR "
	     OSMO_SOCKADDR_STR_FMT "\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
	     age, global_title_name(local_msc_name),
	     OSMO_SOCKADDR_STR_FMT_ARGS(&subscr->remote_hlr_addr));

	return true;
}

static bool subscriber_has_done_lu_here(const struct osmo_mslookup_query *query,
					uint32_t *lu_age_p,
					struct global_title *local_msc_name)
{
	uint32_t lu_age = 0;
	struct global_title msc_name = {};
	uint32_t proxy_lu_age = 0;
	struct global_title proxy_msc_name = {};

	/* First ask the local HLR db, but if the local proxy record indicates a more recent LU, use that instead.
	 * For all usual cases, only one of these will reflect a LU, even if a subscriber had more than one home HLR:
	 *   - if the subscriber is known here, we will never proxy.
	 *   - if the subscriber is not known here, this local HLR db will never record a LU.
	 * However, if a subscriber was being proxied to a remote home HLR, and if then the subscriber was also added to
	 * the local HLR database, there might occur a situation where both reflect a LU. So, to be safe against all
	 * situations, compare the two entries.
	 */
	if (!subscriber_has_done_lu_here_hlr(query, &lu_age, &msc_name))
		lu_age = 0;
	if (!subscriber_has_done_lu_here_proxy(query, &proxy_lu_age, &proxy_msc_name))
		proxy_lu_age = 0;
	if (lu_age && proxy_lu_age) {
		LOGP(DDGSM, LOGL_DEBUG,
		     "%s: a LU is on record both in the local HLR (age %us) and the GSUP proxy (age %us)\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     lu_age, proxy_lu_age);
	}
	/* If proxy has a younger lu, replace. */
	if (proxy_lu_age && (!lu_age || (proxy_lu_age < lu_age))) {
		lu_age = proxy_lu_age;
		msc_name = proxy_msc_name;
	}

	if (!lu_age || !msc_name.len) {
		LOGP(DDGSM, LOGL_DEBUG, "%s: not attached here\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		return false;
	}

	LOGP(DDGSM, LOGL_DEBUG, "%s: attached here, at MSC %s\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
	     global_title_name(&msc_name));
	*lu_age_p = lu_age;
	*local_msc_name = msc_name;
	return true;
}

/* A remote entity is asking us whether we are providing the given service for the given subscriber. */
void osmo_mslookup_server_rx(const struct osmo_mslookup_query *query,
			     struct osmo_mslookup_result *result)
{
	const struct dgsm_service_host *service_host;
	uint32_t age;
	struct global_title msc_name;

	/* A request for a home HLR: answer exactly if this is the subscriber's home HLR, i.e. the IMSI is listed in the
	 * HLR database. */
	if (strcmp(query->service, OSMO_MSLOOKUP_SERVICE_HLR_GSUP) == 0)
		return mslookup_server_rx_hlr_gsup(query, result);

	/* All other service types: answer when the subscriber has done a LU that is either listed in the local HLR or
	 * in the GSUP proxy database: i.e. if the subscriber has done a Location Updating at an MSC belonging to this
	 * HLR. Respond with whichever services are configured in the osmo-hlr.cfg. */
	if (!subscriber_has_done_lu_here(query, &age, &msc_name)) {
		*result = not_found;
		return;
	}

	/* We've detected a LU here. The MSC where the LU happened is stored in msc_unit_name, and the LU age is stored
	 * in 'age'. Figure out the address configured for that MSC and service name. */
	service_host = dgsm_config_service_get(&msc_name, query->service);

	if (!service_host) {
		/* Find such service set globally (no MSC unit name) */
		service_host = dgsm_config_service_get(&dgsm_config_msc_wildcard, query->service);
	}

	if (!service_host) {
		LOGP(DDGSM, LOGL_ERROR,
		     "%s: subscriber found, but no service %s configured, cannot service lookup request\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL),
		     osmo_quote_str_c(OTC_SELECT, query->service, -1));
		*result = not_found;
		return;
	}

	set_result(result, service_host, age);
}
