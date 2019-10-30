#include <string.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mslookup/mslookup.h>
#include "logging.h"
#include "hlr.h"
#include "db.h"
#include "dgsm.h"
#include "mslookup_server.h"

static const struct osmo_mslookup_result not_found = {
		.ip_v4.rc = OSMO_MSLOOKUP_RC_NOT_FOUND,
		.ip_v6.rc = OSMO_MSLOOKUP_RC_NOT_FOUND,
	};

static void set_result(struct osmo_mslookup_result_part *result,
		       const struct osmo_sockaddr_str *addr,
		       uint32_t age)
{
	if (!osmo_sockaddr_str_is_nonzero(addr)) {
		result->rc = OSMO_MSLOOKUP_RC_NOT_FOUND;
		return;
	}
	result->rc = OSMO_MSLOOKUP_RC_OK;
	result->host = *addr;
	result->age = age;
}

static void set_results(struct osmo_mslookup_result *result,
			const struct dgsm_service_addr *service_addr,
			uint32_t age)
{
	set_result(&result->ip_v4, &service_addr->addr_v4, age);
	set_result(&result->ip_v6, &service_addr->addr_v6, age);
}

void mslookup_server_rx_hlr_gsup(const struct osmo_mslookup_query *query,
				 struct osmo_mslookup_result *result)
{
	struct dgsm_service_addr *addr;
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
		LOGP(DDGSM, LOGL_DEBUG, "Does not exist in local HLR: %s\n",
		     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));
		*result = not_found;
		return;
	}

	LOGP(DDGSM, LOGL_DEBUG, "Found in local HLR: %s\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, NULL));

	/* Find a HLR/GSUP service set for the server (no MSC unit name) */
	addr = dgsm_config_service_get(NULL, 0, OSMO_MSLOOKUP_SERVICE_HLR_GSUP);
	if (!addr) {
		LOGP(DDGSM, LOGL_ERROR,
		     "Subscriber found, but no service '" OSMO_MSLOOKUP_SERVICE_HLR_GSUP "' configured,"
		     " cannot service HLR lookup request\n");
		*result = not_found;
		return;
	}

	set_results(result, addr, 0);
}

/* Determine whether the subscriber with the given ID has routed a Location Updating via this HLR as first hop -- either
 * entirely here, or here first but proxying to a remote HLR. Do not return a match if the LU was registered here
 * (because this is the home HLR) but the LU was routed via a closer HLR first.
 * A proxy adds source_name IEs to forwarded GSUP requests that indicates the MSC where the subscriber is attached.
 * So a) if the LU that was received at the home HLR contained a source_name, we know that the LU happened at a remote
 * MSC. b) The source_name is stored as the vlr_number; hence if that vlr_number is not known locally, we know the LU
 * happened at a remote MSC. (at the time of writing it is not yet clear whether we'll use a or b).
 */
bool subscriber_has_done_location_updating_here(const struct osmo_mslookup_id *id,
						uint32_t *lu_age,
						const uint8_t **lu_msc_unit_name,
						size_t *lu_msc_unit_name_len)
{
	return false;
}

void mslookup_server_rx(const struct osmo_mslookup_query *query,
			struct osmo_mslookup_result *result)
{
	const uint8_t *msc_unit_name;
	size_t msc_unit_name_len;
	const struct dgsm_service_addr *service_addr;
	uint32_t age;

	/* A request for a home HLR: answer exactly if this is the subscriber's home HLR, i.e. the IMSI is listed in the
	 * HLR database. */
	if (strcmp(query->service, OSMO_MSLOOKUP_SERVICE_HLR_GSUP) != 0)
		return mslookup_server_rx_hlr_gsup(query, result);

	/* All other service types: answer when the subscriber has done a LU that is either listed in the local HLR or
	 * in the GSUP proxy database: i.e. if the subscriber has done a Location Updating at an MSC belonging to this
	 * HLR. Respond with whichever services are configured in the osmo-hlr.cfg. */
	if (!subscriber_has_done_location_updating_here(&query->id, &age, &msc_unit_name, &msc_unit_name_len)) {
		*result = not_found;
		return;
	}

	/* We've detected a LU here. The MSC where the LU happened is stored in msc_unit_name, and the LU age is stored
	 * in 'age'. Figure out the address configured for that MSC and service name. */
	service_addr = dgsm_config_service_get(msc_unit_name, msc_unit_name_len, query->service);
	if (!service_addr) {
		*result = not_found;
		return;
	}

	set_results(result, service_addr, age);
}

struct osmo_mslookup_server_dns *osmo_mslookup_server_dns_start(const struct osmo_sockaddr_str *multicast_bind_addr)
{
	return NULL;
}

void osmo_mslookup_server_dns_stop(struct osmo_mslookup_server_dns *server)
{
}

