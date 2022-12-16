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

/*! \defgroup mslookup Distributed GSM: finding subscribers
 *  @{
 * \file mslookup.h
 */

#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#define OSMO_MSLOOKUP_SERVICE_MAXLEN 64

bool osmo_mslookup_service_valid(const char *service);

enum osmo_mslookup_id_type {
	OSMO_MSLOOKUP_ID_NONE = 0,
	OSMO_MSLOOKUP_ID_IMSI,
	OSMO_MSLOOKUP_ID_MSISDN,
	OSMO_MSLOOKUP_ID_IMSI_AUTHORIZED,
};

extern const struct value_string osmo_mslookup_id_type_names[];
static inline const char *osmo_mslookup_id_type_name(enum osmo_mslookup_id_type val)
{ return get_value_string(osmo_mslookup_id_type_names, val); }

struct osmo_mslookup_id {
	enum osmo_mslookup_id_type type;
	union {
		char imsi[GSM23003_IMSI_MAX_DIGITS+1];
		char msisdn[GSM23003_MSISDN_MAX_DIGITS+1];
	};
};

int osmo_mslookup_id_cmp(const struct osmo_mslookup_id *a, const struct osmo_mslookup_id *b);
bool osmo_mslookup_id_valid(const struct osmo_mslookup_id *id);

enum osmo_mslookup_result_code {
	OSMO_MSLOOKUP_RC_NONE = 0,
	/*! An intermediate valid result. The request is still open for more results. */
	OSMO_MSLOOKUP_RC_RESULT,
	/*! Returned when the final request timeout has elapsed without results. */
	OSMO_MSLOOKUP_RC_NOT_FOUND,
};

extern const struct value_string osmo_mslookup_result_code_names[];
static inline const char *osmo_mslookup_result_code_name(enum osmo_mslookup_result_code val)
{ return get_value_string(osmo_mslookup_result_code_names, val); }

/*! Information to request from a lookup. */
struct osmo_mslookup_query {
	/*! Which service to request, by freely invented names. For service name conventions (for voice, SMS, HLR,...),
	 * refer to the OsmoHLR user's manual http://ftp.osmocom.org/docs/latest/osmohlr-usermanual.pdf */
	char service[OSMO_MSLOOKUP_SERVICE_MAXLEN + 1];
	/*! IMSI or MSISDN to look up. */
	struct osmo_mslookup_id id;

	/*! Caller provided private data, if desired. */
	void *priv;
};

/*! Result data as passed back to a lookup client that invoked an osmo_mslookup_client_request. */
struct osmo_mslookup_result {
	/*! Outcome of the request. */
	enum osmo_mslookup_result_code rc;

	/*! IP address and port to reach the given service via IPv4, if any. */
	struct osmo_sockaddr_str host_v4;

	/*! IP address and port to reach the given service via IPv6, if any. */
	struct osmo_sockaddr_str host_v6;

	/*! How long ago the service last verified presence of the subscriber, in seconds, or zero if the presence is
	 * invariable (like the home HLR record for an IMSI).
	 * If a subscriber has recently moved to a different location, we get multiple replies and want to choose the
	 * most recent one. If this were a timestamp, firstly the time zones would need to be taken care of.
	 * Even if we choose UTC, a service provider with an inaccurate date/time would end up affecting the result.
	 * The least susceptible to configuration errors or difference in local and remote clock is a value that
	 * indicates the actual age of the record in seconds. The time that the lookup query took to be answered should
	 * be neglectable here, since we would typically wait one second (or very few seconds) for lookup replies,
	 * while typical Location Updating periods are in the range of 15 minutes. */
	uint32_t age;

	/*! Whether this is the last result returned for this request. */
	bool last;
};

int osmo_mslookup_query_init_from_domain_str(struct osmo_mslookup_query *q, const char *domain);

size_t osmo_mslookup_id_name_buf(char *buf, size_t buflen, const struct osmo_mslookup_id *id);
char *osmo_mslookup_id_name_c(void *ctx, const struct osmo_mslookup_id *id);
char *osmo_mslookup_id_name_b(char *buf, size_t buflen, const struct osmo_mslookup_id *id);

size_t osmo_mslookup_result_to_str_buf(char *buf, size_t buflen,
				     const struct osmo_mslookup_query *query,
				     const struct osmo_mslookup_result *result);
char *osmo_mslookup_result_name_c(void *ctx,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result);
char *osmo_mslookup_result_name_b(char *buf, size_t buflen,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result);

/*! @} */
