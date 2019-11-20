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

#include <string.h>
#include <errno.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/mslookup/mslookup.h>

/*! \addtogroup mslookup
 *
 * Distributed GSM: finding subscribers
 *
 * There are various aspects of the D-GSM code base in osmo-hlr.git, here is an overview:
 *
 * mslookup is the main enabler of D-GSM, a concept for connecting services between independent core network stacks.
 *
 * D-GSM consists of:
 * (1) mslookup client to find subscribers:
 *     (a) external clients like ESME, SIP PBX, ... ask osmo-hlr to tell where to send SMS, voice calls, ...
 *     (b) osmo-hlr's own mslookup client asks remote osmo-hlrs whether they know a given IMSI.
 * (2) when a subscriber was found at a remote HLR, GSUP gets forwarded there:
 *     (a) to deliver messages for the GSUP proxy, osmo-hlr manages many GSUP clients to establish links to remote HLRs.
 *     (b) osmo-hlr has a GSUP proxy layer that caches data of IMSIs that get proxied to a remote HLR.
 *     (c) decision making to distinguish local IMSIs from ones proxied to a remote HLR.
 *
 * (1) mslookup is a method of finding subscribers using (multicast) queries, by MSISDN or by IMSI.
 * It is open to various lookup methods, the first one being multicast DNS.
 * An mslookup client sends a request, and an mslookup server responds.
 * The mslookup server is implemented by osmo-hlr. mslookup clients are arbitrary programs, like an ESME or a SIP PBX.
 * Hence the mslookup client is public API, while the mslookup server is implemented "privately" in osmo-hlr.
 *
 * (1a) Public mslookup client: libosmo-mslookup
 *   src/mslookup/mslookup.c               Things useful for both client and server.
 *   src/mslookup/mslookup_client.c        The client API, which can use various lookup methods,
 *                                         and consolidates results from various responders.
 *   src/mslookup/mslookup_client_mdns.c   lookup method implementing multicast DNS, client side.
 *
 *   src/mslookup/osmo-mslookup-client.c   Utility program to ease invocation for (blocking) mslookup clients.
 *
 *   src/mslookup/mslookup_client_fake.c   lookup method generating fake results, for testing client implementations.
 *
 *   src/mslookup/mdns*.c                  implementation of DNS to be used by mslookup_client_mdns.c,
 *                                         and the mslookup_server.c.
 *
 *   contrib/dgsm/esme_dgsm.py                 Example implementation for an mslookup enabled SMS handler.
 *   contrib/dgsm/freeswitch_dialplan_dgsm.py  Example implementation for an mslookup enabled FreeSWITCH dialplan.
 *   contrib/dgsm/osmo-mslookup-pipe.py        Example for writing a python client using the osmo-mslookup-client
 *                                             cmdline.
 *   contrib/dgsm/osmo-mslookup-socket.py      Example for writing a python client using the osmo-mslookup-client
 *                                             unix domain socket.
 *
 * (1b) "Private" mslookup server in osmo-hlr:
 *   src/mslookup_server.c        Respond to mslookup queries, independent from the particular lookup method.
 *   src/mslookup_server_mdns.c   mDNS specific implementation for mslookup_server.c.
 *   src/dgsm_vty.c               Configure services that mslookup server sends to remote requests.
 *
 * (2) Proxy and GSUP clients to remote HLR instances:
 *
 * (a) Be a GSUP client to forward to a remote HLR:
 *  src/gsupclient/   The same API that is used by osmo-{msc,sgsn} is also used to forward GSUP to remote osmo-hlrs.
 *  src/remote_hlr.c  Establish links to remote osmo-hlrs, where this osmo-hlr is a client (proxying e.g. for an MSC).
 *
 * (b) Keep track of remotely handled IMSIs:
 *  src/proxy.c       Keep track of proxied IMSIs and cache important subscriber data.
 *
 * (c) Direct GSUP request to the right destination: either the local or a remote HLR:
 *  src/dgsm.c        The glue that makes osmo-hlr distinguish between local IMSIs and those that are proxied to another
 *                    osmo-hlr.
 *  src/dgsm_vty.c    Config.
 *
 *  @{
 * \file mslookup.c
 */

const struct value_string osmo_mslookup_id_type_names[] = {
	{ OSMO_MSLOOKUP_ID_NONE, "none" },
	{ OSMO_MSLOOKUP_ID_IMSI, "imsi" },
	{ OSMO_MSLOOKUP_ID_MSISDN, "msisdn" },
	{}
};

const struct value_string osmo_mslookup_result_code_names[] = {
	{ OSMO_MSLOOKUP_RC_NONE, "none" },
	{ OSMO_MSLOOKUP_RC_RESULT, "result" },
	{ OSMO_MSLOOKUP_RC_NOT_FOUND, "not-found" },
	{}
};

/*! Compare two struct osmo_mslookup_id.
 * \returns   0 if a and b are equal,
 *          < 0 if a (or the ID type / start of ID) is < b,
 *          > 0 if a (or the ID type / start of ID) is > b.
 */
int osmo_mslookup_id_cmp(const struct osmo_mslookup_id *a, const struct osmo_mslookup_id *b)
{
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	cmp = OSMO_CMP(a->type, b->type);
	if (cmp)
		return cmp;

	switch (a->type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		return strncmp(a->imsi, b->imsi, sizeof(a->imsi));
	case OSMO_MSLOOKUP_ID_MSISDN:
		return strncmp(a->msisdn, b->msisdn, sizeof(a->msisdn));
	default:
		return 0;
	}
}

bool osmo_mslookup_id_valid(const struct osmo_mslookup_id *id)
{
	switch (id->type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		return osmo_imsi_str_valid(id->imsi);
	case OSMO_MSLOOKUP_ID_MSISDN:
		return osmo_msisdn_str_valid(id->msisdn);
	default:
		return false;
	}
}

bool osmo_mslookup_service_valid(const char *service)
{
	return strlen(service) > 0;
}

/*! Write ID and ID type to a buffer.
 * \param[out] buf  nul-terminated {id}.{id_type} string (e.g. "1234.msisdn") or
* 		    "?.none" if the ID type is invalid.
 * \returns amount of bytes written to buf.
 */
size_t osmo_mslookup_id_name_buf(char *buf, size_t buflen, const struct osmo_mslookup_id *id)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	switch (id->type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		OSMO_STRBUF_PRINTF(sb, "%s", id->imsi);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		OSMO_STRBUF_PRINTF(sb, "%s", id->msisdn);
		break;
	default:
		OSMO_STRBUF_PRINTF(sb, "?");
		break;
	}
	OSMO_STRBUF_PRINTF(sb, ".%s", osmo_mslookup_id_type_name(id->type));
	return sb.chars_needed;
}

/*! Same as osmo_mslookup_id_name_buf(), but return a talloc allocated string of sufficient size. */
char *osmo_mslookup_id_name_c(void *ctx, const struct osmo_mslookup_id *id)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_mslookup_id_name_buf, id)
}

/*! Same as osmo_mslookup_id_name_buf(), but directly return the char* (for printf-like string formats). */
char *osmo_mslookup_id_name_b(char *buf, size_t buflen, const struct osmo_mslookup_id *id)
{
	int rc = osmo_mslookup_id_name_buf(buf, buflen, id);
	if (rc < 0 && buflen)
		buf[0] = '\0';
	return buf;
}

/*! Write mslookup result string to buffer.
 * \param[in] query  with the service, ID and ID type to be written to buf like a domain string, or NULL to omit.
 * \param[in] result with the result code, IPv4/v6 and age to be written to buf or NULL to omit.
 * \param[out] buf  result as flat string, which looks like the following for a valid query and result with IPv4 and v6
 *                  answer: "sip.voice.1234.msisdn -> ipv4: 42.42.42.42:1337 -> ipv6: [1234:5678:9ABC::]:1338 (age=1)",
 *                  the result part can also be " -> timeout" or " -> rc=5" depending on the result code.
 * \returns amount of bytes written to buf.
 */
size_t osmo_mslookup_result_to_str_buf(char *buf, size_t buflen,
				     const struct osmo_mslookup_query *query,
				     const struct osmo_mslookup_result *result)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (query) {
		OSMO_STRBUF_PRINTF(sb, "%s.", query->service);
		OSMO_STRBUF_APPEND(sb, osmo_mslookup_id_name_buf, &query->id);
	}
	if (result && result->rc == OSMO_MSLOOKUP_RC_NONE)
		result = NULL;
	if (result) {
		if (result->rc != OSMO_MSLOOKUP_RC_RESULT) {
			OSMO_STRBUF_PRINTF(sb, " %s", osmo_mslookup_result_code_name(result->rc));
		} else {
			if (result->host_v4.ip[0]) {
				OSMO_STRBUF_PRINTF(sb, " -> ipv4: " OSMO_SOCKADDR_STR_FMT,
						   OSMO_SOCKADDR_STR_FMT_ARGS(&result->host_v4));
			}
			if (result->host_v6.ip[0]) {
				OSMO_STRBUF_PRINTF(sb, " -> ipv6: " OSMO_SOCKADDR_STR_FMT,
						   OSMO_SOCKADDR_STR_FMT_ARGS(&result->host_v6));
			}
			OSMO_STRBUF_PRINTF(sb, " (age=%u)", result->age);
		}
		OSMO_STRBUF_PRINTF(sb, " %s", result->last ? "(last)" : "(not-last)");
	}
	return sb.chars_needed;
}

/*! Same as osmo_mslookup_result_to_str_buf(), but return a talloc allocated string of sufficient size. */
char *osmo_mslookup_result_name_c(void *ctx,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_mslookup_result_to_str_buf, query, result)
}

/*! Same as osmo_mslookup_result_to_str_buf(), but directly return the char* (for printf-like string formats). */
char *osmo_mslookup_result_name_b(char *buf, size_t buflen,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result)
{
	int rc = osmo_mslookup_result_to_str_buf(buf, buflen, query, result);
	if (rc < 0 && buflen)
		buf[0] = '\0';
	return buf;
}

/*! Copy part of a string to a buffer and nul-terminate it.
 * \returns 0 on success, negative on error.
 */
static int token(char *dest, size_t dest_size, const char *start, const char *end)
{
	int len;
	if (start >= end)
		return -10;
	len = end - start;
	if (len >= dest_size)
		return -11;
	strncpy(dest, start, len);
	dest[len] = '\0';
	return 0;
}

/*! Parse a string like "foo.moo.goo.123456789012345.msisdn" into service="foo.moo.goo", id="123456789012345" and
 * id_type="msisdn", placed in a struct osmo_mslookup_query.
 * \param q  Write parsed query to this osmo_mslookup_query.
 * \param domain  Human readable domain string like "sip.voice.12345678.msisdn".
 * \returns 0 on success, negative on error.
 */
int osmo_mslookup_query_init_from_domain_str(struct osmo_mslookup_query *q, const char *domain)
{
	const char *last_dot;
	const char *second_last_dot;
	const char *id_type;
	const char *id;
	int rc;

	*q = (struct osmo_mslookup_query){};

	if (!domain)
		return -1;

	last_dot = strrchr(domain, '.');

	if (!last_dot)
		return -2;

	if (last_dot <= domain)
		return -3;

	for (second_last_dot = last_dot - 1; second_last_dot > domain && *second_last_dot != '.'; second_last_dot--);
	if (second_last_dot == domain || *second_last_dot != '.')
		return -3;

	id_type = last_dot + 1;
	if (!*id_type)
		return -4;

	q->id.type = get_string_value(osmo_mslookup_id_type_names, id_type);

	id = second_last_dot + 1;
	switch (q->id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		rc = token(q->id.imsi, sizeof(q->id.imsi), id, last_dot);
		if (rc)
			return rc;
		if (!osmo_imsi_str_valid(q->id.imsi))
			return -5;
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		rc = token(q->id.msisdn, sizeof(q->id.msisdn), id, last_dot);
		if (rc)
			return rc;
		if (!osmo_msisdn_str_valid(q->id.msisdn))
			return -6;
		break;
	default:
		return -7;
	}

	return token(q->service, sizeof(q->service), domain, second_last_dot);
}

/*! @} */
