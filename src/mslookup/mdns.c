/* mslookup specific functions for encoding and decoding mslookup queries/results into mDNS packets, using the high
 * level functions from mdns_msg.c and mdns_record.c to build the request/answer messages. */

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

#include <osmocom/hlr/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/mslookup/mslookup.h>
#include <osmocom/mslookup/mdns_msg.h>
#include <osmocom/mslookup/mdns_rfc.h>
#include <errno.h>
#include <inttypes.h>

static struct msgb *osmo_mdns_msgb_alloc(const char *label)
{
	return msgb_alloc(1024, label);
}

/*! Combine the mslookup query service, ID and ID type into a domain string.
 * \param[in] domain_suffix  is appended to each domain in the queries to avoid colliding with the top-level domains
 *                           administrated by IANA. Example: "mdns.osmocom.org"
 * \returns allocated buffer with the resulting domain (i.e. "sip.voice.123.msisdn.mdns.osmocom.org") on success,
 * 	    NULL on failure.
 */
static char *domain_from_query(void *ctx, const struct osmo_mslookup_query *query, const char *domain_suffix)
{
	const char *id;

	/* Get id from query */
	switch (query->id.type) {
		case OSMO_MSLOOKUP_ID_IMSI:
		case OSMO_MSLOOKUP_ID_IMSI_AUTHORIZED:
			id = query->id.imsi;
			break;
		case OSMO_MSLOOKUP_ID_MSISDN:
			id = query->id.msisdn;
			break;
		default:
			LOGP(DMSLOOKUP, LOGL_ERROR, "can't encode mslookup query id type %i", query->id.type);
			return NULL;
	}

	return talloc_asprintf(ctx, "%s.%s.%s.%s", query->service, id, osmo_mslookup_id_type_name(query->id.type),
			       domain_suffix);
}

/*! Split up query service, ID and ID type from a domain string into a mslookup query.
 * \param[in] domain  with domain_suffix, e.g. "sip.voice.123.msisdn.mdns.osmocom.org"
 * \param[in] domain_suffix  is appended to each domain in the queries to avoid colliding with the top-level domains
 *                           administrated by IANA. It is not part of the resulting struct osmo_mslookup_query, so we
 *                           remove it in this function. Example: "mdns.osmocom.org"
 */
int query_from_domain(struct osmo_mslookup_query *query, const char *domain, const char *domain_suffix)
{
	int domain_len = strlen(domain) - strlen(domain_suffix) - 1;
	char domain_buf[OSMO_MDNS_RFC_MAX_NAME_LEN];

	if (domain_len <= 0 || domain_len >= sizeof(domain_buf))
		return -EINVAL;

	if (domain[domain_len] != '.' || strcmp(domain + domain_len + 1, domain_suffix) != 0)
		return -EINVAL;

	memcpy(domain_buf, domain, domain_len);
	domain_buf[domain_len] = '\0';
	return osmo_mslookup_query_init_from_domain_str(query, domain_buf);
}

/*! Encode a mslookup query into a mDNS packet.
 * \param[in] domain_suffix  is appended to each domain in the queries to avoid colliding with the top-level domains
 *                           administrated by IANA. Example: "mdns.osmocom.org"
 * \returns msgb, or NULL on error.
 */
struct msgb *osmo_mdns_query_encode(void *ctx, uint16_t packet_id, const struct osmo_mslookup_query *query,
				    const char *domain_suffix)
{
	struct osmo_mdns_msg_request req = {0};
	struct msgb *msg = osmo_mdns_msgb_alloc(__func__);

	req.id = packet_id;
	req.type = OSMO_MDNS_RFC_RECORD_TYPE_ALL;
	req.domain = domain_from_query(ctx, query, domain_suffix);
	if (!req.domain)
		goto error;
	if (osmo_mdns_msg_request_encode(ctx, msg, &req))
		goto error;
	talloc_free(req.domain);
	return msg;
error:
	msgb_free(msg);
	talloc_free(req.domain);
	return NULL;
}

/*! Decode a mDNS request packet into a mslookup query.
 * \param[out] packet_id  the result must be sent with the same packet_id.
 * \param[in] domain_suffix  is appended to each domain in the queries to avoid colliding with the top-level domains
 *                           administrated by IANA. Example: "mdns.osmocom.org"
 * \returns allocated mslookup query on success, NULL on error.
 */
struct osmo_mslookup_query *osmo_mdns_query_decode(void *ctx, const uint8_t *data, size_t data_len,
						   uint16_t *packet_id, const char *domain_suffix)
{
	struct osmo_mdns_msg_request *req = NULL;
	struct osmo_mslookup_query *query = NULL;

	req = osmo_mdns_msg_request_decode(ctx, data, data_len);
	if (!req)
		return NULL;

	query = talloc_zero(ctx, struct osmo_mslookup_query);
	OSMO_ASSERT(query);
	if (query_from_domain(query, req->domain, domain_suffix) < 0)
		goto error_free;

	*packet_id = req->id;
	talloc_free(req);
	return query;
error_free:
	talloc_free(req);
	talloc_free(query);
	return NULL;
}

/*! Parse sockaddr_str from mDNS record, so the mslookup result can be filled with it.
 * \param[out] sockaddr_str resulting IPv4 or IPv6 sockaddr_str.
 * \param[in] rec  single record of the abstracted list of mDNS records
 * \returns 0 on success, -EINVAL on error.
 */
static int sockaddr_str_from_mdns_record(struct osmo_sockaddr_str *sockaddr_str, struct osmo_mdns_record *rec)
{
	switch (rec->type) {
	case OSMO_MDNS_RFC_RECORD_TYPE_A:
		if (rec->length != 4) {
			LOGP(DMSLOOKUP, LOGL_ERROR, "unexpected length of A record\n");
			return -EINVAL;
		}
		osmo_sockaddr_str_from_32(sockaddr_str, *(uint32_t *)rec->data, 0);
		break;
	case OSMO_MDNS_RFC_RECORD_TYPE_AAAA:
		if (rec->length != 16) {
			LOGP(DMSLOOKUP, LOGL_ERROR, "unexpected length of AAAA record\n");
			return -EINVAL;
		}
		osmo_sockaddr_str_from_in6_addr(sockaddr_str, (struct in6_addr*)rec->data, 0);
		break;
	default:
		LOGP(DMSLOOKUP, LOGL_ERROR, "unexpected record type\n");
		return -EINVAL;
	}
	return 0;
}

/*! Encode a successful mslookup result, along with the original query and packet_id into one mDNS answer packet.
 *
 * The records in the packet are ordered as follows:
 * 1) "age", ip_v4/v6, "port" (only IPv4 or IPv6 present) or
 * 2) "age", ip_v4, "port", ip_v6, "port" (both IPv4 and v6 present).
 * "age" and "port" are TXT records, ip_v4 is an A record, ip_v6 is an AAAA record.
 *
 * \param[in] packet_id  as received in osmo_mdns_query_decode().
 * \param[in] query  the original query, so we can send the domain back in the answer (i.e. "sip.voice.1234.msisdn").
 * \param[in] result  holds the age, IPs and ports of the queried service.
 * \param[in] domain_suffix  is appended to each domain in the queries to avoid colliding with the top-level domains
 *                           administrated by IANA. Example: "mdns.osmocom.org"
 * \returns msg on success, NULL on error.
 */
struct msgb *osmo_mdns_result_encode(void *ctx, uint16_t packet_id, const struct osmo_mslookup_query *query,
				     const struct osmo_mslookup_result *result, const char *domain_suffix)
{
	struct osmo_mdns_msg_answer ans = {};
	struct osmo_mdns_record *rec_age = NULL;
	struct osmo_mdns_record rec_ip_v4 = {0};
	struct osmo_mdns_record rec_ip_v6 = {0};
	struct osmo_mdns_record *rec_ip_v4_port = NULL;
	struct osmo_mdns_record *rec_ip_v6_port = NULL;
	struct in_addr rec_ip_v4_in;
	struct in6_addr rec_ip_v6_in;
	struct msgb *msg = osmo_mdns_msgb_alloc(__func__);
	char buf[256];

	ctx = talloc_named(ctx, 0, "osmo_mdns_result_encode");

	/* Prepare answer (ans) */
	ans.domain = domain_from_query(ctx, query, domain_suffix);
	if (!ans.domain)
		goto error;
	ans.id = packet_id;
	INIT_LLIST_HEAD(&ans.records);

	/* Record for age */
	rec_age = osmo_mdns_record_txt_keyval_encode(ctx, "age", "%"PRIu32, result->age);
	OSMO_ASSERT(rec_age);
	llist_add_tail(&rec_age->list, &ans.records);

	/* Records for IPv4 */
	if (osmo_sockaddr_str_is_set(&result->host_v4)) {
		if (osmo_sockaddr_str_to_in_addr(&result->host_v4, &rec_ip_v4_in) < 0) {
			LOGP(DMSLOOKUP, LOGL_ERROR, "failed to encode ipv4: %s\n",
			     osmo_mslookup_result_name_b(buf, sizeof(buf), query, result));
			goto error;
		}
		rec_ip_v4.type = OSMO_MDNS_RFC_RECORD_TYPE_A;
		rec_ip_v4.data = (uint8_t *)&rec_ip_v4_in;
		rec_ip_v4.length = sizeof(rec_ip_v4_in);
		llist_add_tail(&rec_ip_v4.list, &ans.records);

		rec_ip_v4_port = osmo_mdns_record_txt_keyval_encode(ctx, "port", "%"PRIu16, result->host_v4.port);
		OSMO_ASSERT(rec_ip_v4_port);
		llist_add_tail(&rec_ip_v4_port->list, &ans.records);
	}

	/* Records for IPv6 */
	if (osmo_sockaddr_str_is_set(&result->host_v6)) {
		if (osmo_sockaddr_str_to_in6_addr(&result->host_v6, &rec_ip_v6_in) < 0) {
			LOGP(DMSLOOKUP, LOGL_ERROR, "failed to encode ipv6: %s\n",
			     osmo_mslookup_result_name_b(buf, sizeof(buf), query, result));
			goto error;
		}
		rec_ip_v6.type = OSMO_MDNS_RFC_RECORD_TYPE_AAAA;
		rec_ip_v6.data = (uint8_t *)&rec_ip_v6_in;
		rec_ip_v6.length = sizeof(rec_ip_v6_in);
		llist_add_tail(&rec_ip_v6.list, &ans.records);

		rec_ip_v6_port = osmo_mdns_record_txt_keyval_encode(ctx, "port", "%"PRIu16, result->host_v6.port);
		OSMO_ASSERT(rec_ip_v6_port);
		llist_add_tail(&rec_ip_v6_port->list, &ans.records);
	}

	if (osmo_mdns_msg_answer_encode(ctx, msg, &ans)) {
		LOGP(DMSLOOKUP, LOGL_ERROR, "failed to encode mDNS answer: %s\n",
		     osmo_mslookup_result_name_b(buf, sizeof(buf), query, result));
		goto error;
	}
	talloc_free(ctx);
	return msg;
error:
	msgb_free(msg);
	talloc_free(ctx);
	return NULL;
}

static int decode_uint32_t(const char *str, uint32_t *val)
{
	long long int lld;
	char *endptr = NULL;
	*val = 0;
	errno = 0;
	lld = strtoll(str, &endptr, 10);
	if (errno || !endptr || *endptr)
		return -EINVAL;
	if (lld < 0 || lld > UINT32_MAX)
		return -EINVAL;
	*val = lld;
	return 0;
}

static int decode_port(const char *str, uint16_t *port)
{
	uint32_t val;
	if (decode_uint32_t(str, &val))
		return -EINVAL;
	if (val > 65535)
		return -EINVAL;
	*port = val;
	return 0;
}

/*! Read expected mDNS records into mslookup result.
 *
 * The records in the packet must be ordered as follows:
 * 1) "age", ip_v4/v6, "port" (only IPv4 or IPv6 present) or
 * 2) "age", ip_v4, "port", ip_v6, "port" (both IPv4 and v6 present).
 * "age" and "port" are TXT records, ip_v4 is an A record, ip_v6 is an AAAA record.
 *
 * \param[out] result  holds the age, IPs and ports of the queried service.
 * \param[in] ans  abstracted mDNS answer with a list of resource records.
 * \returns 0 on success, -EINVAL on error.
 */
int osmo_mdns_result_from_answer(struct osmo_mslookup_result *result, const struct osmo_mdns_msg_answer *ans)
{
	struct osmo_mdns_record *rec;
	char txt_key[64];
	char txt_value[64];
	bool found_age = false;
	bool found_ip_v4 = false;
	bool found_ip_v6 = false;
	struct osmo_sockaddr_str *expect_port_for = NULL;

	*result = (struct osmo_mslookup_result){};

	result->rc = OSMO_MSLOOKUP_RC_NONE;

	llist_for_each_entry(rec, &ans->records, list) {
		switch (rec->type) {
			case OSMO_MDNS_RFC_RECORD_TYPE_A:
				if (expect_port_for) {
					LOGP(DMSLOOKUP, LOGL_ERROR,
					     "'A' record found, but still expecting a 'port' value first\n");
					return -EINVAL;
				}
				if (found_ip_v4) {
					LOGP(DMSLOOKUP, LOGL_ERROR, "'A' record found twice in mDNS answer\n");
					return -EINVAL;
				}
				found_ip_v4 = true;
				expect_port_for = &result->host_v4;
				if (sockaddr_str_from_mdns_record(expect_port_for, rec)) {
					LOGP(DMSLOOKUP, LOGL_ERROR, "'A' record with invalid address data\n");
					return -EINVAL;
				}
				break;
			case OSMO_MDNS_RFC_RECORD_TYPE_AAAA:
				if (expect_port_for) {
					LOGP(DMSLOOKUP, LOGL_ERROR,
					     "'AAAA' record found, but still expecting a 'port' value first\n");
					return -EINVAL;
				}
				if (found_ip_v6) {
					LOGP(DMSLOOKUP, LOGL_ERROR, "'AAAA' record found twice in mDNS answer\n");
					return -EINVAL;
				}
				found_ip_v6 = true;
				expect_port_for = &result->host_v6;
				if (sockaddr_str_from_mdns_record(expect_port_for, rec) != 0) {
					LOGP(DMSLOOKUP, LOGL_ERROR, "'AAAA' record with invalid address data\n");
					return -EINVAL;
				}
				break;
			case OSMO_MDNS_RFC_RECORD_TYPE_TXT:
				if (osmo_mdns_record_txt_keyval_decode(rec, txt_key, sizeof(txt_key),
								       txt_value, sizeof(txt_value)) != 0) {
					LOGP(DMSLOOKUP, LOGL_ERROR, "failed to decode txt record\n");
					return -EINVAL;
				}
				if (strcmp(txt_key, "age") == 0) {
					if (found_age) {
						LOGP(DMSLOOKUP, LOGL_ERROR, "duplicate 'TXT' record for 'age'\n");
						return -EINVAL;
					}
					found_age = true;
					if (decode_uint32_t(txt_value, &result->age)) {
						LOGP(DMSLOOKUP, LOGL_ERROR,
						     "'TXT' record: invalid 'age' value ('age=%s')\n", txt_value);
						return -EINVAL;
					}
				} else if (strcmp(txt_key, "port") == 0) {
					if (!expect_port_for) {
						LOGP(DMSLOOKUP, LOGL_ERROR,
						     "'TXT' record for 'port' without previous 'A' or 'AAAA' record\n");
						return -EINVAL;
					}
					if (decode_port(txt_value, &expect_port_for->port)) {
						LOGP(DMSLOOKUP, LOGL_ERROR,
						     "'TXT' record: invalid 'port' value ('port=%s')\n", txt_value);
						return -EINVAL;
					}
					expect_port_for = NULL;
				} else {
					LOGP(DMSLOOKUP, LOGL_ERROR, "unexpected key '%s' in TXT record\n", txt_key);
					return -EINVAL;
				}
				break;
			default:
				LOGP(DMSLOOKUP, LOGL_ERROR, "unexpected record type\n");
				return -EINVAL;
		}
	}

	/* Check if everything was found */
	if (!found_age || !(found_ip_v4 || found_ip_v6) || expect_port_for) {
		LOGP(DMSLOOKUP, LOGL_ERROR, "missing resource records in mDNS answer\n");
		return -EINVAL;
	}

	result->rc = OSMO_MSLOOKUP_RC_RESULT;
	return 0;
}

/*! Decode a mDNS answer packet into a mslookup result, query and packet_id.
 * \param[out] packet_id  same ID as sent in the request packet.
 * \param[out] query  the original query (service, ID, ID type).
 * \param[out] result  holds the age, IPs and ports of the queried service.
 * \param[in] domain_suffix  is appended to each domain in the queries to avoid colliding with the top-level domains
 *                           administrated by IANA. Example: "mdns.osmocom.org"
 * \returns 0 on success, -EINVAL on error.
 */
int osmo_mdns_result_decode(void *ctx, const uint8_t *data, size_t data_len, uint16_t *packet_id,
			    struct osmo_mslookup_query *query, struct osmo_mslookup_result *result,
			    const char *domain_suffix)
{
	int rc = -EINVAL;
	struct osmo_mdns_msg_answer *ans;
	ans = osmo_mdns_msg_answer_decode(ctx, data, data_len);
	if (!ans)
		goto exit_free;

	if (query_from_domain(query, ans->domain, domain_suffix) < 0)
		goto exit_free;

	if (osmo_mdns_result_from_answer(result, ans) < 0)
		goto exit_free;

	*packet_id = ans->id;
	rc = 0;

exit_free:
	talloc_free(ans);
	return rc;
}
