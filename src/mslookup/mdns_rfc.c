/* Low level mDNS encoding and decoding functions of the qname IE, header/question sections and resource records,
 * as described in these RFCs:
 * - RFC 1035 (Domain names - implementation and specification)
 * - RFC 3596 (DNS Extensions to Support IP Version 6) */

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
#include <ctype.h>
#include <errno.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mdns_rfc.h>

/*
 * Encode/decode IEs
 */

/*! Encode a domain string as qname (RFC 1035 4.1.2).
 * \param[in] domain  multiple labels separated by dots, e.g. "sip.voice.1234.msisdn".
 * \returns allocated buffer with length-value pairs for each label (e.g. 0x03 "sip" 0x05 "voice" ...), NULL on error.
 */
char *osmo_mdns_rfc_qname_encode(void *ctx, const char *domain)
{
	char *domain_dup;
	char *domain_iter;
	char buf[OSMO_MDNS_RFC_MAX_NAME_LEN + 2] = ""; /* len(qname) is len(domain) +1 */
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
	char *label;

	if (strlen(domain) > OSMO_MDNS_RFC_MAX_NAME_LEN)
		return NULL;

	domain_iter = domain_dup = talloc_strdup(ctx, domain);
	while ((label = strsep(&domain_iter, "."))) {
		size_t len = strlen(label);

		/* Empty domain, dot at start, two dots in a row, or ending with a dot */
		if (!len)
			goto error;

		OSMO_STRBUF_PRINTF(sb, "%c%s", (char)len, label);
	}

	talloc_free(domain_dup);
	return talloc_strdup(ctx, buf);

error:
	talloc_free(domain_dup);
	return NULL;
}

/*! Decode a domain string from a qname (RFC 1035 4.1.2).
 * \param[in] qname  buffer with length-value pairs for each label (e.g. 0x03 "sip" 0x05 "voice" ...)
 * \param[in] qname_max_len  amount of bytes that can be read at most from the memory location that qname points to.
 * \returns allocated buffer with domain string, multiple labels separated by dots (e.g. "sip.voice.1234.msisdn"),
 *	    NULL on error.
 */
char *osmo_mdns_rfc_qname_decode(void *ctx, const char *qname, size_t qname_max_len)
{
	const char *next_label, *qname_end = qname + qname_max_len;
	char buf[OSMO_MDNS_RFC_MAX_NAME_LEN + 1];
	int i = 0;

	if (qname_max_len < 1)
		return NULL;

	while (*qname) {
		size_t len = *qname;
		next_label = qname + len + 1;

		if (next_label >= qname_end || i + len > OSMO_MDNS_RFC_MAX_NAME_LEN)
			return NULL;

		if (i) {
			/* Two dots in a row is not allowed */
			if (buf[i - 1] == '.')
				return NULL;

			buf[i] = '.';
			i++;
		}

		memcpy(buf + i, qname + 1, len);
		i += len;
		qname = next_label;
	}
	buf[i] = '\0';

	return talloc_strdup(ctx, buf);
}

/*
 * Encode/decode message sections
 */

/*! Encode header section (RFC 1035 4.1.1).
 * \param[in] msgb  mesage buffer to which the encoded data will be appended.
 */
void osmo_mdns_rfc_header_encode(struct msgb *msg, const struct osmo_mdns_rfc_header *hdr)
{
	struct osmo_mdns_rfc_header *buf = (struct osmo_mdns_rfc_header *) msgb_put(msg, sizeof(*hdr));
	memcpy(buf, hdr, sizeof(*hdr));

	osmo_store16be(buf->id, &buf->id);
	osmo_store16be(buf->qdcount, &buf->qdcount);
	osmo_store16be(buf->ancount, &buf->ancount);
	osmo_store16be(buf->nscount, &buf->nscount);
	osmo_store16be(buf->arcount, &buf->arcount);
}

/*! Decode header section (RFC 1035 4.1.1). */
int osmo_mdns_rfc_header_decode(const uint8_t *data, size_t data_len, struct osmo_mdns_rfc_header *hdr)
{
	if (data_len != sizeof(*hdr))
		return -EINVAL;

	memcpy(hdr, data, data_len);

	hdr->id = osmo_load16be(&hdr->id);
	hdr->qdcount = osmo_load16be(&hdr->qdcount);
	hdr->ancount = osmo_load16be(&hdr->ancount);
	hdr->nscount = osmo_load16be(&hdr->nscount);
	hdr->arcount = osmo_load16be(&hdr->arcount);

	return 0;
}

/*! Encode question section (RFC 1035 4.1.2).
 * \param[in] msgb  mesage buffer to which the encoded data will be appended.
 */
int osmo_mdns_rfc_question_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_rfc_question *qst)
{
	char *qname;
	size_t qname_len;
	uint8_t *qname_buf;

	/* qname */
	qname = osmo_mdns_rfc_qname_encode(ctx, qst->domain);
	if (!qname)
		return -EINVAL;
	qname_len = strlen(qname) + 1;
	qname_buf = msgb_put(msg, qname_len);
	memcpy(qname_buf, qname, qname_len);
	talloc_free(qname);

	/* qtype and qclass */
	msgb_put_u16(msg, qst->qtype);
	msgb_put_u16(msg, qst->qclass);

	return 0;
}

/*! Decode question section (RFC 1035 4.1.2). */
struct osmo_mdns_rfc_question *osmo_mdns_rfc_question_decode(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_rfc_question *ret;
	size_t qname_len = data_len - 4;

	if (data_len < 6)
		return NULL;

	/* qname */
	ret = talloc_zero(ctx, struct osmo_mdns_rfc_question);
	if (!ret)
		return NULL;
	ret->domain = osmo_mdns_rfc_qname_decode(ret, (const char *)data, qname_len);
	if (!ret->domain) {
		talloc_free(ret);
		return NULL;
	}

	/* qtype and qclass */
	ret->qtype = osmo_load16be(data + qname_len);
	ret->qclass = osmo_load16be(data + qname_len + 2);

	return ret;
}

/*
 * Encode/decode resource records
 */

/*! Encode one resource record (RFC 1035 4.1.3).
 * \param[in] msgb  mesage buffer to which the encoded data will be appended.
 */
int osmo_mdns_rfc_record_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_rfc_record *rec)
{
	char *name;
	size_t name_len;
	uint8_t *buf;

	/* name */
	name = osmo_mdns_rfc_qname_encode(ctx, rec->domain);
	if (!name)
		return -EINVAL;
	name_len = strlen(name) + 1;
	buf = msgb_put(msg, name_len);
	memcpy(buf, name, name_len);
	talloc_free(name);

	/* type, class, ttl, rdlength */
	msgb_put_u16(msg, rec->type);
	msgb_put_u16(msg, rec->class);
	msgb_put_u32(msg, rec->ttl);
	msgb_put_u16(msg, rec->rdlength);

	/* rdata */
	buf = msgb_put(msg, rec->rdlength);
	memcpy(buf, rec->rdata, rec->rdlength);
	return 0;
}

/*! Decode one resource record (RFC 1035 4.1.3). */
struct osmo_mdns_rfc_record *osmo_mdns_rfc_record_decode(void *ctx, const uint8_t *data, size_t data_len,
						       size_t *record_len)
{
	struct osmo_mdns_rfc_record *ret = talloc_zero(ctx, struct osmo_mdns_rfc_record);
	size_t name_len;

	/* name */
	ret->domain = osmo_mdns_rfc_qname_decode(ret, (const char *)data, data_len - 10);
	if (!ret->domain)
		goto error;
	name_len = strlen(ret->domain) + 2;
	if (name_len + 10 > data_len)
		goto error;

	/* type, class, ttl, rdlength */
	ret->type = osmo_load16be(data + name_len);
	ret->class = osmo_load16be(data + name_len + 2);
	ret->ttl = osmo_load32be(data + name_len + 4);
	ret->rdlength = osmo_load16be(data + name_len + 8);
	if (name_len + 10 + ret->rdlength > data_len)
		goto error;

	/* rdata */
	ret->rdata = talloc_memdup(ret, data + name_len + 10, ret->rdlength);
	if (!ret->rdata)
		return NULL;

	*record_len = name_len + 10 + ret->rdlength;
	return ret;
error:
	talloc_free(ret);
	return NULL;
}

