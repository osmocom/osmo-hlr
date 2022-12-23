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
#include <osmocom/gsm/apn.h>
#include <osmocom/mslookup/mdns_rfc.h>

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
int osmo_mdns_rfc_question_encode(struct msgb *msg, const struct osmo_mdns_rfc_question *qst)
{
	uint8_t *buf;
	size_t buf_len;

	/* qname */
	buf_len = strlen(qst->domain) + 1;
	buf = msgb_put(msg, buf_len);
	if (osmo_apn_from_str(buf, buf_len, qst->domain) < 0)
		return -EINVAL;
	msgb_put_u8(msg, 0x00);

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

	ret = talloc_zero(ctx, struct osmo_mdns_rfc_question);
	if (!ret)
		return NULL;

	/* qname */
	ret->domain = talloc_size(ret, qname_len - 1);
	if (!ret->domain)
		goto error;
	if (!osmo_apn_to_str(ret->domain, data, qname_len - 1))
		goto error;

	/* qtype and qclass */
	ret->qtype = osmo_load16be(data + qname_len);
	ret->qclass = osmo_load16be(data + qname_len + 2);

	return ret;
error:
	talloc_free(ret);
	return NULL;
}

/*
 * Encode/decode resource records
 */

/*! Encode one resource record (RFC 1035 4.1.3).
 * \param[in] msgb  mesage buffer to which the encoded data will be appended.
 */
int osmo_mdns_rfc_record_encode(struct msgb *msg, const struct osmo_mdns_rfc_record *rec)
{
	uint8_t *buf;
	size_t buf_len;

	/* name */
	buf_len = strlen(rec->domain) + 1;
	buf = msgb_put(msg, buf_len);
	if (osmo_apn_from_str(buf, buf_len, rec->domain) < 0)
		return -EINVAL;
	msgb_put_u8(msg, 0x00);

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
	struct osmo_mdns_rfc_record *ret;
	size_t name_len;

	/* name length: represented as a series of labels, and terminated by a
	 * label with zero length (RFC 1035 3.3). A label with zero length is a
	 * NUL byte. */
	name_len = strnlen((const char *)data, data_len - 10) + 1;
	if (data[name_len])
		return NULL;

	/* allocate ret + ret->domain */
	ret = talloc_zero(ctx, struct osmo_mdns_rfc_record);
	if (!ret)
		return NULL;
	ret->domain = talloc_size(ctx, name_len - 1);
	if (!ret->domain)
		goto error;

	/* name */
	if (!osmo_apn_to_str(ret->domain, data, name_len - 1))
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
		goto error;

	*record_len = name_len + 10 + ret->rdlength;
	return ret;
error:
	talloc_free(ret);
	return NULL;
}

