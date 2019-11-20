/* High level mDNS encoding and decoding functions for whole messages:
 * Request message (header, question)
 * Answer message (header, resource record 1, ... resource record N)*/

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

#include <errno.h>
#include <string.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/mslookup/mdns_msg.h>

/*! Encode request message into one mDNS packet, consisting of the header section and one question section.
 * \returns 0 on success, -EINVAL on error.
 */
int osmo_mdns_msg_request_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_request *req)
{
	struct osmo_mdns_rfc_header hdr = {0};
	struct osmo_mdns_rfc_question qst = {0};

	hdr.id = req->id;
	hdr.qdcount = 1;
	osmo_mdns_rfc_header_encode(msg, &hdr);

	qst.domain = req->domain;
	qst.qtype = req->type;
	qst.qclass = OSMO_MDNS_RFC_CLASS_IN;
	if (osmo_mdns_rfc_question_encode(ctx, msg, &qst) != 0)
		return -EINVAL;

	return 0;
}

/*! Decode request message from a mDNS packet, consisting of the header section and one question section.
 * \returns allocated request message on success, NULL on error.
 */
struct osmo_mdns_msg_request *osmo_mdns_msg_request_decode(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_rfc_header hdr = {0};
	size_t hdr_len = sizeof(struct osmo_mdns_rfc_header);
	struct osmo_mdns_rfc_question* qst = NULL;
	struct osmo_mdns_msg_request *ret = NULL;

	if (data_len < hdr_len || osmo_mdns_rfc_header_decode(data, hdr_len, &hdr) != 0 || hdr.qr != 0)
		return NULL;

	qst = osmo_mdns_rfc_question_decode(ctx, data + hdr_len, data_len - hdr_len);
	if (!qst)
		return NULL;

	ret = talloc_zero(ctx, struct osmo_mdns_msg_request);
	ret->id = hdr.id;
	ret->domain = talloc_strdup(ret, qst->domain);
	ret->type = qst->qtype;

	talloc_free(qst);
	return ret;
}

/*! Initialize the linked list for resource records in a answer message. */
void osmo_mdns_msg_answer_init(struct osmo_mdns_msg_answer *ans)
{
	*ans = (struct osmo_mdns_msg_answer){};
	INIT_LLIST_HEAD(&ans->records);
}

/*! Encode answer message into one mDNS packet, consisting of the header section and N resource records.
 *
 * To keep things simple, this sends the domain with each resource record. Other DNS implementations make use of
 * "message compression", which would send a question section with the domain before the resource records, and then
 * point inside each resource record with an offset back to the domain in the question section (RFC 1035 4.1.4).
 * \returns 0 on success, -EINVAL on error.
 */
int osmo_mdns_msg_answer_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_answer *ans)
{
	struct osmo_mdns_rfc_header hdr = {0};
	struct osmo_mdns_record *ans_record;

	hdr.id = ans->id;
	hdr.qr = 1;
	hdr.ancount = llist_count(&ans->records);
	osmo_mdns_rfc_header_encode(msg, &hdr);

	llist_for_each_entry(ans_record, &ans->records, list) {
		struct osmo_mdns_rfc_record rec = {0};

		rec.domain = ans->domain;
		rec.type = ans_record->type;
		rec.class = OSMO_MDNS_RFC_CLASS_IN;
		rec.ttl = 0;
		rec.rdlength = ans_record->length;
		rec.rdata = ans_record->data;

		if (osmo_mdns_rfc_record_encode(ctx, msg, &rec) != 0)
			return -EINVAL;
	}

	return 0;
}

/*! Decode answer message from a mDNS packet.
 *
 * Answer messages must consist of one header and one or more resource records. An additional question section or
 * message compression (RFC 1035 4.1.4) are not supported.
* \returns allocated answer message on success, NULL on error.
 */
struct osmo_mdns_msg_answer *osmo_mdns_msg_answer_decode(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_rfc_header hdr = {};
	size_t hdr_len = sizeof(struct osmo_mdns_rfc_header);
	struct osmo_mdns_msg_answer *ret = talloc_zero(ctx, struct osmo_mdns_msg_answer);

	/* Parse header section */
	if (data_len < hdr_len || osmo_mdns_rfc_header_decode(data, hdr_len, &hdr) != 0 || hdr.qr != 1)
		goto error;
	ret->id = hdr.id;
	data_len -= hdr_len;
	data += hdr_len;

	/* Parse resource records */
	INIT_LLIST_HEAD(&ret->records);
	while (data_len) {
		size_t record_len;
		struct osmo_mdns_rfc_record *rec;
		struct osmo_mdns_record* ret_record;

		rec = osmo_mdns_rfc_record_decode(ret, data, data_len, &record_len);
		if (!rec)
			goto error;

		/* Copy domain to ret */
		if (ret->domain) {
			if (strcmp(ret->domain, rec->domain) != 0) {
				LOGP(DMSLOOKUP, LOGL_ERROR, "domain mismatch in resource records ('%s' vs '%s')\n",
				     ret->domain, rec->domain);
				goto error;
			}
		}
		else
			ret->domain = talloc_strdup(ret, rec->domain);

		/* Add simplified record to ret */
		ret_record = talloc_zero(ret, struct osmo_mdns_record);
		ret_record->type = rec->type;
		ret_record->length = rec->rdlength;
		ret_record->data = talloc_memdup(ret_record, rec->rdata, rec->rdlength);
		llist_add_tail(&ret_record->list, &ret->records);

		data += record_len;
		data_len -= record_len;
		talloc_free(rec);
	}

	/* Verify record count */
	if (llist_count(&ret->records) != hdr.ancount) {
		LOGP(DMSLOOKUP, LOGL_ERROR, "amount of parsed records (%i) doesn't match count in header (%i)\n",
		     llist_count(&ret->records), hdr.ancount);
		goto error;
	}

	return ret;
error:
	talloc_free(ret);
	return NULL;
}

/*! Get a TXT resource record, which stores a key=value string.
 * \returns allocated resource record on success, NULL on error.
 */
static struct osmo_mdns_record *_osmo_mdns_record_txt_encode(void *ctx, const char *key, const char *value)
{
	struct osmo_mdns_record *ret = talloc_zero(ctx, struct osmo_mdns_record);
	size_t len = strlen(key) + 1 + strlen(value);

	if (len > OSMO_MDNS_RFC_MAX_CHARACTER_STRING_LEN - 1)
		return NULL;

	/* redundant len is required, see RFC 1035 3.3.14 and 3.3. */
	ret->data = (uint8_t *)talloc_asprintf(ctx, "%c%s=%s", (char)len, key, value);
	if (!ret->data)
		return NULL;
	ret->type = OSMO_MDNS_RFC_RECORD_TYPE_TXT;
	ret->length = len + 1;
	return ret;
}

/*! Get a TXT resource record, which stores a key=value string, but build value from a format string.
 * \returns allocated resource record on success, NULL on error.
 */
struct osmo_mdns_record *osmo_mdns_record_txt_keyval_encode(void *ctx, const char *key, const char *value_fmt, ...)
{
	va_list ap;
	char *value = NULL;
	struct osmo_mdns_record *r;

	if (!value_fmt)
		return _osmo_mdns_record_txt_encode(ctx, key, "");

	va_start(ap, value_fmt);
	value = talloc_vasprintf(ctx, value_fmt, ap);
	if (!value)
		return NULL;
	va_end(ap);
	r = _osmo_mdns_record_txt_encode(ctx, key, value);
	talloc_free(value);
	return r;
}

/*! Decode a TXT resource record, which stores a key=value string.
 * \returns 0 on success, -EINVAL on error.
 */
int osmo_mdns_record_txt_keyval_decode(const struct osmo_mdns_record *rec,
				       char *key_buf, size_t key_size, char *value_buf, size_t value_size)
{
	const char *key_value;
	const char *key_value_end;
	const char *sep;
	const char *value;

	if (rec->type != OSMO_MDNS_RFC_RECORD_TYPE_TXT)
		return -EINVAL;

	key_value = (const char *)rec->data;
	key_value_end = key_value + rec->length;

	/* Verify and then skip the redundant string length byte */
	if (*key_value != rec->length - 1)
		return -EINVAL;
	key_value++;

	if (key_value >= key_value_end)
		return -EINVAL;

	/* Find equals sign */
	sep = osmo_strnchr(key_value, key_value_end - key_value, '=');
	if (!sep)
		return -EINVAL;

	/* Parse key */
	osmo_print_n(key_buf, key_size, key_value, sep - key_value);

	/* Parse value */
	value = sep + 1;
	osmo_print_n(value_buf, value_size, value, key_value_end - value);
	return 0;
}
