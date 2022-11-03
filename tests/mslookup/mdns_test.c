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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/mslookup/mdns_rfc.h>
#include <osmocom/mslookup/mdns_msg.h>

struct qname_enc_dec_test {
	const char *domain;
	const char *qname;
	size_t qname_max_len; /* default: strlen(qname) + 1 */
};

static const struct qname_enc_dec_test qname_enc_dec_test_data[] = {
	{
		/* OK: typical mslookup domain */
		.domain = "hlr.1234567.imsi",
		.qname = "\x03" "hlr" "\x07" "1234567" "\x04" "imsi",
	},
	{
		/* Wrong format: double dot */
		.domain = "hlr..imsi",
		.qname = NULL,
	},
	{
		/* Wrong format: double dot */
		.domain = "hlr",
		.qname = "\x03hlr\0\x03imsi",
	},
	{
		/* Wrong format: dot at end */
		.domain = "hlr.",
		.qname = NULL,
	},
	{
		/* Wrong format: dot at start */
		.domain = ".hlr",
		.qname = NULL,
	},
	{
		/* Wrong format: empty */
		.domain = "",
		.qname = NULL,
	},
	{
		/* OK: maximum length */
		.domain =
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"12345"
			,
		.qname =
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\x05" "12345"
	},
	{
		/* Error: too long domain */
		.domain =
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"12345toolong"
			,
		.qname = NULL,
	},
	{
		/* Error: too long qname */
		.domain = NULL,
		.qname =
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
	},
	{
		/* Error: wrong token length in qname */
		.domain = NULL,
		.qname = "\x03" "hlr" "\x07" "1234567" "\x05" "imsi",
	},
	{
		/* Error: wrong token length in qname */
		.domain = NULL,
		.qname = "\x02" "hlr" "\x07" "1234567" "\x04" "imsi",
	},
	{
		/* Wrong format: token length at end of qname */
		.domain = NULL,
		.qname = "\x03hlr\x03",
	},
	{
		/* Error: overflow in label length */
		.domain = NULL,
		.qname = "\x03" "hlr" "\x07" "1234567" "\x04" "imsi",
		.qname_max_len = 17,
	},
};

void test_enc_dec_rfc_qname(void *ctx)
{
	char quote_buf[300];
	int i;

	fprintf(stderr, "-- %s --\n", __func__);

	for (i = 0; i < ARRAY_SIZE(qname_enc_dec_test_data); i++) {
		const struct qname_enc_dec_test *t = &qname_enc_dec_test_data[i];
		char *res;

		if (t->domain) {
			fprintf(stderr, "domain: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->domain, -1));
			fprintf(stderr, "exp: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->qname, -1));
			res = osmo_mdns_rfc_qname_encode(ctx, t->domain);
			fprintf(stderr, "res: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), res, -1));
			if (t->qname == res || (t->qname && res && strcmp(t->qname, res) == 0))
				fprintf(stderr, "=> OK\n");
			else
				fprintf(stderr, "=> ERROR\n");
			if (res)
				talloc_free(res);
			fprintf(stderr, "\n");
		}

		if (t->qname) {
			size_t qname_max_len = t->qname_max_len;
			if (qname_max_len)
				fprintf(stderr, "qname_max_len: %lu\n", qname_max_len);
			else
				qname_max_len = strlen(t->qname) + 1;

			fprintf(stderr, "qname: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->qname, -1));
			fprintf(stderr, "exp: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->domain, -1));
			res = osmo_mdns_rfc_qname_decode(ctx, t->qname, qname_max_len);
			fprintf(stderr, "res: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), res, -1));
			if (t->domain == res || (t->domain && res && strcmp(t->domain, res) == 0))
				fprintf(stderr, "=> OK\n");
			else
				fprintf(stderr, "=> ERROR\n");
			if (res)
				talloc_free(res);
			fprintf(stderr, "\n");
		}
	}
}

#define PRINT_HDR(hdr, name) \
	fprintf(stderr, "header %s:\n" \
	       ".id = %i\n" \
	       ".qr = %i\n" \
	       ".opcode = %x\n" \
	       ".aa = %i\n" \
	       ".tc = %i\n" \
	       ".rd = %i\n" \
	       ".ra = %i\n" \
	       ".z = %x\n" \
	       ".rcode = %x\n" \
	       ".qdcount = %u\n" \
	       ".ancount = %u\n" \
	       ".nscount = %u\n" \
	       ".arcount = %u\n", \
	       name, hdr.id, hdr.qr, hdr.opcode, hdr.aa, hdr.tc, hdr.rd, hdr.ra, hdr.z, hdr.rcode, hdr.qdcount, \
	       hdr.ancount, hdr.nscount, hdr.arcount)

static const struct osmo_mdns_rfc_header header_enc_dec_test_data[] = {
	{
		/* Typical use case for mslookup */
		.id = 1337,
		.qdcount = 1,
	},
	{
		/* Fill out everything */
		.id = 42,
		.qr = 1,
		.opcode = 0x02,
		.aa = 1,
		.tc = 1,
		.rd = 1,
		.ra = 1,
		.z  = 0x02,
		.rcode = 0x03,
		.qdcount = 1234,
		.ancount = 1111,
		.nscount = 2222,
		.arcount = 3333,
	},
};

void test_enc_dec_rfc_header(void)
{
	int i;

	fprintf(stderr, "-- %s --\n", __func__);
	for (i = 0; i< ARRAY_SIZE(header_enc_dec_test_data); i++) {
		const struct osmo_mdns_rfc_header in = header_enc_dec_test_data[i];
		struct osmo_mdns_rfc_header out = {0};
		struct msgb *msg = msgb_alloc(4096, "dns_test");

		PRINT_HDR(in, "in");
		osmo_mdns_rfc_header_encode(msg, &in);
		fprintf(stderr, "encoded: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		assert(osmo_mdns_rfc_header_decode(msgb_data(msg), msgb_length(msg), &out) == 0);
		PRINT_HDR(out, "out");

		fprintf(stderr, "in (hexdump):  %s\n", osmo_hexdump((unsigned char *)&in, sizeof(in)));
		fprintf(stderr, "out (hexdump): %s\n", osmo_hexdump((unsigned char *)&out, sizeof(out)));
		assert(memcmp(&in, &out, sizeof(in)) == 0);

		fprintf(stderr, "=> OK\n\n");
		msgb_free(msg);
	}
}

void test_enc_dec_rfc_header_einval(void)
{
	struct osmo_mdns_rfc_header out = {0};
	struct msgb *msg = msgb_alloc(4096, "dns_test");
	fprintf(stderr, "-- %s --\n", __func__);

	assert(osmo_mdns_rfc_header_decode(msgb_data(msg), 11, &out) == -EINVAL);
	fprintf(stderr, "=> OK\n\n");

	msgb_free(msg);
}

#define PRINT_QST(qst, name) \
	fprintf(stderr, "question %s:\n" \
	       ".domain = %s\n" \
	       ".qtype = %i\n" \
	       ".qclass = %i\n", \
	       name, (qst)->domain, (qst)->qtype, (qst)->qclass)

static const struct osmo_mdns_rfc_question question_enc_dec_test_data[] = {
	{
		.domain = "hlr.1234567.imsi",
		.qtype = OSMO_MDNS_RFC_RECORD_TYPE_ALL,
		.qclass = OSMO_MDNS_RFC_CLASS_IN,
	},
	{
		.domain = "hlr.1234567.imsi",
		.qtype = OSMO_MDNS_RFC_RECORD_TYPE_A,
		.qclass = OSMO_MDNS_RFC_CLASS_ALL,
	},
	{
		.domain = "hlr.1234567.imsi",
		.qtype = OSMO_MDNS_RFC_RECORD_TYPE_AAAA,
		.qclass = OSMO_MDNS_RFC_CLASS_ALL,
	},
};

void test_enc_dec_rfc_question(void *ctx)
{
	int i;

	fprintf(stderr, "-- %s --\n", __func__);
	for (i = 0; i< ARRAY_SIZE(question_enc_dec_test_data); i++) {
		const struct osmo_mdns_rfc_question in = question_enc_dec_test_data[i];
		struct osmo_mdns_rfc_question *out;
		struct msgb *msg = msgb_alloc(4096, "dns_test");

		PRINT_QST(&in, "in");
		assert(osmo_mdns_rfc_question_encode(ctx, msg, &in) == 0);
		fprintf(stderr, "encoded: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		out = osmo_mdns_rfc_question_decode(ctx, msgb_data(msg), msgb_length(msg));
		assert(out);
		PRINT_QST(out, "out");

		if (strcmp(in.domain, out->domain) != 0)
			fprintf(stderr, "=> ERROR: domain does not match\n");
		else if (in.qtype != out->qtype)
			fprintf(stderr, "=> ERROR: qtype does not match\n");
		else if (in.qclass != out->qclass)
			fprintf(stderr, "=> ERROR: qclass does not match\n");
		else
			fprintf(stderr, "=> OK\n");

		fprintf(stderr, "\n");
		msgb_free(msg);
		talloc_free(out);
	}
}

void test_enc_dec_rfc_question_null(void *ctx)
{
	uint8_t data[5] = {0};

	fprintf(stderr, "-- %s --\n", __func__);
	assert(osmo_mdns_rfc_question_decode(ctx, data, sizeof(data)) == NULL);
	fprintf(stderr, "=> OK\n\n");
}

#define PRINT_REC(rec, name) \
	fprintf(stderr, "question %s:\n" \
	       ".domain = %s\n" \
	       ".type = %i\n" \
	       ".class = %i\n" \
	       ".ttl = %i\n" \
	       ".rdlength = %i\n" \
	       ".rdata = %s\n", \
	       name, (rec)->domain, (rec)->type, (rec)->class, (rec)->ttl, (rec)->rdlength, \
	       osmo_quote_str((char *)(rec)->rdata, (rec)->rdlength))

static const struct osmo_mdns_rfc_record record_enc_dec_test_data[] = {
	{
		.domain = "hlr.1234567.imsi",
		.type = OSMO_MDNS_RFC_RECORD_TYPE_A,
		.class = OSMO_MDNS_RFC_CLASS_IN,
		.ttl = 1234,
		.rdlength = 9,
		.rdata = (uint8_t *)"10.42.2.1",
	},
};

void test_enc_dec_rfc_record(void *ctx)
{
	int i;

	fprintf(stderr, "-- %s --\n", __func__);
	for (i=0; i< ARRAY_SIZE(record_enc_dec_test_data); i++) {
		const struct osmo_mdns_rfc_record in = record_enc_dec_test_data[i];
		struct osmo_mdns_rfc_record *out;
		struct msgb *msg = msgb_alloc(4096, "dns_test");
		size_t record_len;

		PRINT_REC(&in, "in");
		assert(osmo_mdns_rfc_record_encode(ctx, msg, &in) == 0);
		fprintf(stderr, "encoded: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		out = osmo_mdns_rfc_record_decode(ctx, msgb_data(msg), msgb_length(msg), &record_len);
		fprintf(stderr, "record_len: %lu\n", record_len);
		assert(out);
		PRINT_REC(out, "out");

		if (strcmp(in.domain, out->domain) != 0)
			fprintf(stderr, "=> ERROR: domain does not match\n");
		else if (in.type != out->type)
			fprintf(stderr, "=> ERROR: type does not match\n");
		else if (in.class != out->class)
			fprintf(stderr, "=> ERROR: class does not match\n");
		else if (in.ttl != out->ttl)
			fprintf(stderr, "=> ERROR: ttl does not match\n");
		else if (in.rdlength != out->rdlength)
			fprintf(stderr, "=> ERROR: rdlength does not match\n");
		else if (memcmp(in.rdata, out->rdata, in.rdlength) != 0)
			fprintf(stderr, "=> ERROR: rdata does not match\n");
		else
			fprintf(stderr, "=> OK\n");

		fprintf(stderr, "\n");
		msgb_free(msg);
		talloc_free(out);
	}
}

static uint8_t ip_v4_n[] = {23, 42, 47, 11};
static uint8_t ip_v6_n[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};


enum test_records {
	RECORD_NONE,
	RECORD_A,
	RECORD_AAAA,
	RECORD_TXT_AGE,
	RECORD_TXT_PORT_444,
	RECORD_TXT_PORT_666,
	RECORD_TXT_INVALID_KEY,
	RECORD_TXT_INVALID_NO_KEY_VALUE,
	RECORD_INVALID,
};
struct result_from_answer_test {
	const char *desc;
	const enum test_records records[5];
	bool error;
	const struct osmo_mslookup_result res;
};

static void test_result_from_answer(void *ctx)
{
	void *print_ctx = talloc_named_const(ctx, 0, __func__);
	struct osmo_sockaddr_str test_host_v4 = {.af = AF_INET, .port=444, .ip = "23.42.47.11"};
	struct osmo_sockaddr_str test_host_v6 = {.af = AF_INET6, .port=666,
						 .ip = "1122:3344:5566:7788:99aa:bbcc:ddee:ff00"};
	struct osmo_mslookup_result test_result_v4 = {.rc = OSMO_MSLOOKUP_RC_RESULT, .age = 3,
						      .host_v4 = test_host_v4};
	struct osmo_mslookup_result test_result_v6 = {.rc = OSMO_MSLOOKUP_RC_RESULT, .age = 3,
						      .host_v6 = test_host_v6};
	struct osmo_mslookup_result test_result_v4_v6 = {.rc = OSMO_MSLOOKUP_RC_RESULT, .age = 3,
							 .host_v4 = test_host_v4, .host_v6 = test_host_v6};
	struct result_from_answer_test result_from_answer_data[] = {
		{
			.desc = "IPv4",
			.records = {RECORD_TXT_AGE, RECORD_A, RECORD_TXT_PORT_444},
			.res = test_result_v4
		},
		{
			.desc = "IPv6",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_PORT_666},
			.res = test_result_v6
		},
		{
			.desc = "IPv4 + IPv6",
			.records = {RECORD_TXT_AGE, RECORD_A, RECORD_TXT_PORT_444, RECORD_AAAA, RECORD_TXT_PORT_666},
			.res = test_result_v4_v6
		},
		{
			.desc = "A twice",
			.records = {RECORD_TXT_AGE, RECORD_A, RECORD_TXT_PORT_444, RECORD_A},
			.error = true
		},
		{
			.desc = "AAAA twice",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_PORT_444, RECORD_AAAA},
			.error = true
		},
		{
			.desc = "invalid TXT: no key/value pair",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_INVALID_NO_KEY_VALUE},
			.error = true
		},
		{
			.desc = "age twice",
			.records = {RECORD_TXT_AGE, RECORD_TXT_AGE},
			.error = true
		},
		{
			.desc = "port as first record",
			.records = {RECORD_TXT_PORT_444},
			.error = true
		},
		{
			.desc = "port without previous ip record",
			.records = {RECORD_TXT_AGE, RECORD_TXT_PORT_444},
			.error = true
		},
		{
			.desc = "invalid TXT: invalid key",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_INVALID_KEY},
			.error = true
		},
		{
			.desc = "unexpected record type",
			.records = {RECORD_TXT_AGE, RECORD_INVALID},
			.error = true
		},
		{
			.desc = "missing record: age",
			.records = {RECORD_A, RECORD_TXT_PORT_444},
			.error = true
		},
		{
			.desc = "missing record: port for ipv4",
			.records = {RECORD_TXT_AGE, RECORD_A},
			.error = true
		},
		{
			.desc = "missing record: port for ipv4 #2",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_PORT_666, RECORD_A},
			.error = true
		},
	};
	int i = 0;
	int j = 0;

	fprintf(stderr, "-- %s --\n", __func__);
	for (i = 0; i < ARRAY_SIZE(result_from_answer_data); i++) {
		struct result_from_answer_test *t = &result_from_answer_data[i];
		struct osmo_mdns_msg_answer ans = {0};
		struct osmo_mslookup_result res = {0};
		void *ctx_test = talloc_named_const(ctx, 0, t->desc);
		bool is_error;

		fprintf(stderr, "---\n");
		fprintf(stderr, "test: %s\n", t->desc);
		fprintf(stderr, "error: %s\n", t->error ? "true" : "false");
		fprintf(stderr, "records:\n");
		/* Build records list */
		INIT_LLIST_HEAD(&ans.records);
		for (j = 0; j < ARRAY_SIZE(t->records); j++) {
			struct osmo_mdns_record *rec = NULL;

			switch (t->records[j]) {
				case RECORD_NONE:
					break;
				case RECORD_A:
					fprintf(stderr, "- A 42.42.42.42\n");
					rec = talloc_zero(ctx_test, struct osmo_mdns_record);
					rec->type = OSMO_MDNS_RFC_RECORD_TYPE_A;
					rec->data = ip_v4_n;
					rec->length = sizeof(ip_v4_n);
					break;
				case RECORD_AAAA:
					fprintf(stderr, "- AAAA 1122:3344:5566:7788:99aa:bbcc:ddee:ff00\n");
					rec = talloc_zero(ctx_test, struct osmo_mdns_record);
					rec->type = OSMO_MDNS_RFC_RECORD_TYPE_AAAA;
					rec->data = ip_v6_n;
					rec->length = sizeof(ip_v6_n);
					break;
				case RECORD_TXT_AGE:
					fprintf(stderr, "- TXT age=3\n");
					rec = osmo_mdns_record_txt_keyval_encode(ctx_test, "age", "3");
					break;
				case RECORD_TXT_PORT_444:
					fprintf(stderr, "- TXT port=444\n");
					rec = osmo_mdns_record_txt_keyval_encode(ctx_test, "port", "444");
					break;
				case RECORD_TXT_PORT_666:
					fprintf(stderr, "- TXT port=666\n");
					rec = osmo_mdns_record_txt_keyval_encode(ctx_test, "port", "666");
					break;
				case RECORD_TXT_INVALID_KEY:
					fprintf(stderr, "- TXT hello=world\n");
					rec = osmo_mdns_record_txt_keyval_encode(ctx_test, "hello", "world");
					break;
				case RECORD_TXT_INVALID_NO_KEY_VALUE:
					fprintf(stderr, "- TXT 12345\n");
					rec = osmo_mdns_record_txt_keyval_encode(ctx_test, "12", "45");
					rec->data[3] = '3';
					break;
				case RECORD_INVALID:
					fprintf(stderr, "- (invalid)\n");
					rec = talloc_zero(ctx, struct osmo_mdns_record);
					rec->type = OSMO_MDNS_RFC_RECORD_TYPE_UNKNOWN;
					break;
			}

			if (rec)
				llist_add_tail(&rec->list, &ans.records);
		}

		/* Verify output */
		is_error = (osmo_mdns_result_from_answer(&res, &ans) != 0);
		if (t->error != is_error) {
			fprintf(stderr, "got %s\n", is_error ? "error" : "no error");
			OSMO_ASSERT(false);
		}
		if (!t->error) {
			fprintf(stderr, "exp: %s\n", osmo_mslookup_result_name_c(print_ctx, NULL, &t->res));
			fprintf(stderr, "res: %s\n", osmo_mslookup_result_name_c(print_ctx, NULL, &res));
			OSMO_ASSERT(t->res.rc == res.rc);
			OSMO_ASSERT(!osmo_sockaddr_str_cmp(&t->res.host_v4, &res.host_v4));
			OSMO_ASSERT(!osmo_sockaddr_str_cmp(&t->res.host_v6, &res.host_v6));
			OSMO_ASSERT(t->res.age == res.age);
			OSMO_ASSERT(t->res.last == res.last);
		}

		talloc_free(ctx_test);
		fprintf(stderr, "=> OK\n");
	}
}

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);

	test_enc_dec_rfc_qname(ctx);
	test_enc_dec_rfc_header();
	test_enc_dec_rfc_header_einval();
	test_enc_dec_rfc_question(ctx);
	test_enc_dec_rfc_question_null(ctx);
	test_enc_dec_rfc_record(ctx);

	test_result_from_answer(ctx);

	return 0;
}
