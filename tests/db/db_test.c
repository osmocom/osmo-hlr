/* (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include "db.h"
#include "logging.h"

#define comment_start() fprintf(stderr, "\n===== %s\n", __func__);
#define comment(fmt, args...) fprintf(stderr, "\n--- " fmt "\n\n", ## args);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

/* Perform a function call and verbosely assert that its return value is as expected.
 * The return code is then available in g_rc. */
#define ASSERT_RC(call, expect_rc) \
	do { \
		fprintf(stderr, #call " --> " #expect_rc "\n"); \
		g_rc = call; \
		if (g_rc != (expect_rc)) \
			fprintf(stderr, " MISMATCH: got rc = %d, expected: " \
                                        #expect_rc " = %d\n", g_rc, expect_rc); \
		OSMO_ASSERT(g_rc == (expect_rc)); \
		fprintf(stderr, "\n"); \
	} while (0)

/* Do db_subscr_get_by_xxxx and verbosely assert that its return value is as expected.
 * Print the subscriber struct to stderr to be validated by db_test.err.
 * The result is then available in g_subscr. */
#define ASSERT_SEL(by, val, expect_rc) \
	do { \
		int rc; \
		g_subscr = (struct hlr_subscriber){}; \
		fprintf(stderr, "db_subscr_get_by_" #by "(dbc, " #val ", &g_subscr) --> " \
                                #expect_rc "\n"); \
		rc = db_subscr_get_by_##by(dbc, val, &g_subscr); \
		if (rc != (expect_rc)) \
			fprintf(stderr, " MISMATCH: got rc = %d, expected: " \
                                        #expect_rc " = %d\n", rc, expect_rc); \
		OSMO_ASSERT(rc == (expect_rc)); \
		if (!rc) \
			dump_subscr(&g_subscr); \
		fprintf(stderr, "\n"); \
	} while (0)

static struct db_context *dbc = NULL;
static void *ctx = NULL;
static struct hlr_subscriber g_subscr;
static int g_rc;
static int64_t g_id;

#define Pfv(name, fmt, val) \
	fprintf(stderr, "  ." #name " = " fmt ",\n", val)
#define Pfo(name, fmt, obj) \
	Pfv(name, fmt, obj->name)

/* Print a subscriber struct to stderr to be validated by db_test.err. */
void dump_subscr(struct hlr_subscriber *subscr)
{
#define Ps(name) \
	if (*subscr->name) \
		Pfo(name, "'%s'", subscr)
#define Pd(name) \
	Pfv(name, "%"PRId64, (int64_t)subscr->name)
#define Pd_nonzero(name) \
	if (subscr->name) \
		Pd(name)
#define Pb(if_val, name) \
	if (subscr->name == (if_val)) \
		Pfv(name, "%s", subscr->name ? "true" : "false")

	fprintf(stderr, "struct hlr_subscriber {\n");
	Pd(id);
	Ps(imsi);
	Ps(msisdn);
	Ps(vlr_number);
	Ps(sgsn_number);
	Ps(sgsn_address);
	Pd_nonzero(periodic_lu_timer);
	Pd_nonzero(periodic_rau_tau_timer);
	Pb(false, nam_cs);
	Pb(false, nam_ps);
	if (subscr->lmsi)
		Pfo(lmsi, "0x%x", subscr);
	Pb(true, ms_purged_cs);
	Pb(true, ms_purged_ps);
	fprintf(stderr, "}\n");
#undef Ps
#undef Pd
#undef Pd_nonzero
#undef Pb
}

void dump_aud(const char *label, struct osmo_sub_auth_data *aud)
{
	if (aud->type == OSMO_AUTH_TYPE_NONE) {
		fprintf(stderr, "%s: none\n", label);
		return;
	}

	fprintf(stderr, "%s: struct osmo_sub_auth_data {\n", label);
#define Pf(name, fmt) \
	Pfo(name, fmt, aud)
#define Phex(name) \
	Pfv(name, "'%s'", osmo_hexdump_nospc(aud->name, sizeof(aud->name)))

	Pfv(type, "%s", osmo_sub_auth_type_name(aud->type));
	Pfv(algo, "%s", osmo_auth_alg_name(aud->algo));
	switch (aud->type) {
	case OSMO_AUTH_TYPE_GSM:
		Phex(u.gsm.ki);
		break;
	case OSMO_AUTH_TYPE_UMTS:
		Phex(u.umts.opc);
		Pf(u.umts.opc_is_op, "%u");
		Phex(u.umts.k);
		Phex(u.umts.amf);
		if (aud->u.umts.sqn) {
			Pf(u.umts.sqn, "%"PRIu64);
			Pf(u.umts.sqn, "0x%"PRIx64);
		}
		if (aud->u.umts.ind_bitlen)
			Pf(u.umts.ind_bitlen, "%u");
		break;
	default:
		OSMO_ASSERT(false);
	}

	fprintf(stderr, "}\n");

#undef Pf
#undef Phex
}

static const char *imsi0 = "123456789000000";
static const char *imsi1 = "123456789000001";
static const char *imsi2 = "123456789000002";
static const char *short_imsi = "123456";
static const char *unknown_imsi = "999999999";

static void test_subscr_create_update_sel_delete()
{
	int64_t id0, id1, id2, id_short;
	comment_start();

	comment("Create with valid / invalid IMSI");

	ASSERT_RC(db_subscr_create(dbc, imsi0), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	id0 = g_subscr.id;
	ASSERT_RC(db_subscr_create(dbc, imsi1), 0);
	ASSERT_SEL(imsi, imsi1, 0);
	id1 = g_subscr.id;
	ASSERT_RC(db_subscr_create(dbc, imsi2), 0);
	ASSERT_SEL(imsi, imsi2, 0);
	id2 = g_subscr.id;
	ASSERT_RC(db_subscr_create(dbc, imsi0), -EIO);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_create(dbc, imsi1), -EIO);
	ASSERT_RC(db_subscr_create(dbc, imsi1), -EIO);
	ASSERT_SEL(imsi, imsi1, 0);
	ASSERT_RC(db_subscr_create(dbc, imsi2), -EIO);
	ASSERT_RC(db_subscr_create(dbc, imsi2), -EIO);
	ASSERT_SEL(imsi, imsi2, 0);

	ASSERT_RC(db_subscr_create(dbc, "123456789 000003"), -EINVAL);
	ASSERT_SEL(imsi, "123456789000003", -ENOENT);

	ASSERT_RC(db_subscr_create(dbc, "123456789000002123456"), -EINVAL);
	ASSERT_SEL(imsi, "123456789000002123456", -ENOENT);

	ASSERT_RC(db_subscr_create(dbc, "foobar123"), -EINVAL);
	ASSERT_SEL(imsi, "foobar123", -ENOENT);

	ASSERT_RC(db_subscr_create(dbc, "123"), -EINVAL);
	ASSERT_SEL(imsi, "123", -ENOENT);

	ASSERT_RC(db_subscr_create(dbc, short_imsi), 0);
	ASSERT_SEL(imsi, short_imsi, 0);
	id_short = g_subscr.id;


	comment("Set valid / invalid MSISDN");

	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, imsi0, "54321"), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_SEL(msisdn, "54321", 0);
	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, imsi0,
					  "54321012345678912345678"), -EINVAL);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_SEL(msisdn, "54321", 0);
	ASSERT_SEL(msisdn, "54321012345678912345678", -ENOENT);
	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, imsi0,
					  "543 21"), -EINVAL);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_SEL(msisdn, "543 21", -ENOENT);
	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, imsi0,
					  "foobar123"), -EINVAL);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_SEL(msisdn, "foobar123", -ENOENT);
	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, imsi0,
					  "5"), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_SEL(msisdn, "5", 0);
	ASSERT_SEL(msisdn, "54321", -ENOENT);
	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, imsi0,
					  "543210123456789"), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_SEL(msisdn, "543210123456789", 0);
	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, imsi0,
					  "5432101234567891"), -EINVAL);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_SEL(msisdn, "5432101234567891", -ENOENT);

	comment("Set MSISDN on non-existent / invalid IMSI");

	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, unknown_imsi, "99"), -ENOENT);
	ASSERT_SEL(msisdn, "99", -ENOENT);

	ASSERT_RC(db_subscr_update_msisdn_by_imsi(dbc, "foobar", "99"), -ENOENT);
	ASSERT_SEL(msisdn, "99", -ENOENT);

	comment("Set / unset nam_cs and nam_ps");

	/*                                nam_val, is_ps */
	ASSERT_RC(db_subscr_nam(dbc, imsi0, false, true), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, false, false), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, true, false), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, true, true), 0);
	ASSERT_SEL(imsi, imsi0, 0);

	comment("Set / unset nam_cs and nam_ps *again*");
	ASSERT_RC(db_subscr_nam(dbc, imsi0, false, true), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, false, true), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, false, false), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, false, false), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, true, true), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, true, true), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, true, false), 0);
	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_nam(dbc, imsi0, true, false), 0);
	ASSERT_SEL(imsi, imsi0, 0);

	comment("Set nam_cs and nam_ps on non-existent / invalid IMSI");

	ASSERT_RC(db_subscr_nam(dbc, unknown_imsi, false, true), -ENOENT);
	ASSERT_RC(db_subscr_nam(dbc, unknown_imsi, false, false), -ENOENT);
	ASSERT_SEL(imsi, unknown_imsi, -ENOENT);

	ASSERT_RC(db_subscr_nam(dbc, "foobar", false, true), -ENOENT);
	ASSERT_RC(db_subscr_nam(dbc, "foobar", false, false), -ENOENT);

	comment("Delete non-existent / invalid IDs");

	ASSERT_RC(db_subscr_delete_by_id(dbc, 999), -ENOENT);
	ASSERT_RC(db_subscr_delete_by_id(dbc, -10), -ENOENT);

	comment("Delete subscribers");

	ASSERT_SEL(imsi, imsi0, 0);
	ASSERT_RC(db_subscr_delete_by_id(dbc, id0), 0);
	ASSERT_SEL(imsi, imsi0, -ENOENT);
	ASSERT_RC(db_subscr_delete_by_id(dbc, id0), -ENOENT);

	ASSERT_SEL(imsi, imsi1, 0);
	ASSERT_RC(db_subscr_delete_by_id(dbc, id1), 0);
	ASSERT_SEL(imsi, imsi1, -ENOENT);

	ASSERT_SEL(imsi, imsi2, 0);
	ASSERT_RC(db_subscr_delete_by_id(dbc, id2), 0);
	ASSERT_SEL(imsi, imsi2, -ENOENT);

	ASSERT_SEL(imsi, short_imsi, 0);
	ASSERT_RC(db_subscr_delete_by_id(dbc, id_short), 0);
	ASSERT_SEL(imsi, short_imsi, -ENOENT);

	comment_end();
}

static struct {
	bool verbose;
} cmdline_opts = {
	.verbose = false,
};

static void print_help(const char *program)
{
	printf("Usage:\n"
	       "  %s [-v] [N [N...]]\n"
	       "Options:\n"
	       "  -h --help      show this text.\n"
	       "  -v --verbose   print source file and line numbers\n",
	       program
	       );
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"verbose", 1, 0, 'v'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help(argv[0]);
			exit(0);
		case 'v':
			cmdline_opts.verbose = true;
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "too many args\n");
		exit(-1);
	}
}

int main(int argc, char **argv)
{
	printf("db_test.c\n");

	ctx = talloc_named_const(NULL, 1, "db_test");

	handle_options(argc, argv);

	osmo_init_logging(&hlr_log_info);
	log_set_print_filename(osmo_stderr_target, cmdline_opts.verbose);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	/* omit the SQLite version and compilation flags from test output */
	log_set_log_level(osmo_stderr_target, LOGL_ERROR);
	dbc = db_open(ctx, "db_test.db");
	log_set_log_level(osmo_stderr_target, 0);
	OSMO_ASSERT(dbc);

	test_subscr_create_update_sel_delete();

	printf("Done\n");
	return 0;
}

/* stubs */
int auc_compute_vectors(struct osmo_auth_vector *vec, unsigned int num_vec,
			struct osmo_sub_auth_data *aud2g,
			struct osmo_sub_auth_data *aud3g,
			const uint8_t *rand_auts, const uint8_t *auts)
{ OSMO_ASSERT(false); return -1; }
