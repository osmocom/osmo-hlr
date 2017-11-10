/* (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
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
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <inttypes.h>
#include <string.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>

#include "logging.h"
#include "db.h"
#include "rand.h"

struct hlr_db_tool_ctx {
	/* DB context */
	struct db_context *dbc;
};

struct hlr_db_tool_ctx *g_hlr_db_tool_ctx;

static struct {
	const char *db_file;
	bool bootstrap;
	const char *import_nitb_db;
} cmdline_opts = {
	.db_file = "hlr.db",
};

static void print_help()
{
	printf("\n");
	printf("Usage: osmo-hlr-db-tool [-l <hlr.db>] [create|import-nitb-db <nitb.db>]\n");
	printf("  -l --database db-name      The OsmoHLR database to use, default '%s'.\n",
	       cmdline_opts.db_file);
	printf("  -h --help                  This text.\n");
	printf("  -d option --debug=DMAIN:DDB:DAUC  Enable debugging.\n");
	printf("  -s --disable-color         Do not print ANSI colors in the log\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");
	printf("  -V --version               Print the version of OsmoHLR-db-tool.\n");
	printf("\n");
	printf("Commands:\n");
	printf("\n");
	printf("  create                     Create an empty OsmoHLR database.\n");
	printf("                             (All commands imply this if none exists yet.)\n");
	printf("\n");
	printf("  import-nitb-db <nitb.db>   Add OsmoNITB db's subscribers to OsmoHLR db.\n");
	printf("                             Be aware that the import is lossy, only the\n");
	printf("                             IMSI, MSISDN, nam_cs/ps and 2G auth data are set.\n");
}

static void print_version(int print_copyright)
{
	printf("OsmoHLR-db-tool version %s\n", PACKAGE_VERSION);
	if (print_copyright)
		printf("\n"
       "Copyright (C) 2017 by sysmocom - s.f.m.c. GmbH\n"
       "License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\n"
       "This is free software: you are free to change and redistribute it.\n"
       "There is NO WARRANTY, to the extent permitted by law.\n"
       "\n");
}

static void handle_options(int argc, char **argv)
{
	const char *cmd;

	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"database", 1, 0, 'l'},
			{"debug", 1, 0, 'd'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"log-level", 1, 0, 'e'},
			{"version", 0, 0, 'V' },
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hl:d:sTe:V",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case 'l':
			cmdline_opts.db_file = optarg;
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'V':
			print_version(1);
			exit(EXIT_SUCCESS);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (argc - optind <= 0) {
		fprintf(stderr, "Error: You must specify a command.\n");
		print_help();
		exit(EXIT_FAILURE);
	}

	cmd = argv[optind++];

	if (!strcmp(cmd, "create")) {
		/* Nothing to do, just run the main program to open the database without running any
		 * action, which will bootstrap all tables. */
	} else if (!strcmp(cmd, "import-nitb-db")) {
		if (argc - optind < 1) {
			fprintf(stderr, "You must specify an input db file\n");
			print_help();
			exit(EXIT_FAILURE);
		}
		cmdline_opts.import_nitb_db = argv[optind++];
	} else {
		fprintf(stderr, "Error: Unknown command `%s'\n", cmd);
		print_help();
		exit(EXIT_FAILURE);
	}
}

static void signal_hdlr(int signal)
{
	switch (signal) {
	case SIGINT:
		LOGP(DMAIN, LOGL_NOTICE, "Terminating due to SIGINT\n");
		db_close(g_hlr_db_tool_ctx->dbc);
		log_fini();
		talloc_report_full(g_hlr_db_tool_ctx, stderr);
		exit(EXIT_SUCCESS);
		break;
	case SIGUSR1:
		LOGP(DMAIN, LOGL_DEBUG, "Talloc Report due to SIGUSR1\n");
		talloc_report_full(g_hlr_db_tool_ctx, stderr);
		break;
	}
}

sqlite3 *open_nitb_db(const char *filename)
{
	int rc;
	sqlite3 *nitb_db = NULL;

	rc = sqlite3_open(filename, &nitb_db);
	if (rc != SQLITE_OK) {
		LOGP(DDB, LOGL_ERROR, "Unable to open OsmoNITB DB %s; rc = %d\n", filename, rc);
		return NULL;
	}

	return nitb_db;
}

enum nitb_stmt {
	NITB_SELECT_SUBSCR,
	NITB_SELECT_AUTH_KEYS,
};

static const char *nitb_stmt_sql[] = {
	[NITB_SELECT_SUBSCR] =
		"SELECT imsi, id, extension, authorized"
		" FROM Subscriber"
		" ORDER BY id",
	[NITB_SELECT_AUTH_KEYS] =
		"SELECT algorithm_id, a3a8_ki from authkeys"
		" WHERE subscriber_id = $subscr_id",
};

sqlite3_stmt *nitb_stmt[ARRAY_SIZE(nitb_stmt_sql)] = {};

size_t _dbd_decode_binary(const unsigned char *in, unsigned char *out);

void import_nitb_subscr_aud(sqlite3 *nitb_db, const char *imsi, int64_t nitb_id, int64_t hlr_id)
{
	int rc;
	struct db_context *dbc = g_hlr_db_tool_ctx->dbc;
	sqlite3_stmt *stmt;

	int count = 0;

	stmt = nitb_stmt[NITB_SELECT_AUTH_KEYS];
	if (!db_bind_int(stmt, NULL, nitb_id))
		return;

	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		const void *blob;
		unsigned int blob_size;
		static unsigned char buf[4096];
		static char ki[128];
		int decoded_size;
		struct sub_auth_data_str aud2g = {
			.type = OSMO_AUTH_TYPE_GSM,
			.algo = OSMO_AUTH_ALG_NONE,
			.u.gsm.ki = ki,
		};

		aud2g.algo = sqlite3_column_int(stmt, 0);

		if (count) {
			LOGP(DDB, LOGL_ERROR,
			     "Warning: subscriber has more than one auth key,"
			     " importing only the first key, for IMSI=%s\n",
			     imsi);
			break;
		}

		blob = sqlite3_column_blob(stmt, 1);
		blob_size = sqlite3_column_bytes(stmt, 1);

		if (blob_size > sizeof(buf)) {
			LOGP(DDB, LOGL_ERROR,
			     "OsmoNITB import to %s: Cannot import auth data for IMSI %s:"
			     " too large blob: %u\n",
			     dbc->fname, imsi, blob_size);
			db_remove_reset(stmt);
			continue;
		}

		decoded_size = _dbd_decode_binary(blob, buf);
		osmo_strlcpy(ki, osmo_hexdump_nospc(buf, decoded_size), sizeof(ki));

		db_subscr_update_aud_by_id(dbc, hlr_id, &aud2g);
		count ++;
	}

	if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
		LOGP(DDB, LOGL_ERROR, "OsmoNITB DB: SQL error: (%d) %s,"
		     " during stmt '%s'",
		     rc, sqlite3_errmsg(nitb_db),
		     nitb_stmt_sql[NITB_SELECT_AUTH_KEYS]);
	}

	db_remove_reset(stmt);
}

void import_nitb_subscr(sqlite3 *nitb_db, sqlite3_stmt *stmt)
{
	struct db_context *dbc = g_hlr_db_tool_ctx->dbc;
	int rc;
	struct hlr_subscriber subscr;

	int64_t nitb_id;
	int64_t imsi;
	char imsi_str[32];
	bool authorized;

	imsi = sqlite3_column_int64(stmt, 0);

	snprintf(imsi_str, sizeof(imsi_str), "%"PRId64, imsi);

	rc = db_subscr_create(dbc, imsi_str);
	if (rc < 0) {
		LOGP(DDB, LOGL_ERROR, "OsmoNITB DB import to %s: failed to create IMSI %s: %d: %s\n",
		     dbc->fname,
		     imsi_str,
		     rc,
		     strerror(-rc));
		/* on error, still attempt to continue */
	}

	nitb_id = sqlite3_column_int64(stmt, 1);
	copy_sqlite3_text_to_buf(subscr.msisdn, stmt, 2);
	authorized = sqlite3_column_int(stmt, 3) ? true : false;

	db_subscr_update_msisdn_by_imsi(dbc, imsi_str, subscr.msisdn);
	db_subscr_nam(dbc, imsi_str, authorized, true);
	db_subscr_nam(dbc, imsi_str, authorized, false);

	/* find the just created id */
	rc = db_subscr_get_by_imsi(dbc, imsi_str, &subscr);
	if (rc < 0) {
		LOGP(DDB, LOGL_ERROR, "OsmoNITB DB import to %s: created IMSI %s,"
		     " but failed to get new subscriber id: %d: %s\n",
		     dbc->fname,
		     imsi_str,
		     rc,
		     strerror(-rc));
		return;
	}

	OSMO_ASSERT(!strcmp(imsi_str, subscr.imsi));

	import_nitb_subscr_aud(nitb_db, imsi_str, nitb_id, subscr.id);
}

int import_nitb_db(void)
{
	int i;
	int ret;
	int rc;
	const char *sql;
	sqlite3_stmt *stmt;

	sqlite3 *nitb_db = open_nitb_db(cmdline_opts.import_nitb_db);

	if (!nitb_db)
		return -1;
	ret = 0;

	for (i = 0; i < ARRAY_SIZE(nitb_stmt_sql); i++) {
		sql = nitb_stmt_sql[i];
		rc = sqlite3_prepare_v2(nitb_db, sql, -1, &nitb_stmt[i], NULL);
		if (rc != SQLITE_OK) {
			LOGP(DDB, LOGL_ERROR, "OsmoNITB DB: Unable to prepare SQL statement '%s'\n", sql);
			ret = -1;
			goto out_free;
		}
	}

	stmt = nitb_stmt[NITB_SELECT_SUBSCR];

	while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
		import_nitb_subscr(nitb_db, stmt);
		/* On failure, carry on with the rest. */
	}
	if (rc != SQLITE_DONE) {
		LOGP(DDB, LOGL_ERROR, "OsmoNITB DB: SQL error: (%d) %s,"
		     " during stmt '%s'",
		     rc, sqlite3_errmsg(nitb_db),
		     nitb_stmt_sql[NITB_SELECT_SUBSCR]);
		goto out_free;
	}

	db_remove_reset(stmt);
	sqlite3_finalize(stmt);

out_free:
	sqlite3_close(nitb_db);
	return ret;
}

int main(int argc, char **argv)
{
	int rc;
	int (*main_action)(void);
	main_action = NULL;

	g_hlr_db_tool_ctx = talloc_zero(NULL, struct hlr_db_tool_ctx);
	OSMO_ASSERT(g_hlr_db_tool_ctx);
	talloc_set_name_const(g_hlr_db_tool_ctx, "OsmoHLR-db-tool");

	rc = osmo_init_logging(&hlr_log_info);
	if (rc < 0) {
		fprintf(stderr, "Error initializing logging\n");
		exit(EXIT_FAILURE);
	}

	handle_options(argc, argv);

	if (cmdline_opts.import_nitb_db) {
		if (main_action)
			goto too_many_actions;
		main_action = import_nitb_db;
	}
	/* Future: add more main_actions, besides import-nitb-db, here.
	 * For command 'create', no action is required. */

	/* Just in case any db actions need randomness */
	rc = rand_init();
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL, "Error initializing random source\n");
		exit(EXIT_FAILURE);
	}

	g_hlr_db_tool_ctx->dbc = db_open(g_hlr_db_tool_ctx, cmdline_opts.db_file);
	if (!g_hlr_db_tool_ctx->dbc) {
		LOGP(DMAIN, LOGL_FATAL, "Error opening database\n");
		exit(EXIT_FAILURE);
	}

	osmo_init_ignore_signals();
	signal(SIGINT, &signal_hdlr);
	signal(SIGUSR1, &signal_hdlr);

	rc = 0;
	if (main_action)
		rc = (*main_action)();

	db_close(g_hlr_db_tool_ctx->dbc);
	log_fini();
	exit(rc ? EXIT_FAILURE : EXIT_SUCCESS);

too_many_actions:
	fprintf(stderr, "Too many actions requested.\n");
	log_fini();
	exit(EXIT_FAILURE);
}

/* stubs */
void lu_op_alloc_conn(void) { OSMO_ASSERT(0); }
void lu_op_tx_del_subscr_data(void) { OSMO_ASSERT(0); }
void lu_op_free(void) { OSMO_ASSERT(0); }
