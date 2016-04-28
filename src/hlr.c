#include <signal.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsup.h>

#include "db.h"
#include "logging.h"
#include "gsup_server.h"
#include "rand.h"

static struct db_context *g_dbc;

/* process an incoming SAI request */
static int rx_send_auth_info(struct osmo_gsup_conn *conn,
			     const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_out;
	struct msgb *msg_out;
	int rc;

	/* initialize return message structure */
	memset(&gsup_out, 0, sizeof(gsup_out));
	gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT;
	memcpy(&gsup_out.imsi, &gsup->imsi, sizeof(gsup_out.imsi));

	rc = db_get_auc(g_dbc, gsup->imsi, gsup_out.auth_vectors,
			ARRAY_SIZE(gsup_out.auth_vectors),
			NULL /* gsup->rand_auts */, gsup->auts);
	if (rc <= 0) {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR;
	}

	msg_out = msgb_alloc(1024, "GSUP response");
	osmo_gsup_encode(msg_out, &gsup_out);
	return osmo_gsup_conn_send(conn, msg_out);
}

static int read_cb(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	static struct osmo_gsup_message gsup;
	int rc;

	rc = osmo_gsup_decode(msgb_l3(msg), msgb_l3len(msg), &gsup);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "error in GSUP decode: %d\n", rc);
		return rc;
	}

	switch (gsup.message_type) {
	/* requests sent to us */
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST:
		rx_send_auth_info(conn, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		break;
	/* responses to requests sent by us */
	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
		break;
	default:
		LOGP(DMAIN, LOGL_DEBUG, "Unhandled GSUP message type %u\n",
			gsup.message_type);
		break;
	}
	msgb_free(msg);
	return 0;
}

static struct osmo_gsup_server *gs;

static void signal_hdlr(int signal)
{
	switch (signal) {
	case SIGINT:
		LOGP(DMAIN, LOGL_NOTICE, "Terminating due to SIGINT\n");
		osmo_gsup_server_destroy(gs);
		db_close(g_dbc);
		log_fini();
		exit(0);
		break;
	case SIGUSR1:
		LOGP(DMAIN, LOGL_DEBUG, "Talloc Report due to SIGUSR1\n");
		talloc_report_full(NULL, stderr);
		break;
	}
}

int main(int argc, char **argv)
{
	int rc;

	talloc_enable_leak_report_full();

	rc = osmo_init_logging(&hlr_log_info);
	if (rc < 0) {
		fprintf(stderr, "Error initializing logging\n");
		exit(1);
	}
	LOGP(DMAIN, LOGL_NOTICE, "hlr starting\n");

	rc = rand_init();
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL, "Error initializing random source\n");
		exit(1);
	}

	g_dbc = db_open(NULL, "hlr.db");
	if (!g_dbc) {
		LOGP(DMAIN, LOGL_FATAL, "Error opening database\n");
		exit(1);
	}

	gs = osmo_gsup_server_create(NULL, NULL, 2222, read_cb);
	if (!gs) {
		LOGP(DMAIN, LOGL_FATAL, "Error starting GSUP server\n");
		exit(1);
	}

	osmo_init_ignore_signals();
	signal(SIGINT, &signal_hdlr);
	signal(SIGUSR1, &signal_hdlr);

	//osmo_daemonize();

	while (1) {
		osmo_select_main(0);
	}

	db_close(g_dbc);

	log_fini();

	exit(0);
}
