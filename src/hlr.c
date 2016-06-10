/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
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

#include <signal.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsup.h>

#include "db.h"
#include "logging.h"
#include "gsup_server.h"
#include "gsup_router.h"
#include "rand.h"

static struct db_context *g_dbc;

/***********************************************************************
 * Send Auth Info handling
 ***********************************************************************/

/* process an incoming SAI request */
static int rx_send_auth_info(struct osmo_gsup_conn *conn,
			     const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_out;
	struct msgb *msg_out;
	int rc;

	/* initialize return message structure */
	memset(&gsup_out, 0, sizeof(gsup_out));
	memcpy(&gsup_out.imsi, &gsup->imsi, sizeof(gsup_out.imsi));

	rc = db_get_auc(g_dbc, gsup->imsi, gsup_out.auth_vectors,
			ARRAY_SIZE(gsup_out.auth_vectors),
			gsup->rand, gsup->auts);
	if (rc < 0) {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR;
		gsup_out.cause = GMM_CAUSE_NET_FAIL;
	} else if (rc == 0) {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR;
		gsup_out.cause = GMM_CAUSE_IMSI_UNKNOWN;
	} else {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT;
		gsup_out.num_auth_vectors = rc;
	}

	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP AUC response");
	osmo_gsup_encode(msg_out, &gsup_out);
	return osmo_gsup_conn_send(conn, msg_out);
}

/***********************************************************************
 * LU Operation State / Structure
 ***********************************************************************/

static LLIST_HEAD(g_lu_ops);

#define CANCEL_TIMEOUT_SECS	30
#define ISD_TIMEOUT_SECS	30

enum lu_state {
	LU_S_NULL,
	LU_S_LU_RECEIVED,
	LU_S_CANCEL_SENT,
	LU_S_CANCEL_ACK_RECEIVED,
	LU_S_ISD_SENT,
	LU_S_ISD_ACK_RECEIVED,
	LU_S_COMPLETE,
};

static const struct value_string lu_state_names[] = {
	{ LU_S_NULL,			"NULL" },
	{ LU_S_LU_RECEIVED,		"LU RECEIVED" },
	{ LU_S_CANCEL_SENT,		"CANCEL SENT" },
	{ LU_S_CANCEL_ACK_RECEIVED,	"CANCEL-ACK RECEIVED" },
	{ LU_S_ISD_SENT,		"ISD SENT" },
	{ LU_S_ISD_ACK_RECEIVED,	"ISD-ACK RECEIVED" },
	{ LU_S_COMPLETE,		"COMPLETE" },
	{ 0, NULL }
};

struct lu_operation {
	/*! entry in global list of location update operations */
	struct llist_head list;
	/*! to which gsup_server do we belong */
	struct osmo_gsup_server *gsup_server;
	/*! state of the location update */
	enum lu_state state;
	/*! CS (false) or PS (true) Location Update? */
	bool is_ps;
	/*! currently running timer */
	struct osmo_timer_list timer;

	/*! subscriber related to this operation */
	struct hlr_subscriber subscr;
	/*! peer VLR/SGSN starting the request */
	uint8_t *peer;
};

void lu_op_statechg(struct lu_operation *luop, enum lu_state new_state)
{
	enum lu_state old_state = luop->state;

	DEBUGP(DMAIN, "LU OP state change: %s -> ",
		get_value_string(lu_state_names, old_state));
	DEBUGPC(DMAIN, "%s\n",
		get_value_string(lu_state_names, new_state));

	luop->state = new_state;
}

struct lu_operation *lu_op_by_imsi(const char *imsi)
{
	struct lu_operation *luop;

	llist_for_each_entry(luop, &g_lu_ops, list) {
		if (!strcmp(imsi, luop->subscr.imsi))
			return luop;
	}
	return NULL;
}

/* Send a msgb to a given address using routing */
int osmo_gsup_addr_send(struct osmo_gsup_server *gs,
			const uint8_t *addr, size_t addrlen,
			struct msgb *msg)
{
	struct osmo_gsup_conn *conn;

	conn = gsup_route_find(gs, addr, addrlen);
	if (!conn) {
		DEBUGP(DMAIN, "Cannot find route for addr %s\n", addr);
		msgb_free(msg);
		return -ENODEV;
	}

	return osmo_gsup_conn_send(conn, msg);
}

/* Transmit a given GSUP message for the given LU operation */
static void _luop_tx_gsup(struct lu_operation *luop,
			  const struct osmo_gsup_message *gsup)
{
	struct msgb *msg_out;

	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP LUOP");
	osmo_gsup_encode(msg_out, gsup);

	osmo_gsup_addr_send(luop->gsup_server, luop->peer,
			    talloc_total_size(luop->peer),
			    msg_out);
}

/*! Transmit UPD_LOC_ERROR and destroy lu_operation */
void lu_op_tx_error(struct lu_operation *luop, enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup;

	DEBUGP(DMAIN, "%s: LU OP Tx Error (cause=%u)\n",
		luop->subscr.imsi, cause);

	memset(&gsup, 0, sizeof(gsup));
	gsup.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR;
	strncpy(&gsup.imsi, luop->subscr.imsi, sizeof(gsup.imsi));
	gsup.imsi[sizeof(gsup.imsi)-1] = '\0';
	gsup.cause = cause;

	_luop_tx_gsup(luop, &gsup);

	llist_del(&luop->list);
	talloc_free(luop);
}

/* timer call-back in case LU operation doesn't receive an response */
static void lu_op_timer_cb(void *data)
{
	struct lu_operation *luop = data;

	DEBUGP(DMAIN, "LU OP timer expired in state %s\n",
		get_value_string(lu_state_names, luop->state));

	switch (luop->state) {
	case LU_S_CANCEL_SENT:
		break;
	case LU_S_ISD_SENT:
		break;
	default:
		break;
	}

	lu_op_tx_error(luop, GMM_CAUSE_NET_FAIL);
}

/*! Transmit UPD_LOC_RESULT and destroy lu_operation */
void lu_op_tx_ack(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	memset(&gsup, 0, sizeof(gsup));
	gsup.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT;
	strncpy(gsup.imsi, luop->subscr.imsi, sizeof(gsup.imsi)-1);
	//FIXME gsup.hlr_enc;

	_luop_tx_gsup(luop, &gsup);

	llist_del(&luop->list);
	talloc_free(luop);
}

/*! Send Cancel Location to old VLR/SGSN */
void lu_op_tx_cancel_old(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	OSMO_ASSERT(luop->state == LU_S_LU_RECEIVED);

	memset(&gsup, 0, sizeof(gsup));
	gsup.message_type = OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST;
	//gsup.cause = FIXME;
	//gsup.cancel_type = FIXME;

	_luop_tx_gsup(luop, &gsup);

	lu_op_statechg(luop, LU_S_CANCEL_SENT);
	osmo_timer_schedule(&luop->timer, CANCEL_TIMEOUT_SECS, 0);
}

/*! Receive Cancel Location Result from old VLR/SGSN */
void lu_op_rx_cancel_old_ack(struct lu_operation *luop,
			    const struct osmo_gsup_message *gsup)
{
	OSMO_ASSERT(luop->state == LU_S_CANCEL_SENT);
	/* FIXME: Check for spoofing */

	osmo_timer_del(&luop->timer);

	/* FIXME */

	lu_op_tx_insert_subscr_data(luop);
}

/*! Transmit Insert Subscriber Data to new VLR/SGSN */
void lu_op_tx_insert_subscr_data(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	OSMO_ASSERT(luop->state == LU_S_LU_RECEIVED ||
		    luop->state == LU_S_CANCEL_ACK_RECEIVED);

	memset(&gsup, 0, sizeof(gsup));
	gsup.message_type = OSMO_GSUP_MSGT_INSERT_DATA_REQUEST;
	strncpy(gsup.imsi, luop->subscr.imsi, sizeof(gsup.imsi)-1);
	/* FIXME: deal with encoding the following data */
	gsup.msisdn_enc;
	gsup.hlr_enc;

	if (luop->is_ps) {
		/* FIXME: PDP infos */
	}

	/* Send ISD to new VLR/SGSN */
	_luop_tx_gsup(luop, &gsup);

	lu_op_statechg(luop, LU_S_ISD_SENT);
	osmo_timer_schedule(&luop->timer, ISD_TIMEOUT_SECS, 0);
}

/*! Receive Insert Subscriber Data Result from new VLR/SGSN */
static void lu_op_rx_insert_subscr_data_ack(struct lu_operation *luop,
				    const struct osmo_gsup_message *gsup)
{
	OSMO_ASSERT(luop->state == LU_S_ISD_SENT);
	/* FIXME: Check for spoofing */

	osmo_timer_del(&luop->timer);

	/* Subscriber_Present_HLR */
	/* CS only: Check_SS_required? -> MAP-FW-CHECK_SS_IND.req */

	/* Send final ACK towards inquiring VLR/SGSN */
	lu_op_tx_ack(luop);
}

/*! Receive GSUP message for given \ref lu_operation */
void lu_op_rx_gsup(struct lu_operation *luop,
		  const struct osmo_gsup_message *gsup)
{
	switch (gsup->message_type) {
	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
		/* FIXME */
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
		lu_op_rx_insert_subscr_data_ack(luop, gsup);
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR:
		/* FIXME */
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT:
		lu_op_rx_cancel_old_ack(luop, gsup);
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR, "Unhandled GSUP msg_type 0x%02x\n",
			gsup->message_type);
		break;
	}
}

static struct lu_operation *lu_op_alloc(struct osmo_gsup_server *srv)
{
	struct lu_operation *luop;

	luop = talloc_zero(srv, struct lu_operation);
	OSMO_ASSERT(luop);
	luop->gsup_server = srv;
	luop->timer.cb = lu_op_timer_cb;
	luop->timer.data = luop;

	return luop;
}

/*! Receive Update Location Request, creates new \ref lu_operation */
static int rx_upd_loc_req(struct osmo_gsup_conn *conn,
			  const struct osmo_gsup_message *gsup)
{
	int rc;
	struct lu_operation *luop;
	struct hlr_subscriber *subscr;
	uint8_t *peer_addr;

	rc = osmo_gsup_conn_ccm_get(conn, &peer_addr, IPAC_IDTAG_SERNR);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "LU REQ from conn without addr?\n");
		return rc;
	}

	luop = lu_op_alloc(conn->server);
	luop->peer = talloc_memdup(luop, peer_addr, rc);
	lu_op_statechg(luop, LU_S_LU_RECEIVED);
	subscr = &luop->subscr;
	if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS)
		luop->is_ps = true;
	llist_add(&luop->list, &g_lu_ops);

	/* Roughly follwing "Process Update_Location_HLR" of TS 09.02 */

	/* check if subscriber is known at all */
	rc = db_subscr_get(g_dbc, gsup->imsi, subscr);
	if (rc < 0) {
		/* Send Error back: Subscriber Unknown in HLR */
		strcpy(luop->subscr.imsi, gsup->imsi);
		lu_op_tx_error(luop, GMM_CAUSE_IMSI_UNKNOWN);
		return 0;
	}

	/* Check if subscriber is generally permitted on CS or PS
	 * service (as requested) */
	if (!luop->is_ps && !subscr->nam_cs) {
		lu_op_tx_error(luop, GMM_CAUSE_PLMN_NOTALLOWED);
		return 0;
	} else if (luop->is_ps && !subscr->nam_ps) {
		lu_op_tx_error(luop, GMM_CAUSE_GPRS_NOTALLOWED);
		return 0;
	}

	/* TODO: Set subscriber tracing = deactive in VLR/SGSN */

#if 0
	/* Cancel in old VLR/SGSN, if new VLR/SGSN differs from old */
	if (luop->is_ps == false &&
	    strcmp(subscr->vlr_number, vlr_number)) {
		lu_op_tx_cancel_old(luop);
	} else if (luop->is_ps == true &&
		   strcmp(subscr->sgsn_number, sgsn_number)) {
		lu_op_tx_cancel_old(luop);
	} else
#endif
	{
		/* TODO: Subscriber allowed to roam in PLMN? */
		/* TODO: Update RoutingInfo */
		/* TODO: Reset Flag MS Purged (cs/ps) */
		/* TODO: Control_Tracing_HLR / Control_Tracing_HLR_with_SGSN */
		lu_op_tx_insert_subscr_data(luop);
	}
	return 0;
}

static int rx_purge_ms_req(struct osmo_gsup_conn *conn,
			   const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};
	struct msgb *msg_out;
	bool is_ps = false;
	int rc;

	LOGP(DAUC, LOGL_INFO, "%s: Purge MS (%s)\n", gsup->imsi,
		is_ps ? "PS" : "CS");

	memcpy(gsup_reply.imsi, gsup->imsi, sizeof(gsup_reply.imsi));

	if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS)
		is_ps = true;

	/* FIXME: check if the VLR that sends the purge is the same that
	 * we have on record. Only update if yes */

	/* Perform the actual update of the DB */
	rc = db_subscr_purge(g_dbc, gsup->imsi, is_ps);

	if (rc == 1)
		gsup_reply.message_type = OSMO_GSUP_MSGT_PURGE_MS_RESULT;
	else if (rc == 0) {
		gsup_reply.message_type = OSMO_GSUP_MSGT_PURGE_MS_ERROR;
		gsup_reply.cause = GMM_CAUSE_IMSI_UNKNOWN;
	} else {
		gsup_reply.message_type = OSMO_GSUP_MSGT_PURGE_MS_ERROR;
		gsup_reply.cause = GMM_CAUSE_NET_FAIL;
	}

	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP AUC response");
	osmo_gsup_encode(msg_out, &gsup_reply);
	return osmo_gsup_conn_send(conn, msg_out);
}

static int read_cb(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	static struct osmo_gsup_message gsup;
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
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
		rx_upd_loc_req(conn, &gsup);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_REQUEST:
		rx_purge_ms_req(conn, &gsup);
		break;
	/* responses to requests sent by us */
	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT:
		{
			struct lu_operation *luop = lu_op_by_imsi(gsup.imsi);
			if (!luop) {
				LOGP(DMAIN, LOGL_ERROR, "GSUP message %u for "
					"unknown IMSI %s\n", gsup.message_type,
					gsup.imsi);
				break;
			}
			lu_op_rx_gsup(luop, &gsup);
		}
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
