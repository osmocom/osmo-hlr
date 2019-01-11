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
#include <stdbool.h>
#include <getopt.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm48_ie.h>

#include "db.h"
#include "hlr.h"
#include "ctrl.h"
#include "logging.h"
#include "gsup_server.h"
#include "gsup_router.h"
#include "rand.h"
#include "luop.h"
#include "hlr_vty.h"
#include "hlr_ussd.h"

struct hlr *g_hlr;
static int quit = 0;

/* Trigger 'Insert Subscriber Data' messages to all connected GSUP clients.
 *
 * \param[in] subscr  A subscriber we have new data to send for.
 */
void
osmo_hlr_subscriber_update_notify(struct hlr_subscriber *subscr)
{
        struct osmo_gsup_conn *co;

	if (g_hlr->gs == NULL) {
		LOGP(DLGSUP, LOGL_DEBUG,
		     "IMSI %s: NOT Notifying peers of subscriber data change,"
		     " there is no GSUP server\n",
		     subscr->imsi);
		return;
	}

	llist_for_each_entry(co, &g_hlr->gs->clients, list) {
		struct osmo_gsup_message gsup = { };
		uint8_t msisdn_enc[OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN];
		uint8_t apn[APN_MAXLEN];
		struct msgb *msg_out;
		uint8_t *peer;
		int peer_len;
		size_t peer_strlen;
		const char *peer_compare;
		enum osmo_gsup_cn_domain cn_domain;

		if (co->supports_ps) {
			cn_domain = OSMO_GSUP_CN_DOMAIN_PS;
			peer_compare = subscr->sgsn_number;
		} else if (co->supports_cs) {
			cn_domain = OSMO_GSUP_CN_DOMAIN_CS;
			peer_compare = subscr->vlr_number;
		} else {
			/* We have not yet received a location update from this GSUP client.*/
			continue;
		}

		peer_len = osmo_gsup_conn_ccm_get(co, &peer, IPAC_IDTAG_SERNR);
		if (peer_len < 0) {
			LOGP(DLGSUP, LOGL_ERROR,
			       "IMSI='%s': cannot get peer name for connection %s:%u\n", subscr->imsi,
			       co && co->conn && co->conn->server? co->conn->server->addr : "unset",
			       co && co->conn && co->conn->server? co->conn->server->port : 0);
			continue;
		}

		peer_strlen = strnlen((const char*)peer, peer_len);
		if (strlen(peer_compare) != peer_strlen || strncmp(peer_compare, (const char *)peer, peer_len)) {
			/* Mismatch. The subscriber is not subscribed with this GSUP client. */
			/* I hope peer is always nul terminated... */
			if (peer_strlen < peer_len)
				LOGP(DLGSUP, LOGL_DEBUG,
				     "IMSI %s: subscriber change: skipping %s peer %s\n",
				     subscr->imsi, cn_domain == OSMO_GSUP_CN_DOMAIN_PS ? "PS" : "CS",
				     osmo_quote_str((char*)peer, -1));
			continue;
		}

		LOGP(DLGSUP, LOGL_DEBUG,
		     "IMSI %s: subscriber change: notifying %s peer %s\n",
		     subscr->imsi, cn_domain == OSMO_GSUP_CN_DOMAIN_PS ? "PS" : "CS",
		     osmo_quote_str(peer_compare, -1));

		if (osmo_gsup_create_insert_subscriber_data_msg(&gsup, subscr->imsi, subscr->msisdn, msisdn_enc,
								sizeof(msisdn_enc), apn, sizeof(apn), cn_domain) != 0) {
			LOGP(DLGSUP, LOGL_ERROR,
			       "IMSI='%s': Cannot notify GSUP client; could not create gsup message "
			       "for %s:%u\n", subscr->imsi,
			       co && co->conn && co->conn->server? co->conn->server->addr : "unset",
			       co && co->conn && co->conn->server? co->conn->server->port : 0);
			continue;
		}

		/* Send ISD to MSC/SGSN */
		msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP ISD UPDATE");
		if (msg_out == NULL) {
			LOGP(DLGSUP, LOGL_ERROR,
			       "IMSI='%s': Cannot notify GSUP client; could not allocate msg buffer "
			       "for %s:%u\n", subscr->imsi,
			       co && co->conn && co->conn->server? co->conn->server->addr : "unset",
			       co && co->conn && co->conn->server? co->conn->server->port : 0);
			continue;
		}
		osmo_gsup_encode(msg_out, &gsup);

		if (osmo_gsup_addr_send(g_hlr->gs, peer, peer_len, msg_out) < 0) {
			LOGP(DMAIN, LOGL_ERROR,
			       "IMSI='%s': Cannot notify GSUP client; send operation failed "
			       "for %s:%u\n", subscr->imsi,
			       co && co->conn && co->conn->server? co->conn->server->addr : "unset",
			       co && co->conn && co->conn->server? co->conn->server->port : 0);
			continue;
		}
	}
}

/***********************************************************************
 * Send Auth Info handling
 ***********************************************************************/

/* process an incoming SAI request */
static int rx_send_auth_info(struct osmo_gsup_conn *conn,
			     const struct osmo_gsup_message *gsup,
			     struct db_context *dbc)
{
	struct osmo_gsup_message gsup_out;
	struct msgb *msg_out;
	int rc;

	/* initialize return message structure */
	memset(&gsup_out, 0, sizeof(gsup_out));
	memcpy(&gsup_out.imsi, &gsup->imsi, sizeof(gsup_out.imsi));

	rc = db_get_auc(dbc, gsup->imsi, conn->auc_3g_ind,
			gsup_out.auth_vectors,
			ARRAY_SIZE(gsup_out.auth_vectors),
			gsup->rand, gsup->auts);
	if (rc <= 0) {
		gsup_out.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR;
		switch (rc) {
		case 0:
			/* 0 means "0 tuples generated", which shouldn't happen.
			 * Treat the same as "no auth data". */
		case -ENOKEY:
			LOGP(DAUC, LOGL_NOTICE, "%s: IMSI known, but has no auth data;"
			     " Returning slightly inaccurate cause 'IMSI Unknown' via GSUP\n",
			     gsup->imsi);
			gsup_out.cause = GMM_CAUSE_IMSI_UNKNOWN;
			break;
		case -ENOENT:
			LOGP(DAUC, LOGL_NOTICE, "%s: IMSI not known\n", gsup->imsi);
			gsup_out.cause = GMM_CAUSE_IMSI_UNKNOWN;
			break;
		default:
			LOGP(DAUC, LOGL_ERROR, "%s: failure to look up IMSI in db\n", gsup->imsi);
			gsup_out.cause = GMM_CAUSE_NET_FAIL;
			break;
		}
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

/*! Receive Update Location Request, creates new \ref lu_operation */
static int rx_upd_loc_req(struct osmo_gsup_conn *conn,
			  const struct osmo_gsup_message *gsup)
{
	struct hlr_subscriber *subscr;
	struct lu_operation *luop = lu_op_alloc_conn(conn);
	if (!luop) {
		LOGP(DMAIN, LOGL_ERROR, "LU REQ from conn without addr?\n");
		return -EINVAL;
	}

	subscr = &luop->subscr;

	lu_op_statechg(luop, LU_S_LU_RECEIVED);

	switch (gsup->cn_domain) {
	case OSMO_GSUP_CN_DOMAIN_CS:
		conn->supports_cs = true;
		break;
	default:
		/* The client didn't send a CN_DOMAIN IE; assume packet-switched in
		 * accordance with the GSUP spec in osmo-hlr's user manual (section
		 * 11.6.15 "CN Domain" says "if no CN Domain IE is present within
		 * a request, the PS Domain is assumed." */
	case OSMO_GSUP_CN_DOMAIN_PS:
		conn->supports_ps = true;
		luop->is_ps = true;
		break;
	}
	llist_add(&luop->list, &g_lu_ops);

	/* Roughly follwing "Process Update_Location_HLR" of TS 09.02 */

	/* check if subscriber is known at all */
	if (!lu_op_fill_subscr(luop, g_hlr->dbc, gsup->imsi)) {
		/* Send Error back: Subscriber Unknown in HLR */
		osmo_strlcpy(luop->subscr.imsi, gsup->imsi, sizeof(luop->subscr.imsi));
		lu_op_tx_error(luop, GMM_CAUSE_IMSI_UNKNOWN);
		return 0;
	}

	/* Check if subscriber is generally permitted on CS or PS
	 * service (as requested) */
	if (!luop->is_ps && !luop->subscr.nam_cs) {
		lu_op_tx_error(luop, GMM_CAUSE_PLMN_NOTALLOWED);
		return 0;
	} else if (luop->is_ps && !luop->subscr.nam_ps) {
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

	/* Store the VLR / SGSN number with the subscriber, so we know where it was last seen. */
	LOGP(DAUC, LOGL_DEBUG, "IMSI='%s': storing %s = %s\n",
	     subscr->imsi, luop->is_ps ? "SGSN number" : "VLR number",
	     osmo_quote_str((const char*)luop->peer, -1));
	if (db_subscr_lu(g_hlr->dbc, subscr->id, (const char *)luop->peer, luop->is_ps))
		LOGP(DAUC, LOGL_ERROR, "IMSI='%s': Cannot update %s in the database\n",
		     subscr->imsi, luop->is_ps ? "SGSN number" : "VLR number");

	/* TODO: Subscriber allowed to roam in PLMN? */
	/* TODO: Update RoutingInfo */
	/* TODO: Reset Flag MS Purged (cs/ps) */
	/* TODO: Control_Tracing_HLR / Control_Tracing_HLR_with_SGSN */
	lu_op_tx_insert_subscr_data(luop);

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
	rc = db_subscr_purge(g_hlr->dbc, gsup->imsi, true, is_ps);

	if (rc == 0)
		gsup_reply.message_type = OSMO_GSUP_MSGT_PURGE_MS_RESULT;
	else if (rc == -ENOENT) {
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

static int gsup_send_err_reply(struct osmo_gsup_conn *conn, const char *imsi,
				enum osmo_gsup_message_type type_in, uint8_t err_cause)
{
	int type_err = osmo_gsup_get_err_msg_type(type_in);
	struct osmo_gsup_message gsup_reply = {0};
	struct msgb *msg_out;

	if (type_err < 0) {
		LOGP(DMAIN, LOGL_ERROR, "unable to determine error response for %s\n",
			osmo_gsup_message_type_name(type_in));
		return type_err;
	}

	OSMO_STRLCPY_ARRAY(gsup_reply.imsi, imsi);
	gsup_reply.message_type = type_err;
	gsup_reply.cause = err_cause;
	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP ERR response");
	OSMO_ASSERT(msg_out);
	osmo_gsup_encode(msg_out, &gsup_reply);
	LOGP(DMAIN, LOGL_NOTICE, "Tx %s\n", osmo_gsup_message_type_name(type_err));
	return osmo_gsup_conn_send(conn, msg_out);
}

static int rx_check_imei_req(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};
	struct msgb *msg_out;
	char imei[GSM23003_IMEI_NUM_DIGITS+1] = {0};

	/* Encoded IMEI length check */
	if (!gsup->imei_enc || gsup->imei_enc_len < 1 || gsup->imei_enc[0] >= sizeof(imei)) {
		LOGP(DMAIN, LOGL_ERROR, "%s: wrong encoded IMEI length\n", gsup->imsi);
		gsup_send_err_reply(conn, gsup->imsi, gsup->message_type, GMM_CAUSE_INV_MAND_INFO);
		return -1;
	}

	/* Decode IMEI */
	if (gsm48_decode_bcd_number(imei, sizeof(imei), gsup->imei_enc, 0) < 0) {
		LOGP(DMAIN, LOGL_ERROR, "%s: failed to decode IMEI\n", gsup->imsi);
		gsup_send_err_reply(conn, gsup->imsi, gsup->message_type, GMM_CAUSE_INV_MAND_INFO);
		return -1;
	}

	/* Save in DB if desired */
	if (g_hlr->store_imei) {
		LOGP(DAUC, LOGL_DEBUG, "IMSI='%s': storing IMEI = %s\n", gsup->imsi, imei);
		if (db_subscr_update_imei_by_imsi(g_hlr->dbc, gsup->imsi, imei) < 0) {
			gsup_send_err_reply(conn, gsup->imsi, gsup->message_type, GMM_CAUSE_INV_MAND_INFO);
			return -1;
		}
	} else {
		/* Check if subscriber exists and print IMEI */
		LOGP(DMAIN, LOGL_INFO, "IMSI='%s': has IMEI = %s (consider setting 'store-imei')\n", gsup->imsi, imei);
		struct hlr_subscriber subscr;
		if (db_subscr_get_by_imsi(g_hlr->dbc, gsup->imsi, &subscr) < 0) {
			gsup_send_err_reply(conn, gsup->imsi, gsup->message_type, GMM_CAUSE_INV_MAND_INFO);
			return -1;
		}
	}

	/* Accept all IMEIs */
	gsup_reply.imei_result = OSMO_GSUP_IMEI_RESULT_ACK;
	gsup_reply.message_type = OSMO_GSUP_MSGT_CHECK_IMEI_RESULT;
	msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP Check_IMEI response");
	memcpy(gsup_reply.imsi, gsup->imsi, sizeof(gsup_reply.imsi));
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

	/* 3GPP TS 23.003 Section 2.2 clearly states that an IMSI with less than 5
	 * digits is impossible.  Even 5 digits is a highly theoretical case */
	if (strlen(gsup.imsi) < 5)
		return gsup_send_err_reply(conn, gsup.imsi, gsup.message_type, GMM_CAUSE_INV_MAND_INFO);

	switch (gsup.message_type) {
	/* requests sent to us */
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST:
		rx_send_auth_info(conn, &gsup, g_hlr->dbc);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		rx_upd_loc_req(conn, &gsup);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_REQUEST:
		rx_purge_ms_req(conn, &gsup);
		break;
	/* responses to requests sent by us */
	case OSMO_GSUP_MSGT_DELETE_DATA_ERROR:
		LOGP(DMAIN, LOGL_ERROR, "Error while deleting subscriber data "
		     "for IMSI %s\n", gsup.imsi);
		break;
	case OSMO_GSUP_MSGT_DELETE_DATA_RESULT:
		LOGP(DMAIN, LOGL_ERROR, "Deleting subscriber data for IMSI %s\n",
		     gsup.imsi);
		break;
	case OSMO_GSUP_MSGT_PROC_SS_REQUEST:
	case OSMO_GSUP_MSGT_PROC_SS_RESULT:
		rx_proc_ss_req(conn, &gsup);
		break;
	case OSMO_GSUP_MSGT_PROC_SS_ERROR:
		rx_proc_ss_error(conn, &gsup);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT:
		{
			struct lu_operation *luop = lu_op_by_imsi(gsup.imsi,
								  &g_lu_ops);
			if (!luop) {
				LOGP(DMAIN, LOGL_ERROR, "GSUP message %s for "
				     "unknown IMSI %s\n",
				     osmo_gsup_message_type_name(gsup.message_type),
					gsup.imsi);
				break;
			}
			lu_op_rx_gsup(luop, &gsup);
		}
		break;
	case OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST:
		rx_check_imei_req(conn, &gsup);
		break;
	default:
		LOGP(DMAIN, LOGL_DEBUG, "Unhandled GSUP message type %s\n",
		     osmo_gsup_message_type_name(gsup.message_type));
		break;
	}
	msgb_free(msg);
	return 0;
}

static void print_usage()
{
	printf("Usage: osmo-hlr\n");
}

static void print_help()
{
	printf("  -h --help                  This text.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -l --database db-name      The database to use.\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM  Enable debugging.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -s --disable-color         Do not print ANSI colors in the log\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");
	printf("  -U --db-upgrade            Allow HLR database schema upgrades.\n");
	printf("  -V --version               Print the version of OsmoHLR.\n");
}

static struct {
	const char *config_file;
	const char *db_file;
	bool daemonize;
	bool db_upgrade;
} cmdline_opts = {
	.config_file = "osmo-hlr.cfg",
	.db_file = "hlr.db",
	.daemonize = false,
	.db_upgrade = false,
};

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{"database", 1, 0, 'l'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"disable-color", 0, 0, 's'},
			{"log-level", 1, 0, 'e'},
			{"timestamp", 0, 0, 'T'},
			{"db-upgrade", 0, 0, 'U' },
			{"version", 0, 0, 'V' },
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hc:l:d:Dse:TUV",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'c':
			cmdline_opts.config_file = optarg;
			break;
		case 'l':
			cmdline_opts.db_file = optarg;
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			cmdline_opts.daemonize = 1;
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'U':
			cmdline_opts.db_upgrade = true;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}
}

static void *hlr_ctx = NULL;

static void signal_hdlr(int signal)
{
	switch (signal) {
	case SIGINT:
		LOGP(DMAIN, LOGL_NOTICE, "Terminating due to SIGINT\n");
		quit++;
		break;
	case SIGUSR1:
		LOGP(DMAIN, LOGL_DEBUG, "Talloc Report due to SIGUSR1\n");
		talloc_report_full(hlr_ctx, stderr);
		break;
	}
}

static const char vlr_copyright[] =
	"Copyright (C) 2016, 2017 by Harald Welte, sysmocom s.f.m.c. GmbH\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	 "There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct vty_app_info vty_info = {
	.name 		= "OsmoHLR",
	.version	= PACKAGE_VERSION,
	.copyright	= vlr_copyright,
	.is_config_node	= hlr_vty_is_config_node,
	.go_parent_cb   = hlr_vty_go_parent,
};

int main(int argc, char **argv)
{
	int rc;

	/* Track the use of talloc NULL memory contexts */
	talloc_enable_null_tracking();

	hlr_ctx = talloc_named_const(NULL, 1, "OsmoHLR");
	msgb_talloc_ctx_init(hlr_ctx, 0);
	vty_info.tall_ctx = hlr_ctx;

	g_hlr = talloc_zero(hlr_ctx, struct hlr);
	INIT_LLIST_HEAD(&g_hlr->euse_list);
	INIT_LLIST_HEAD(&g_hlr->iuse_list);
	INIT_LLIST_HEAD(&g_hlr->ss_sessions);
	INIT_LLIST_HEAD(&g_hlr->ussd_routes);

	/* Init default (call independent) SS session guard timeout value */
	g_hlr->ncss_guard_timeout = NCSS_GUARD_TIMEOUT_DEFAULT;

	rc = osmo_init_logging2(hlr_ctx, &hlr_log_info);
	if (rc < 0) {
		fprintf(stderr, "Error initializing logging\n");
		exit(1);
	}

	vty_init(&vty_info);
	ctrl_vty_init(hlr_ctx);
	handle_options(argc, argv);
	hlr_vty_init(&hlr_log_info);

	rc = vty_read_config_file(cmdline_opts.config_file, NULL);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL,
		     "Failed to parse the config file: '%s'\n",
		     cmdline_opts.config_file);
		return rc;
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(hlr_ctx, NULL, vty_get_bind_addr(),
			       OSMO_VTY_PORT_HLR);
	if (rc < 0)
		return rc;

	LOGP(DMAIN, LOGL_NOTICE, "hlr starting\n");

	rc = rand_init();
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL, "Error initializing random source\n");
		exit(1);
	}

	g_hlr->dbc = db_open(hlr_ctx, cmdline_opts.db_file, true, cmdline_opts.db_upgrade);
	if (!g_hlr->dbc) {
		LOGP(DMAIN, LOGL_FATAL, "Error opening database\n");
		exit(1);
	}

	g_hlr->gs = osmo_gsup_server_create(hlr_ctx, g_hlr->gsup_bind_addr, OSMO_GSUP_PORT,
					    read_cb, &g_lu_ops, g_hlr);
	if (!g_hlr->gs) {
		LOGP(DMAIN, LOGL_FATAL, "Error starting GSUP server\n");
		exit(1);
	}

	g_hlr->ctrl_bind_addr = ctrl_vty_get_bind_addr();
	g_hlr->ctrl = hlr_controlif_setup(g_hlr);

	osmo_init_ignore_signals();
	signal(SIGINT, &signal_hdlr);
	signal(SIGUSR1, &signal_hdlr);

	if (cmdline_opts.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (!quit)
		osmo_select_main(0);

	osmo_gsup_server_destroy(g_hlr->gs);
	db_close(g_hlr->dbc);
	log_fini();

	/**
	 * Report the heap state of root context, then free,
	 * so both ASAN and Valgrind are happy...
	 */
	talloc_report_full(hlr_ctx, stderr);
	talloc_free(hlr_ctx);

	/* FIXME: VTY code still uses NULL-context */
	talloc_free(tall_vty_ctx);

	/**
	 * Report the heap state of NULL context, then free,
	 * so both ASAN and Valgrind are happy...
	 */
	talloc_report_full(NULL, stderr);
	talloc_disable_null_tracking();

	return 0;
}
