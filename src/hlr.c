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
#include <osmocom/core/stats.h>
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
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/mslookup/mslookup_client.h>

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
#include "dgsm.h"
#include "proxy.h"

struct hlr *g_hlr;
static void *hlr_ctx = NULL;
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
		msg_out = osmo_gsup_msgb_alloc("GSUP ISD UPDATE");
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

static int generate_new_msisdn(char *msisdn, const char *imsi, unsigned int len)
{
	int i, j, rc;
	uint8_t rand_buf[GSM23003_MSISDN_MAX_DIGITS];

	OSMO_ASSERT(len <= sizeof(rand_buf));

	/* Generate a random unique MSISDN (with retry) */
	for (i = 0; i < 10; i++) {
		/* Get a random number (with retry) */
		for (j = 0; j < 10; j++) {
			rc = osmo_get_rand_id(rand_buf, len);
			if (!rc)
				break;
		}
		if (rc) {
			LOGP(DMAIN, LOGL_ERROR, "IMSI='%s': Failed to generate new MSISDN, random number generator"
						" failed (rc=%d)\n", imsi, rc);
			return rc;
		}

		/* Shift 0x00 ... 0xff range to 30 ... 39 (ASCII numbers) */
		for (j = 0; j < len; j++)
			msisdn[j] = 48 + (rand_buf[j] % 10);
		msisdn[j] = '\0';

		/* Ensure there is no subscriber with such MSISDN */
		if (db_subscr_exists_by_msisdn(g_hlr->dbc, msisdn) == -ENOENT)
			return 0;
	}

	/* Failure */
	LOGP(DMAIN, LOGL_ERROR, "IMSI='%s': Failed to generate a new MSISDN, consider increasing "
				"the length for the automatically assigned MSISDNs "
				"(see 'subscriber-create-on-demand' command)\n", imsi);
	return -1;
}

static int subscr_create_on_demand(const char *imsi)
{
	char msisdn[GSM23003_MSISDN_MAX_DIGITS + 1];
	int rc;
	unsigned int rand_msisdn_len = g_hlr->subscr_create_on_demand_rand_msisdn_len;

	if (!g_hlr->subscr_create_on_demand)
		return -1;
	if (db_subscr_exists_by_imsi(g_hlr->dbc, imsi) == 0)
		return -1;
	if (rand_msisdn_len && generate_new_msisdn(msisdn, imsi, rand_msisdn_len) != 0)
		return -1;

	LOGP(DMAIN, LOGL_INFO, "IMSI='%s': Creating subscriber on demand\n", imsi);
	rc = db_subscr_create(g_hlr->dbc, imsi, g_hlr->subscr_create_on_demand_flags);
	if (rc) {
		LOGP(DMAIN, LOGL_ERROR, "Failed to create subscriber on demand (rc=%d): IMSI='%s'\n", rc, imsi);
		return rc;
	}

	if (!rand_msisdn_len)
		return 0;

	/* Update MSISDN of the new (just allocated) subscriber */
	rc = db_subscr_update_msisdn_by_imsi(g_hlr->dbc, imsi, msisdn);
	if (rc) {
		LOGP(DMAIN, LOGL_ERROR, "IMSI='%s': Failed to assign MSISDN='%s' (rc=%d)\n", imsi, msisdn, rc);
		return rc;
	}
	LOGP(DMAIN, LOGL_INFO, "IMSI='%s': Successfully assigned MSISDN='%s'\n", imsi, msisdn);

	return 0;
}

/***********************************************************************
 * Send Auth Info handling
 ***********************************************************************/

/* process an incoming SAI request */
static int rx_send_auth_info(struct osmo_gsup_conn *conn,
			     const struct osmo_gsup_message *gsup,
			     struct db_context *dbc)
{
	struct osmo_gsup_message gsup_out = {};
	struct msgb *msg_out;
	int rc;

	subscr_create_on_demand(gsup->imsi);

	/* initialize return message structure */
	osmo_gsup_set_reply(gsup, &gsup_out);

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

	msg_out = osmo_gsup_msgb_alloc("GSUP AUC response");
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
	struct lu_operation *luop = lu_op_alloc_conn(conn, gsup);
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

	subscr_create_on_demand(gsup->imsi);

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
	if (global_title_cmp(&luop->vlr_number, &luop->peer))
		LOGP(DAUC, LOGL_DEBUG, "IMSI='%s': storing %s = %s, via proxy %s\n",
		     subscr->imsi, luop->is_ps ? "SGSN number" : "VLR number",
		     global_title_name(&luop->vlr_number), global_title_name(&luop->peer));
	else
		LOGP(DAUC, LOGL_DEBUG, "IMSI='%s': storing %s = %s\n",
		     subscr->imsi, luop->is_ps ? "SGSN number" : "VLR number",
		     global_title_name(&luop->vlr_number));

	if (db_subscr_lu(g_hlr->dbc, subscr->id, &luop->peer, &luop->vlr_number, luop->is_ps))
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
	struct osmo_gsup_message gsup_reply = {};
	struct msgb *msg_out;
	bool is_ps = false;
	int rc;

	osmo_gsup_set_reply(gsup, &gsup_reply);

	if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS)
		is_ps = true;

	LOGP(DAUC, LOGL_INFO, "%s: Purge MS (%s)\n", gsup->imsi,
		is_ps ? "PS" : "CS");

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

	msg_out = osmo_gsup_msgb_alloc("GSUP AUC response");
	osmo_gsup_encode(msg_out, &gsup_reply);
	return osmo_gsup_conn_send(conn, msg_out);
}

static int rx_check_imei_req(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};
	struct msgb *msg_out;
	char imei[GSM23003_IMEI_NUM_DIGITS_NO_CHK+1] = {0};
	int rc;

	/* Require IMEI */
	if (!gsup->imei_enc) {
		LOGP(DMAIN, LOGL_ERROR, "%s: missing IMEI\n", gsup->imsi);
		osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_INV_MAND_INFO);
		return -1;
	}

	/* Decode IMEI (fails if IMEI is too long) */
	rc = gsm48_decode_bcd_number2(imei, sizeof(imei), gsup->imei_enc, gsup->imei_enc_len, 0);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "%s: failed to decode IMEI (rc: %i)\n", gsup->imsi, rc);
		osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_INV_MAND_INFO);
		return -1;
	}

	/* Check if IMEI is too short */
	if (strlen(imei) != GSM23003_IMEI_NUM_DIGITS_NO_CHK) {
		LOGP(DMAIN, LOGL_ERROR, "%s: wrong encoded IMEI length (IMEI: '%s', %lu, %i)\n", gsup->imsi, imei,
		     strlen(imei), GSM23003_IMEI_NUM_DIGITS_NO_CHK);
		osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_INV_MAND_INFO);
		return -1;
	}

	subscr_create_on_demand(gsup->imsi);

	/* Save in DB if desired */
	if (g_hlr->store_imei) {
		LOGP(DAUC, LOGL_DEBUG, "IMSI='%s': storing IMEI = %s\n", gsup->imsi, imei);
		if (db_subscr_update_imei_by_imsi(g_hlr->dbc, gsup->imsi, imei) < 0) {
			osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_INV_MAND_INFO);
			return -1;
		}
	} else {
		/* Check if subscriber exists and print IMEI */
		LOGP(DMAIN, LOGL_INFO, "IMSI='%s': has IMEI = %s (consider setting 'store-imei')\n", gsup->imsi, imei);
		struct hlr_subscriber subscr;
		if (db_subscr_get_by_imsi(g_hlr->dbc, gsup->imsi, &subscr) < 0) {
			osmo_gsup_conn_send_err_reply(conn, gsup, GMM_CAUSE_INV_MAND_INFO);
			return -1;
		}
	}

	/* Accept all IMEIs */
	gsup_reply.imei_result = OSMO_GSUP_IMEI_RESULT_ACK;
	gsup_reply.message_type = OSMO_GSUP_MSGT_CHECK_IMEI_RESULT;
	msg_out = osmo_gsup_msgb_alloc("GSUP Check_IMEI response");
	memcpy(gsup_reply.imsi, gsup->imsi, sizeof(gsup_reply.imsi));
	osmo_gsup_encode(msg_out, &gsup_reply);
	return osmo_gsup_conn_send(conn, msg_out);
}

static char namebuf[255];
#define LOGP_GSUP_FWD(gsup, level, fmt, args ...) \
	LOGP(DMAIN, level, "Forward %s (class=%s, IMSI=%s, %s->%s): " fmt, \
	     osmo_gsup_message_type_name(gsup->message_type), \
	     osmo_gsup_message_class_name(gsup->message_class), \
	     gsup->imsi, \
	     osmo_quote_str((const char *)gsup->source_name, gsup->source_name_len), \
	     osmo_quote_str_buf2(namebuf, sizeof(namebuf), (const char *)gsup->destination_name, gsup->destination_name_len), \
	     ## args)

static int read_cb_forward(struct osmo_gsup_conn *conn, struct msgb *msg, const struct osmo_gsup_message *gsup)
{
	int ret = -EINVAL;
	struct osmo_gsup_message *gsup_err;

	/* FIXME: it would be better if the msgb never were deallocated immediately by osmo_gsup_addr_send(), which a
	 * select-loop volatile talloc context could facilitate. Then we would still be able to access gsup-> members
	 * (pointing into the msgb) even after sending failed, and we wouldn't need to copy this data before sending: */
	/* Prepare error message (before IEs get deallocated) */
	gsup_err = talloc_zero(hlr_ctx, struct osmo_gsup_message);
	OSMO_STRLCPY_ARRAY(gsup_err->imsi, gsup->imsi);
	gsup_err->message_class = gsup->message_class;
	gsup_err->destination_name = talloc_memdup(gsup_err, gsup->destination_name, gsup->destination_name_len);
	gsup_err->destination_name_len = gsup->destination_name_len;
	gsup_err->message_type = gsup->message_type;
	gsup_err->session_state = gsup->session_state;
	gsup_err->session_id = gsup->session_id;
	gsup_err->source_name = talloc_memdup(gsup_err, gsup->source_name, gsup->source_name_len);
	gsup_err->source_name_len = gsup->source_name_len;

	/* Check for routing IEs */
	if (!gsup->source_name || !gsup->source_name_len || !gsup->destination_name || !gsup->destination_name_len) {
		LOGP_GSUP_FWD(gsup, LOGL_ERROR, "missing routing IEs\n");
		goto end;
	}

	/* Verify source name (e.g. "MSC-00-00-00-00-00-00") */
	if (gsup_route_find(conn->server, gsup->source_name, gsup->source_name_len) != conn) {
		LOGP_GSUP_FWD(gsup, LOGL_ERROR, "mismatching source name\n");
		goto end;
	}

	/* Forward message without re-encoding (so we don't remove unknown IEs) */
	LOGP_GSUP_FWD(gsup, LOGL_INFO, "checks passed, forwarding\n");

	/* Remove incoming IPA header to be able to prepend an outgoing IPA header */
	msgb_pull_to_l2(msg);
	ret = osmo_gsup_addr_send(g_hlr->gs, gsup->destination_name, gsup->destination_name_len, msg);
	/* AT THIS POINT, THE msg MAY BE DEALLOCATED and the data like gsup->imsi, gsup->source_name etc may all be
	 * invalid and cause segfaults. */
	msg = NULL;
	gsup = NULL;
	if (ret == -ENODEV)
		LOGP_GSUP_FWD(gsup_err, LOGL_ERROR, "destination not connected\n");
	else if (ret)
		LOGP_GSUP_FWD(gsup_err, LOGL_ERROR, "unknown error %i\n", ret);

end:
	/* Send error back to source */
	if (ret) {
		struct msgb *msg_err = osmo_gsup_msgb_alloc("GSUP forward ERR response");
		OSMO_ASSERT(msg_err);
		gsup_err->message_type = OSMO_GSUP_MSGT_E_ROUTING_ERROR;
		osmo_gsup_encode(msg_err, gsup_err);
		LOGP_GSUP_FWD(gsup_err, LOGL_NOTICE, "Tx %s\n", osmo_gsup_message_type_name(gsup_err->message_type));
		osmo_gsup_conn_send(conn, msg_err);
	}
	talloc_free(gsup_err);
	if (msg)
		msgb_free(msg);
	return ret;
}

static int read_cb(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	static struct osmo_gsup_message gsup;
	int rc;

	if (!msgb_l2(msg) || !msgb_l2len(msg)) {
		LOGP(DMAIN, LOGL_ERROR, "missing or empty L2 data\n");
		msgb_free(msg);
		return -EINVAL;
	}

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "error in GSUP decode: %d\n", rc);
		msgb_free(msg);
		return rc;
	}

	/* 3GPP TS 23.003 Section 2.2 clearly states that an IMSI with less than 5
	 * digits is impossible.  Even 5 digits is a highly theoretical case */
	if (strlen(gsup.imsi) < 5) { /* TODO: move this check to libosmogsm/gsup.c? */
		LOGP(DMAIN, LOGL_ERROR, "IMSI too short: %s\n", osmo_quote_str(gsup.imsi, -1));
		osmo_gsup_conn_send_err_reply(conn, &gsup, GMM_CAUSE_INV_MAND_INFO);
		msgb_free(msg);
		return -EINVAL;
	}

	if (gsup.destination_name_len)
		return read_cb_forward(conn, msg, &gsup);

	/* Distributed GSM: check whether to proxy for / lookup a remote HLR.
	 * It would require less database hits to do this only if a local-only operation fails with "unknown IMSI", but
	 * it becomes semantically easier if we do this once-off ahead of time. */
	if (osmo_mslookup_client_active(g_hlr->mslookup.client.client)
	    && dgsm_check_forward_gsup_msg(conn, &gsup))
		goto cleanup_and_exit;

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

cleanup_and_exit:
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
	printf("  -C --db-check              Quit after opening (and upgrading) the database.\n");
	printf("  -V --version               Print the version of OsmoHLR.\n");
}

static struct {
	const char *config_file;
	const char *db_file;
	bool daemonize;
	bool db_upgrade;
	bool db_check;
} cmdline_opts = {
	.config_file = "osmo-hlr.cfg",
	.db_file = NULL,
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
			{"db-check", 0, 0, 'C' },
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
		case 'C':
			cmdline_opts.db_check = true;
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

static void signal_hdlr(int signal)
{
	switch (signal) {
	case SIGTERM:
	case SIGINT:
		LOGP(DMAIN, LOGL_NOTICE, "Terminating due to signal=%d\n", signal);
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
	g_hlr->db_file_path = talloc_strdup(g_hlr, HLR_DEFAULT_DB_FILE_PATH);

	/* Init default (call independent) SS session guard timeout value */
	g_hlr->ncss_guard_timeout = NCSS_GUARD_TIMEOUT_DEFAULT;

	g_hlr->proxy = proxy_init(g_hlr);

	rc = osmo_init_logging2(hlr_ctx, &hlr_log_info);
	if (rc < 0) {
		fprintf(stderr, "Error initializing logging\n");
		exit(1);
	}

	/* Set up llists and objects, startup is happening from VTY commands. */
	dgsm_init(hlr_ctx);

	osmo_stats_init(hlr_ctx);
	vty_init(&vty_info);
	ctrl_vty_init(hlr_ctx);
	handle_options(argc, argv);
	hlr_vty_init();

	rc = vty_read_config_file(cmdline_opts.config_file, NULL);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL,
		     "Failed to parse the config file: '%s'\n",
		     cmdline_opts.config_file);
		return rc;
	}

	LOGP(DMAIN, LOGL_NOTICE, "hlr starting\n");

	rc = rand_init();
	if (rc < 0) {
		LOGP(DMAIN, LOGL_FATAL, "Error initializing random source\n");
		exit(1);
	}

	if (cmdline_opts.db_file)
		osmo_talloc_replace_string(g_hlr, &g_hlr->db_file_path, cmdline_opts.db_file);

	g_hlr->dbc = db_open(hlr_ctx, g_hlr->db_file_path, true, cmdline_opts.db_upgrade);
	if (!g_hlr->dbc) {
		LOGP(DMAIN, LOGL_FATAL, "Error opening database %s\n", osmo_quote_str(g_hlr->db_file_path, -1));
		exit(1);
	}

	if (cmdline_opts.db_check) {
		LOGP(DMAIN, LOGL_NOTICE, "Cmdline option --db-check: Database was opened successfully, quitting.\n");
		db_close(g_hlr->dbc);
		log_fini();
		talloc_free(hlr_ctx);
		talloc_free(tall_vty_ctx);
		talloc_disable_null_tracking();
		exit(0);
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(hlr_ctx, NULL, vty_get_bind_addr(),
			       OSMO_VTY_PORT_HLR);
	if (rc < 0)
		return rc;


	g_hlr->gs = osmo_gsup_server_create(hlr_ctx, g_hlr->gsup_bind_addr, OSMO_GSUP_PORT,
					    read_cb, &g_lu_ops, g_hlr);
	if (!g_hlr->gs) {
		LOGP(DMAIN, LOGL_FATAL, "Error starting GSUP server\n");
		exit(1);
	}

	g_hlr->ctrl_bind_addr = ctrl_vty_get_bind_addr();
	g_hlr->ctrl = hlr_controlif_setup(g_hlr);

	dgsm_start(hlr_ctx);

	osmo_init_ignore_signals();
	signal(SIGINT, &signal_hdlr);
	signal(SIGTERM, &signal_hdlr);
	signal(SIGUSR1, &signal_hdlr);

	if (cmdline_opts.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (!quit)
		osmo_select_main_ctx(0);

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
