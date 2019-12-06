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
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/mslookup/mslookup_client.h>

#include <osmocom/gsupclient/gsup_peer_id.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/ctrl.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/gsup_server.h>
#include <osmocom/hlr/gsup_router.h>
#include <osmocom/hlr/rand.h>
#include <osmocom/hlr/hlr_vty.h>
#include <osmocom/hlr/hlr_ussd.h>
#include <osmocom/hlr/dgsm.h>
#include <osmocom/hlr/proxy.h>
#include <osmocom/hlr/lu_fsm.h>
#include <osmocom/mslookup/mdns.h>

struct hlr *g_hlr;
static void *hlr_ctx = NULL;
static int quit = 0;

struct osmo_tdef g_hlr_tdefs[] = {
	/* 4222 is also the OSMO_GSUP_PORT */
	{ .T = -4222, .default_val = 30, .desc = "GSUP Update Location timeout" },
	{}
};

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

	/* FIXME: send only to current vlr_number and sgsn_number */

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

/*! Update nam_cs/nam_ps in the db and trigger notifications to GSUP clients.
 * \param[in,out] hlr  Global hlr context.
 * \param[in] subscr   Subscriber from a fresh db_subscr_get_by_*() call.
 * \param[in] nam_val  True to enable CS/PS, false to disable.
 * \param[in] is_ps    True to enable/disable PS, false for CS.
 * \returns 0 on success, ENOEXEC if there is no need to change, a negative
 *          value on error.
 */
int hlr_subscr_nam(struct hlr *hlr, struct hlr_subscriber *subscr, bool nam_val, bool is_ps)
{
	int rc;
	bool is_val = is_ps? subscr->nam_ps : subscr->nam_cs;
	struct osmo_ipa_name vlr_name;
	struct osmo_gsup_message gsup_del_data = {
		.message_type = OSMO_GSUP_MSGT_DELETE_DATA_REQUEST,
	};
	OSMO_STRLCPY_ARRAY(gsup_del_data.imsi, subscr->imsi);

	if (is_val == nam_val) {
		LOGP(DAUC, LOGL_DEBUG, "IMSI-%s: Already has the requested value when asked to %s %s\n",
		     subscr->imsi, nam_val ? "enable" : "disable", is_ps ? "PS" : "CS");
		return ENOEXEC;
	}

	rc = db_subscr_nam(hlr->dbc, subscr->imsi, nam_val, is_ps);
	if (rc)
		return rc > 0? -rc : rc;

	/* If we're disabling, send a notice out to the GSUP client that is
	 * responsible. Otherwise no need. */
	if (nam_val)
		return 0;

	if (subscr->vlr_number && osmo_ipa_name_set_str(&vlr_name, subscr->vlr_number))
		osmo_gsup_enc_send_to_ipa_name(g_hlr->gs, &vlr_name, &gsup_del_data);
	if (subscr->sgsn_number && osmo_ipa_name_set_str(&vlr_name, subscr->sgsn_number))
		osmo_gsup_enc_send_to_ipa_name(g_hlr->gs, &vlr_name, &gsup_del_data);
	return 0;
}

/***********************************************************************
 * Send Auth Info handling
 ***********************************************************************/

/* process an incoming SAI request */
static int rx_send_auth_info(unsigned int auc_3g_ind, struct osmo_gsup_req *req)
{
	struct osmo_gsup_message gsup_out = {
		.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT,
	};
	bool separation_bit = false;
	int rc;

	subscr_create_on_demand(req->gsup.imsi);

	if (req->gsup.current_rat_type == OSMO_RAT_EUTRAN_SGS)
		separation_bit = true;

	rc = db_get_auc(g_hlr->dbc, req->gsup.imsi, auc_3g_ind,
			gsup_out.auth_vectors,
			ARRAY_SIZE(gsup_out.auth_vectors),
			req->gsup.rand, req->gsup.auts, separation_bit);

	if (rc <= 0) {
		switch (rc) {
		case 0:
			/* 0 means "0 tuples generated", which shouldn't happen.
			 * Treat the same as "no auth data". */
		case -ENOKEY:
			osmo_gsup_req_respond_err(req, GMM_CAUSE_IMSI_UNKNOWN,
						  "IMSI known, but has no auth data;"
						  " Returning slightly inaccurate cause 'IMSI Unknown' via GSUP");
			return rc;
		case -ENOENT:
			osmo_gsup_req_respond_err(req, GMM_CAUSE_IMSI_UNKNOWN, "IMSI unknown");
			return rc;
		default:
			osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "failure to look up IMSI in db");
			return rc;
		}
	}
	gsup_out.num_auth_vectors = rc;

	osmo_gsup_req_respond(req, &gsup_out, false, true);
	return 0;
}

/*! Receive Update Location Request, creates new lu_operation */
static int rx_upd_loc_req(struct osmo_gsup_conn *conn, struct osmo_gsup_req *req)
{
	switch (req->gsup.cn_domain) {
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
		break;
	}

	subscr_create_on_demand(req->gsup.imsi);

	lu_rx_gsup(req);
	return 0;
}

static int rx_purge_ms_req(struct osmo_gsup_req *req)
{
	bool is_ps = (req->gsup.cn_domain != OSMO_GSUP_CN_DOMAIN_CS);
	int rc;

	LOG_GSUP_REQ_CAT(req, DAUC, LOGL_INFO, "Purge MS (%s)\n", is_ps ? "PS" : "CS");

	/* FIXME: check if the VLR that sends the purge is the same that
	 * we have on record. Only update if yes */

	/* Perform the actual update of the DB */
	rc = db_subscr_purge(g_hlr->dbc, req->gsup.imsi, true, is_ps);

	if (rc == 0)
		osmo_gsup_req_respond_msgt(req, OSMO_GSUP_MSGT_PURGE_MS_RESULT, true);
	else if (rc == -ENOENT)
		osmo_gsup_req_respond_err(req, GMM_CAUSE_IMSI_UNKNOWN, "IMSI unknown");
	else
		osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "db error");
	return rc;
}

static int rx_check_imei_req(struct osmo_gsup_req *req)
{
	struct osmo_gsup_message gsup_reply;
	char imei[GSM23003_IMEI_NUM_DIGITS_NO_CHK+1] = {0};
	const struct osmo_gsup_message *gsup = &req->gsup;
	int rc;

	/* Require IMEI */
	if (!gsup->imei_enc) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "missing IMEI");
		return -1;
	}

	/* Decode IMEI (fails if IMEI is too long) */
	rc = gsm48_decode_bcd_number2(imei, sizeof(imei), gsup->imei_enc, gsup->imei_enc_len, 0);
	if (rc < 0) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO,
					  "failed to decode IMEI %s (rc: %d)",
					  osmo_hexdump_c(OTC_SELECT, gsup->imei_enc, gsup->imei_enc_len),
					  rc);
		return -1;
	}

	/* Check if IMEI is too short */
	if (!osmo_imei_str_valid(imei, false)) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO,
					  "invalid IMEI: %s", osmo_quote_str_c(OTC_SELECT, imei, -1));
		return -1;
	}

	subscr_create_on_demand(gsup->imsi);

	/* Save in DB if desired */
	if (g_hlr->store_imei) {
		LOGP(DAUC, LOGL_DEBUG, "IMSI='%s': storing IMEI = %s\n", gsup->imsi, imei);
		if (db_subscr_update_imei_by_imsi(g_hlr->dbc, gsup->imsi, imei) < 0) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "Failed to store IMEI in HLR db");
			return -1;
		}
	} else {
		/* Check if subscriber exists and print IMEI */
		LOGP(DMAIN, LOGL_INFO, "IMSI='%s': has IMEI = %s (consider setting 'store-imei')\n", gsup->imsi, imei);
		struct hlr_subscriber subscr;
		if (db_subscr_get_by_imsi(g_hlr->dbc, gsup->imsi, &subscr) < 0) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "IMSI unknown");
			return -1;
		}
	}

	/* Accept all IMEIs */
	gsup_reply = (struct osmo_gsup_message){
		.message_type = OSMO_GSUP_MSGT_CHECK_IMEI_RESULT,
		.imei_result = OSMO_GSUP_IMEI_RESULT_ACK,
	};
	return osmo_gsup_req_respond(req, &gsup_reply, false, true);
}

static char namebuf[255];
#define LOGP_GSUP_FWD(gsup, level, fmt, args ...) \
	LOGP(DMAIN, level, "Forward %s (class=%s, IMSI=%s, %s->%s): " fmt, \
	     osmo_gsup_message_type_name((gsup)->message_type), \
	     osmo_gsup_message_class_name((gsup)->message_class), \
	     (gsup)->imsi, \
	     osmo_quote_str((const char *)(gsup)->source_name, (gsup)->source_name_len), \
	     osmo_quote_str_buf2(namebuf, sizeof(namebuf), (const char *)(gsup)->destination_name, (gsup)->destination_name_len), \
	     ## args)

static int read_cb_forward(struct osmo_gsup_req *req)
{
	int ret = -EINVAL;
	const struct osmo_gsup_message *gsup = &req->gsup;
	struct osmo_gsup_message gsup_err;
	struct msgb *forward_msg;
	struct osmo_ipa_name destination_name;

	/* Check for routing IEs */
	if (!req->gsup.source_name[0] || !req->gsup.source_name_len
	    || !req->gsup.destination_name[0] || !req->gsup.destination_name_len) {
		LOGP_GSUP_FWD(&req->gsup, LOGL_ERROR, "missing routing IEs\n");
		goto routing_error;
	}

	if (osmo_ipa_name_set(&destination_name, req->gsup.destination_name, req->gsup.destination_name_len)) {
		LOGP_GSUP_FWD(&req->gsup, LOGL_ERROR, "invalid destination name\n");
		goto routing_error;
	}

	LOG_GSUP_REQ(req, LOGL_INFO, "Forwarding to %s\n", osmo_ipa_name_to_str(&destination_name));

	/* Forward message without re-encoding (so we don't remove unknown IEs).
	 * Copy GSUP part to forward, removing incoming IPA header to be able to prepend an outgoing IPA header */
	forward_msg = osmo_gsup_msgb_alloc("GSUP forward");
	forward_msg->l2h = msgb_put(forward_msg, msgb_l2len(req->msg));
	memcpy(forward_msg->l2h, msgb_l2(req->msg), msgb_l2len(req->msg));
	ret = osmo_gsup_send_to_ipa_name(g_hlr->gs, &destination_name, forward_msg);
	if (ret) {
		LOGP_GSUP_FWD(gsup, LOGL_ERROR, "%s (rc=%d)\n",
			      ret == -ENODEV ? "destination not connected" : "unknown error",
			      ret);
		goto routing_error;
	}
	osmo_gsup_req_free(req);
	return 0;

routing_error:
	gsup_err = (struct osmo_gsup_message){
		.message_type = OSMO_GSUP_MSGT_ROUTING_ERROR,
		.source_name = gsup->destination_name,
		.source_name_len = gsup->destination_name_len,
	};
	osmo_gsup_req_respond(req, &gsup_err, true, true);
	return -1;
}

static int read_cb(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	struct osmo_gsup_req *req = osmo_gsup_conn_rx(conn, msg);
	if (!req)
		return -EINVAL;

	/* If the GSUP recipient is other than this HLR, forward. */
	if (req->gsup.destination_name_len) {
		struct osmo_ipa_name destination_name;
		struct osmo_ipa_name my_name;
		osmo_ipa_name_set_str(&my_name, g_hlr->gsup_unit_name.serno);
		if (!osmo_ipa_name_set(&destination_name, req->gsup.destination_name, req->gsup.destination_name_len)
		    && osmo_ipa_name_cmp(&destination_name, &my_name)) {
			return read_cb_forward(req);
		}
	}

	/* Distributed GSM: check whether to proxy for / lookup a remote HLR.
	 * It would require less database hits to do this only if a local-only operation fails with "unknown IMSI", but
	 * it becomes semantically easier if we do this once-off ahead of time. */
	if (osmo_mslookup_client_active(g_hlr->mslookup.client.client)
	    || osmo_sockaddr_str_is_nonzero(&g_hlr->mslookup.client.gsup_gateway_proxy)) {
		if (dgsm_check_forward_gsup_msg(req))
			return 0;
	}

	/* HLR related messages that are handled at this HLR instance */
	switch (req->gsup.message_type) {
	/* requests sent to us */
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST:
		rx_send_auth_info(conn->auc_3g_ind, req);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		rx_upd_loc_req(conn, req);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_REQUEST:
		rx_purge_ms_req(req);
		break;
	/* responses to requests sent by us */
	case OSMO_GSUP_MSGT_DELETE_DATA_ERROR:
		LOG_GSUP_REQ(req, LOGL_ERROR, "Peer responds with: Error while deleting subscriber data\n");
		osmo_gsup_req_free(req);
		break;
	case OSMO_GSUP_MSGT_DELETE_DATA_RESULT:
		LOG_GSUP_REQ(req, LOGL_DEBUG, "Peer responds with: Subscriber data deleted\n");
		osmo_gsup_req_free(req);
		break;
	case OSMO_GSUP_MSGT_PROC_SS_REQUEST:
	case OSMO_GSUP_MSGT_PROC_SS_RESULT:
		rx_proc_ss_req(req);
		break;
	case OSMO_GSUP_MSGT_PROC_SS_ERROR:
		rx_proc_ss_error(req);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT:
		lu_rx_gsup(req);
		break;
	case OSMO_GSUP_MSGT_CHECK_IMEI_REQUEST:
		rx_check_imei_req(req);
		break;
	default:
		LOGP(DMAIN, LOGL_DEBUG, "Unhandled GSUP message type %s\n",
		     osmo_gsup_message_type_name(req->gsup.message_type));
		osmo_gsup_req_free(req);
		break;
	}
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

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
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
	INIT_LLIST_HEAD(&g_hlr->mslookup.server.local_site_services);
	g_hlr->db_file_path = talloc_strdup(g_hlr, HLR_DEFAULT_DB_FILE_PATH);
	g_hlr->mslookup.server.mdns.domain_suffix = talloc_strdup(g_hlr, OSMO_MDNS_DOMAIN_SUFFIX_DEFAULT);
	g_hlr->mslookup.client.mdns.domain_suffix = talloc_strdup(g_hlr, OSMO_MDNS_DOMAIN_SUFFIX_DEFAULT);

	/* Init default (call independent) SS session guard timeout value */
	g_hlr->ncss_guard_timeout = NCSS_GUARD_TIMEOUT_DEFAULT;

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
	dgsm_vty_init();

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
					    read_cb, g_hlr);
	if (!g_hlr->gs) {
		LOGP(DMAIN, LOGL_FATAL, "Error starting GSUP server\n");
		exit(1);
	}
	proxy_init(g_hlr->gs);

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

	dgsm_stop();

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
