/* osmo-demo-euse: An External USSD Entity (EUSE) for demo purpose */

/* (C) 2018 by Harald Welte <laforge@gnumonks.org>
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
 */

/*
 * This program illustrates how to implement an external USSD application using
 * the existing osmocom libraries, particularly libosmocore, libosmogsm and libosmo-gsup-client.
 *
 * It will receive any MS-originated USSD message that is routed to it via the HLR, and
 * simply respond it quoted in the following string: 'You sent "foobar"' (assuming the original
 * message was 'foobar').
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>

#include <osmocom/gsupclient/gsup_client.h>

#include "logging.h"

static struct osmo_gsup_client *g_gc;

/*! send a SS/USSD response to a given imsi/session.
 *  \param[in] gsupc GSUP client connection through which to send
 *  \param[in] imsi IMSI of the subscriber
 *  \param[in] session_id Unique identifier of SS session for which this response is
 *  \param[in] gsup_msg_type GSUP message type (OSMO_GSUP_MSGT_PROC_SS_{REQUEST,RESULT,ERROR})
 *  \param[in] final Is this the final result (true=END) or an intermediate result (false=CONTINUE)
 *  \param[in] msg Optional binary/BER encoded SS date (for FACILITY IE). Can be NULL. Freed in
 *  		   this function call.
 */
static int euse_tx_ss(struct osmo_gsup_client *gsupc, const char *imsi, uint32_t session_id,
		      enum osmo_gsup_message_type gsup_msg_type, bool final, struct msgb *ss_msg)
{
	struct osmo_gsup_message resp = {0};
	struct msgb *resp_msg;

	switch (gsup_msg_type) {
	case OSMO_GSUP_MSGT_PROC_SS_REQUEST:
	case OSMO_GSUP_MSGT_PROC_SS_RESULT:
	case OSMO_GSUP_MSGT_PROC_SS_ERROR:
		break;
	default:
		msgb_free(ss_msg);
		return -EINVAL;
	}

	resp.message_type = gsup_msg_type;
	OSMO_STRLCPY_ARRAY(resp.imsi, imsi);
	if (final)
		resp.session_state = OSMO_GSUP_SESSION_STATE_END;
	else
		resp.session_state = OSMO_GSUP_SESSION_STATE_CONTINUE;
	resp.session_id = session_id;
	if (ss_msg) {
		resp.ss_info = msgb_data(ss_msg);
		resp.ss_info_len = msgb_length(ss_msg);
	}

	resp_msg = gsm0480_msgb_alloc_name(__func__);
	OSMO_ASSERT(resp_msg);
	osmo_gsup_encode(resp_msg, &resp);
	msgb_free(ss_msg);
	return osmo_gsup_client_send(gsupc, resp_msg);
}

/*! send a SS/USSD reject to a given IMSI/session.
 * \param[in] gsupc		GSUP client connection through which to send
 * \param[in] imsi		IMSI of the subscriber
 * \param[in] session_id	Unique identifier of SS session for which this response is
 * \param[in] invoke_id		InvokeID of the request
 * \param[in] problem_tag	Problem code tag (table 3.13)
 * \param[in] problem_code	Problem code (table 3.14-3.17)
 */
static int euse_tx_ussd_reject(struct osmo_gsup_client *gsupc, const char *imsi, uint32_t session_id,
				int invoke_id, uint8_t problem_tag, uint8_t problem_code)
{
	struct msgb *msg = gsm0480_gen_reject(invoke_id, problem_tag, problem_code);
	LOGP(DMAIN, LOGL_NOTICE, "Tx %s/0x%08x: Reject(%d, 0x%02x, 0x%02x)\n", imsi, session_id,
		invoke_id, problem_tag, problem_code);
	OSMO_ASSERT(msg);
	return euse_tx_ss(gsupc, imsi, session_id, OSMO_GSUP_MSGT_PROC_SS_RESULT, true, msg);
}

/*! send a SS/USSD response in 7-bit GSM default alphabet o a given imsi/session.
 * \param[in] gsupc		GSUP client connection through which to send
 * \param[in] imsi		IMSI of the subscriber
 * \param[in] session_id	Unique identifier of SS session for which this response is
 * \param[in] final		Is this the final result (true=END) or an intermediate result
 * 				(false=CONTINUE)
 * \param[in] invoke_id		InvokeID of the request
 */
static int euse_tx_ussd_resp_7bit(struct osmo_gsup_client *gsupc, const char *imsi, uint32_t session_id,
				  bool final, uint8_t invoke_id, const char *text)
{
	struct msgb *ss_msg;

	/* encode response; remove L3 header */
	ss_msg = gsm0480_gen_ussd_resp_7bit(invoke_id, text);
	LOGP(DMAIN, LOGL_DEBUG, "Tx %s/0x%08x: USSD Result(%d, %s, '%s')\n", imsi, session_id,
		invoke_id, final ? "END" : "CONTINUE", text);
	OSMO_ASSERT(ss_msg);
	return euse_tx_ss(gsupc, imsi, session_id, OSMO_GSUP_MSGT_PROC_SS_RESULT, final, ss_msg);
}

static int euse_rx_proc_ss_req(struct osmo_gsup_client *gsupc, const struct osmo_gsup_message *gsup)
{
	char buf[GSM0480_USSD_7BIT_STRING_LEN+1];
	struct ss_request req = {0};

	if (gsup->ss_info && gsup->ss_info_len) {
		if (gsm0480_parse_facility_ie(gsup->ss_info, gsup->ss_info_len, &req)) {
			return euse_tx_ussd_reject(gsupc, gsup->imsi, gsup->session_id, -1,
						   GSM_0480_PROBLEM_CODE_TAG_GENERAL,
						   GSM_0480_GEN_PROB_CODE_BAD_STRUCTURE);
		}
	}

	LOGP(DMAIN, LOGL_INFO, "Rx %s/0x%08x: USSD SessionState=%s, OpCode=%s, '%s'\n", gsup->imsi,
		gsup->session_id, osmo_gsup_session_state_name(gsup->session_state),
		gsm0480_op_code_name(req.opcode), req.ussd_text);

	/* we only handle single-request-response USSD in this demo */
	if (gsup->session_state != OSMO_GSUP_SESSION_STATE_BEGIN) {
		return euse_tx_ussd_reject(gsupc, gsup->imsi, gsup->session_id, req.invoke_id,
					   GSM_0480_PROBLEM_CODE_TAG_GENERAL,
					   GSM_0480_GEN_PROB_CODE_UNRECOGNISED);
	}

	snprintf(buf, sizeof(buf), "You sent \"%s\"", req.ussd_text);
	return euse_tx_ussd_resp_7bit(gsupc, gsup->imsi, gsup->session_id, true, req.invoke_id, buf);
}

static int gsupc_read_cb(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	struct osmo_gsup_message gsup_msg = {0};
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup_msg);
	if (rc < 0) {
		LOGP(DMAIN, LOGL_ERROR, "Error decoding GSUP: %s\n", msgb_hexdump(msg));
		return rc;
	}
	DEBUGP(DMAIN, "Rx GSUP %s: %s\n", osmo_gsup_message_type_name(gsup_msg.message_type),
		msgb_hexdump(msg));

	switch (gsup_msg.message_type) {
	case OSMO_GSUP_MSGT_PROC_SS_REQUEST:
	case OSMO_GSUP_MSGT_PROC_SS_RESULT:
		euse_rx_proc_ss_req(gsupc, &gsup_msg);
		break;
	case OSMO_GSUP_MSGT_PROC_SS_ERROR:
		break;
	default:
		LOGP(DMAIN, LOGL_DEBUG, "Unhandled GSUP message type %s\n",
			osmo_gsup_message_type_name(gsup_msg.message_type));
		break;
	}

	msgb_free(msg);
	return 0;
}


static struct log_info_cat default_categories[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.description = "Main Program",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info gsup_log_info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

static void print_usage(void)
{
	printf("Usage: osmo-euse-demo [hlr-ip [hlr-gsup-port]]\n");
}

int main(int argc, char **argv)
{
	char *server_host = "127.0.0.1";
	uint16_t server_port = OSMO_GSUP_PORT;
	void *ctx = talloc_named_const(NULL, 0, "demo-euse");

	osmo_init_logging2(ctx, &gsup_log_info);

	printf("argc=%d\n", argc);

	if (argc > 1) {
		if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
			print_usage();
			exit(0);
		} else
			server_host = argv[1];
	}
	if (argc > 2)
		server_port = atoi(argv[2]);

	g_gc = osmo_gsup_client_create(ctx, "EUSE-foobar", server_host, server_port, gsupc_read_cb, NULL);

	while (1) {
		osmo_select_main(0);
	}

	exit(0);
}

