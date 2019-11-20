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

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/gsup_server.h>
#include <osmocom/hlr/gsup_router.h>
#include <osmocom/hlr/remote_hlr.h>
#include <osmocom/hlr/proxy.h>

static LLIST_HEAD(remote_hlrs);

static void remote_hlr_err_reply(struct remote_hlr *rh, const struct osmo_gsup_message *gsup_orig,
				 enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply;

	/* No need to answer if we couldn't parse an ERROR message type, only REQUESTs need an error reply. */
	if (!OSMO_GSUP_IS_MSGT_REQUEST(gsup_orig->message_type))
		return;

	gsup_reply = (struct osmo_gsup_message){
		.cause = cause,
		.message_type = OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type),
		.message_class = gsup_orig->message_class,

		/* RP-Message-Reference is mandatory for SM Service */
		.sm_rp_mr = gsup_orig->sm_rp_mr,
	};

	OSMO_STRLCPY_ARRAY(gsup_reply.imsi, gsup_orig->imsi);

	/* For SS/USSD, it's important to keep both session state and ID IEs */
	if (gsup_orig->session_state != OSMO_GSUP_SESSION_STATE_NONE) {
		gsup_reply.session_state = OSMO_GSUP_SESSION_STATE_END;
		gsup_reply.session_id = gsup_orig->session_id;
	}

	if (osmo_gsup_client_enc_send(rh->gsupc, &gsup_reply))
		LOGP(DLGSUP, LOGL_ERROR, "Failed to send Error reply (imsi=%s)\n",
		     osmo_quote_str(gsup_orig->imsi, -1));
}

/* We are receiving a GSUP message from a remote HLR to go back to a local MSC.
 * The local MSC shall be indicated by gsup.destination_name. */
static int remote_hlr_rx(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	struct remote_hlr *rh = gsupc->data;
	const struct proxy_subscr *proxy_subscr;
	struct osmo_gsup_message gsup;
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOG_REMOTE_HLR(rh, LOGL_ERROR, "Failed to decode GSUP message: '%s' (%d) [ %s]\n",
			       get_value_string(gsm48_gmm_cause_names, -rc),
			       -rc, osmo_hexdump(msg->data, msg->len));
		return rc;
	}

	if (!osmo_imsi_str_valid(gsup.imsi)) {
		LOG_REMOTE_HLR_MSG(rh, &gsup, LOGL_ERROR, "Invalid IMSI\n");
		remote_hlr_err_reply(rh, &gsup, GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	proxy_subscr = proxy_subscr_get_by_imsi(g_hlr->gs->proxy, gsup.imsi);
	if (!proxy_subscr) {
		LOG_REMOTE_HLR_MSG(rh, &gsup, LOGL_ERROR, "No proxy entry for this IMSI\n");
		remote_hlr_err_reply(rh, &gsup, GMM_CAUSE_NET_FAIL);
		return -GMM_CAUSE_NET_FAIL;
	}

	rc = proxy_subscr_forward_to_vlr(g_hlr->gs->proxy, proxy_subscr, &gsup, rh);
	if (rc) {
		LOG_REMOTE_HLR_MSG(rh, &gsup, LOGL_ERROR, "Failed to forward GSUP message towards VLR\n");
		remote_hlr_err_reply(rh, &gsup, GMM_CAUSE_NET_FAIL);
		return -GMM_CAUSE_NET_FAIL;
	}
	return 0;
}

static bool remote_hlr_up_yield(struct proxy *proxy, const struct proxy_subscr *proxy_subscr, void *data)
{
	struct remote_hlr *remote_hlr = data;
	proxy_subscr_remote_hlr_up(proxy, proxy_subscr, remote_hlr);
	return true;
}

static bool remote_hlr_up_down(struct osmo_gsup_client *gsupc, bool up)
{
	struct remote_hlr *remote_hlr = gsupc->data;
	if (!up) {
		LOG_REMOTE_HLR(remote_hlr, LOGL_NOTICE, "link to remote HLR is down, removing GSUP client\n");
		remote_hlr_destroy(remote_hlr);
		return false;
	}

	LOG_REMOTE_HLR(remote_hlr, LOGL_NOTICE, "link up\n");
	proxy_subscrs_get_by_remote_hlr(g_hlr->gs->proxy, &remote_hlr->addr, remote_hlr_up_yield, remote_hlr);
	return true;
}

struct remote_hlr *remote_hlr_get(const struct osmo_sockaddr_str *addr, bool create)
{
	struct remote_hlr *rh;
	struct osmo_gsup_client_config cfg;

	llist_for_each_entry(rh, &remote_hlrs, entry) {
		if (!osmo_sockaddr_str_cmp(&rh->addr, addr))
			return rh;
	}

	if (!create)
		return NULL;

	/* Doesn't exist yet, create a GSUP client to remote HLR. */
	cfg = (struct osmo_gsup_client_config){
		.ipa_dev = &g_hlr->gsup_unit_name,
		.ip_addr = addr->ip,
		.tcp_port = addr->port,
		.oapc_config = NULL,
		.read_cb = remote_hlr_rx,
		.up_down_cb = remote_hlr_up_down,
		.data = rh,
	};
	rh = talloc_zero(dgsm_ctx, struct remote_hlr);
	OSMO_ASSERT(rh);
	*rh = (struct remote_hlr){
		.addr = *addr,
		.gsupc = osmo_gsup_client_create3(rh, &cfg),
	};
	if (!rh->gsupc) {
		LOGP(DDGSM, LOGL_ERROR,
		     "Failed to establish connection to remote HLR " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(addr));
		talloc_free(rh);
		return NULL;
	}
	rh->gsupc->data = rh;
	llist_add(&rh->entry, &remote_hlrs);
	return rh;
}

void remote_hlr_destroy(struct remote_hlr *remote_hlr)
{
	osmo_gsup_client_destroy(remote_hlr->gsupc);
	remote_hlr->gsupc = NULL;
	llist_del(&remote_hlr->entry);
	talloc_free(remote_hlr);
}

/* This function takes ownership of the msg, do not free it after passing to this function. */
int remote_hlr_msgb_send(struct remote_hlr *remote_hlr, struct msgb *msg)
{
	int rc = osmo_gsup_client_send(remote_hlr->gsupc, msg);
	if (rc) {
		LOGP(DDGSM, LOGL_ERROR, "Failed to send GSUP message to " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&remote_hlr->addr));
	}
	return rc;
}

/* A GSUP message was received from the MS/MSC side, forward it to the remote HLR. */
void remote_hlr_gsup_forward_to_remote_hlr(struct remote_hlr *remote_hlr, struct osmo_gsup_req *req)
{
	int rc;
	struct msgb *msg;
	/* To forward to a remote HLR, we need to indicate the source MSC's name in the Source Name IE to make sure the
	 * reply can be routed back. Store the sender MSC in gsup->source_name -- the remote HLR is required to return
	 * this as gsup->destination_name so that the reply gets routed to the original MSC. */
	struct osmo_gsup_message forward = req->gsup;

	if (req->source_name.type != OSMO_GSUP_PEER_ID_IPA_NAME) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "Unsupported GSUP peer id type: %s",
					  osmo_gsup_peer_id_type_name(req->source_name.type));
		return;
	}
	forward.source_name = req->source_name.ipa_name.val;
	forward.source_name_len = req->source_name.ipa_name.len;

	msg = osmo_gsup_msgb_alloc("GSUP proxy to remote HLR");
	rc = osmo_gsup_encode(msg, &forward);
	if (rc) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "Failed to encode GSUP message for forwarding");
		return;
	}
	remote_hlr_msgb_send(remote_hlr, msg);
	osmo_gsup_req_free(req);
}
