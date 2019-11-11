#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/gsupclient/gsup_client.h>
#include "logging.h"
#include "hlr.h"
#include "gsup_server.h"
#include "gsup_router.h"
#include "dgsm.h"
#include "remote_hlr.h"
#include "proxy.h"

static LLIST_HEAD(remote_hlrs);

void remote_hlr_err_reply(struct osmo_gsup_client *gsupc, const struct osmo_gsup_message *gsup_orig,
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

	if (osmo_gsup_client_enc_send(gsupc, &gsup_reply))
		LOGP(DLGSUP, LOGL_ERROR, "Failed to send Error reply (imsi=%s)\n",
		     osmo_quote_str(gsup_orig->imsi, -1));
}

/* We are receiving back a GSUP message from a remote HLR to go back to a local MSC.
 * The local MSC shall be indicated by gsup.destination_name. */
static int remote_hlr_rx(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	struct osmo_gsup_message gsup;
	struct osmo_gsup_conn *vlr_conn;
	const struct proxy_subscr *proxy_subscr;
	struct global_title destination;
	struct msgb *gsup_copy;
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOG_GSUPC(gsupc, LOGL_ERROR, "Failed to decode GSUP message: '%s' (%d) [ %s]\n",
			  get_value_string(gsm48_gmm_cause_names, -rc), -rc, osmo_hexdump(msg->data, msg->len));
		return rc;
	}

	if (!gsup.imsi[0]) {
		LOG_GSUPC_MSG(gsupc, &gsup, LOGL_ERROR, "Failed to decode GSUP message: missing IMSI\n");
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	if (!gsup.destination_name || !gsup.destination_name_len
	    || global_title_set(&destination, gsup.destination_name, gsup.destination_name_len)) {
		LOG_GSUPC_MSG(gsupc, &gsup, LOGL_ERROR, "no valid Destination Name IE, cannot route to VLR.\n");
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	proxy_subscr = proxy_subscr_get_by_imsi(g_hlr->proxy, gsup.imsi);
	if (!proxy_subscr) {
		LOG_GSUPC_MSG(gsupc, &gsup, LOGL_ERROR, "Cannot route, no GSUP proxy record for this IMSI\n");
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_IMSI_UNKNOWN);
		return -GMM_CAUSE_IMSI_UNKNOWN;
	}

	/* Route to MSC that we're proxying for */
	vlr_conn = gsup_route_find_gt(g_hlr->gs, &destination);
	if (!vlr_conn) {
		LOG_GSUPC_MSG(gsupc, &gsup, LOGL_ERROR, "Destination VLR unreachable: %s\n",
			      global_title_name(&destination));
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_MSC_TEMP_NOTREACH);
		return -GMM_CAUSE_MSC_TEMP_NOTREACH;
	}

	/* The outgoing message needs to be a separate msgb, because osmo_gsup_conn_send() takes ownership of it, an the
	 * gsup_client also does a msgb_free() after dispatching to this callback.
	 * We also need to strip the IPA header and have headroom. Just re-encode. */
	gsup_copy = osmo_gsup_msgb_alloc("GSUP proxy to VLR");
	if (osmo_gsup_encode(gsup_copy, &gsup)) {
		LOG_GSUPC_MSG(gsupc, &gsup, LOGL_ERROR, "Failed to re-encode GSUP message, cannot forward\n");
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_MSC_TEMP_NOTREACH);
		return -GMM_CAUSE_MSC_TEMP_NOTREACH;
	}
	return osmo_gsup_conn_send(vlr_conn, gsup_copy);
}

static bool remote_hlr_up_down(struct osmo_gsup_client *gsupc, bool up)
{
	struct remote_hlr *remote_hlr = gsupc->data;
	if (!up) {
		LOGP(DDGSM, LOGL_ERROR,
		     "link to remote HLR is down, removing GSUP client: " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&remote_hlr->addr));
		remote_hlr_destroy(remote_hlr);
		return false;
	}

	dgsm_remote_hlr_up(remote_hlr);
	return true;
}

struct remote_hlr *remote_hlr_get(const struct osmo_sockaddr_str *addr, bool create)
{
	struct remote_hlr *rh;

	llist_for_each_entry(rh, &remote_hlrs, entry) {
		if (!osmo_sockaddr_str_ip_cmp(&rh->addr, addr))
			return rh;
	}

	if (!create)
		return NULL;

	/* Doesn't exist yet, create a GSUP client to remote HLR. */
	rh = talloc_zero(dgsm_ctx, struct remote_hlr);
	OSMO_ASSERT(rh);
	*rh = (struct remote_hlr){
		.addr = *addr,
		.gsupc = osmo_gsup_client_create3(rh, &g_hlr->gsup_unit_name,
						  addr->ip, addr->port,
						  NULL,
						  remote_hlr_rx,
						  remote_hlr_up_down,
						  rh),
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

void remote_hlr_gsup_forward(struct remote_hlr *remote_hlr, struct osmo_gsup_req *req)
{
	int rc;
	struct msgb *msg = osmo_gsup_msgb_alloc("GSUP proxy to remote HLR");
	/* To forward to a remote HLR, we need to indicate the source MSC's name in the Source Name IE to make sure the
	 * reply can be routed back. Store the sender MSC in gsup->source_name -- the remote HLR is required to return
	 * this as gsup->destination_name so that the reply gets routed to the original MSC. */
	struct osmo_gsup_message forward = req->gsup;
	forward.source_name = req->source_name.val;
	forward.source_name_len = req->source_name.len;

	rc = osmo_gsup_encode(msg, &forward);
	if (rc) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "Failed to encode GSUP message for forwarding\n");
		return;
	}
	remote_hlr_msgb_send(remote_hlr, msg);
	osmo_gsup_req_free(req);
}
