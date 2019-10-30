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

static LLIST_HEAD(remote_hlrs);

#define LOG_GSUPC(gsupc, level, fmt, args...) \
	LOGP(DDGSM, level, "HLR Proxy: GSUP from %s:%u: " fmt, (gsupc)->link->addr, (gsupc)->link->port, ##args)

#define LOG_GSUP_MSG(gsupc, gsup_msg, level, fmt, args...) \
	LOG_GSUPC(gsupc, level, "%s: " fmt, osmo_gsup_message_type_name((gsup_msg)->message_type), ##args)


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

static int remote_hlr_rx(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	struct osmo_gsup_message gsup;
	struct osmo_gsup_conn *msc_conn;
	int rc;

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOG_GSUPC(gsupc, LOGL_ERROR, "Failed to decode GSUP message: '%s' (%d) [ %s]\n",
			  get_value_string(gsm48_gmm_cause_names, -rc), -rc, osmo_hexdump(msg->data, msg->len));
		return rc;
	}

	if (!gsup.imsi[0]) {
		LOG_GSUP_MSG(gsupc, &gsup, LOGL_ERROR, "Failed to decode GSUP message: missing IMSI\n");
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	/* Since this is a proxy link to a remote osmo-msc, we are acting on behalf of a local MSC, and need to know the
	 * routing name of that local MSC. We have sent it to the remote HLR as source_name, and we're required to get
	 * it back as destination_name. */
	if (!gsup.destination_name || !gsup.destination_name_len) {
		LOG_GSUP_MSG(gsupc, &gsup, LOGL_ERROR, "message lacks Destination Name IE, cannot route to MSC.\n");
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	/* Route to MSC that we're proxying for */
	msc_conn = gsup_route_find(g_hlr->gs, gsup.destination_name, gsup.destination_name_len);
	if (!msc_conn) {
		LOG_GSUP_MSG(gsupc, &gsup, LOGL_ERROR, "Destination MSC unreachable: %s\n",
			     osmo_quote_str((char*)gsup.destination_name, gsup.destination_name_len));
		remote_hlr_err_reply(gsupc, &gsup, GMM_CAUSE_MSC_TEMP_NOTREACH);
		return -GMM_CAUSE_MSC_TEMP_NOTREACH;
	}

	/* The outgoing message needs to be a separate msgb, because osmo_gsup_conn_send() takes ownership of it. */
	return osmo_gsup_conn_send(msc_conn, msgb_copy(msg, "GSUP proxy to MSC"));
}

struct remote_hlr *remote_hlr_get(const struct osmo_sockaddr_str *addr, bool create)
{
	struct remote_hlr *rh;

	llist_for_each_entry(rh, &remote_hlrs, entry) {
		if (!osmo_sockaddr_str_cmp(&rh->addr, addr))
			return rh;
	}

	if (!create)
		return NULL;

	/* Doesn't exist yet, create a GSUP client to remote HLR. */
	rh = talloc_zero(dgsm_ctx, struct remote_hlr);
	*rh = (struct remote_hlr){
		.addr = *addr,
		.gsupc = osmo_gsup_client_create2(rh, &g_hlr->gsup_proxy.gsup_client_name,
						  addr->ip, addr->port,
						  remote_hlr_rx,
						  NULL),
	};
	if (!rh->gsupc) {
		talloc_free(rh);
		return NULL;
	}
	return rh;
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

int remote_hlr_gsup_send(struct remote_hlr *remote_hlr, const struct osmo_gsup_message *gsup)
{
	struct msgb *msg = osmo_gsup_msgb_alloc("GSUP proxy to remote HLR");
	osmo_gsup_encode(msg, gsup);
	return remote_hlr_msgb_send(remote_hlr, msg);
}

