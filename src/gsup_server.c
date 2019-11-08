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

#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm23003.h>

#include "hlr.h"
#include "gsup_server.h"
#include "gsup_router.h"

struct msgb *osmo_gsup_msgb_alloc(const char *label)
{
	struct msgb *msg = msgb_alloc_headroom(1024+16, 16, label);
	OSMO_ASSERT(msg);
	return msg;
}

static void osmo_gsup_server_send(struct osmo_gsup_conn *conn,
			     int proto_ext, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, proto_ext);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_server_conn_send(conn->conn, msg_tx);
}

int osmo_gsup_conn_send(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	if (!conn) {
		msgb_free(msg);
		return -ENOTCONN;
	}

	osmo_gsup_server_send(conn, IPAC_PROTO_EXT_GSUP, msg);

	return 0;
}

/* Only for requests originating here. When answering to a remote request, rather use osmo_gsup_req_respond() or
 * osmo_gsup_req_respond_err(). */
int osmo_gsup_conn_enc_send(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup)
{
	struct msgb *msg = osmo_gsup_msgb_alloc("GSUP Tx");
	int rc;
	rc = osmo_gsup_encode(msg, gsup);
	if (rc) {
		LOG_GSUP_CONN(conn, LOGL_ERROR, "Cannot encode GSUP: %s\n",
			      osmo_gsup_message_type_name(gsup->message_type));
		msgb_free(msg);
		return -EINVAL;
	}

	LOG_GSUP_CONN(conn, LOGL_DEBUG, "Tx: %s\n", osmo_gsup_message_type_name(gsup->message_type));
	rc = osmo_gsup_conn_send(conn, msg);
	if (rc)
		LOG_GSUP_CONN(conn, LOGL_ERROR, "Unable to send: %s\n",
			      osmo_gsup_message_type_name(gsup->message_type));
	return rc;
}

struct osmo_gsup_req *osmo_gsup_req_new(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	static unsigned int next_req_nr = 1;
	struct osmo_gsup_req *req;
	struct osmo_gsup_message gsup_err;
	int rc;

	if (!msgb_l2(msg) || !msgb_l2len(msg)) {
		LOGP(DLGSUP, LOGL_ERROR, "Rx GSUP message: missing or empty L2 data\n");
		msgb_free(msg);
		return NULL;
	}

	req = talloc_zero(conn->server, struct osmo_gsup_req);
	OSMO_ASSERT(req);
	req->nr = next_req_nr++;
	req->server = conn->server;
	req->msg = msg;
	req->source_name = conn->peer_name;

	rc = osmo_gsup_decode(msgb_l2(req->msg), msgb_l2len(req->msg), (struct osmo_gsup_message*)&req->gsup);
	if (rc < 0) {
		LOGP(DLGSUP, LOGL_ERROR, "Rx GSUP message: cannot decode (rc=%d)\n", rc);
		osmo_gsup_req_free(req);
		return NULL;
	}

	LOG_GSUP_REQ(req, LOGL_DEBUG, "new\n");

	if (req->gsup.source_name_len) {
		if (global_title_set(&req->source_name, req->gsup.source_name, req->gsup.source_name_len)) {
			LOGP(DLGSUP, LOGL_ERROR, "cannot decode GSUP message's source_name, message is not routable\n");
			goto unroutable_error;
		}

		if (global_title_cmp(&req->source_name, &conn->peer_name)) {
			/* The source of the GSUP message is not the immediate GSUP peer, but that peer is our proxy for that
			 * source. Add it to the routes for this conn (so we can route responses back). */
			if (gsup_route_add_gt(conn, &req->source_name)) {
				LOGP(DLGSUP, LOGL_ERROR,
				     "GSUP message received from %s via peer %s, but there already exists a different"
				     " route to this source, message is not routable\n",
				     global_title_name(&req->source_name),
				     global_title_name(&conn->peer_name));
				goto unroutable_error;
			}

			req->via_proxy = conn->peer_name;
		}
	}

	if (!osmo_imsi_str_valid(req->gsup.imsi)) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "invalid IMSI: %s",
					  osmo_quote_str(req->gsup.imsi, -1));
		return NULL;
	}

	return req;

unroutable_error:
	gsup_err = (struct osmo_gsup_message){
		.message_type = OSMO_GSUP_MSGT_E_ROUTING_ERROR,
		.destination_name = req->gsup.destination_name,
		.destination_name_len = req->gsup.destination_name_len,
		.source_name = req->gsup.source_name,
		.source_name_len = req->gsup.source_name_len,
	};
	osmo_gsup_set_reply(&req->gsup, &gsup_err);
	osmo_gsup_conn_enc_send(conn, &gsup_err);
	osmo_gsup_req_free(req);
	return NULL;
}

void _osmo_gsup_req_free(struct osmo_gsup_req *req)
{
	if (req->msg)
		msgb_free(req->msg);
	talloc_free(req);
}

int osmo_gsup_req_respond_nonfinal(struct osmo_gsup_req *req, struct osmo_gsup_message *response)
{
	struct osmo_gsup_conn *conn;
	struct msgb *msg;
	int rc;

	conn = gsup_route_find_gt(req->server, &req->source_name);
	if (!conn) {
		LOG_GSUP_REQ(req, LOGL_ERROR, "GSUP client that sent this request was disconnected, cannot respond\n");
		return -EINVAL;
	}

	osmo_gsup_set_reply(&req->gsup, response);

	msg = osmo_gsup_msgb_alloc("GSUP response");
	rc = osmo_gsup_encode(msg, response);
	if (rc) {
		LOG_GSUP_REQ(req, LOGL_ERROR, "Unable to encode response: %s\n",
			     osmo_gsup_message_type_name(response->message_type));
		return -EINVAL;
	}

	LOG_GSUP_REQ(req, LOGL_DEBUG, "Tx response: %s\n", osmo_gsup_message_type_name(response->message_type));

	rc = osmo_gsup_conn_send(conn, msg);
	if (rc)
		LOG_GSUP_REQ(req, LOGL_ERROR, "Unable to send response: %s\n",
			     osmo_gsup_message_type_name(response->message_type));
	return rc;
}

/* Make sure the response message contains all IEs that are required to be a valid response for the received GSUP
 * request, and send back to the requesting peer. */
int osmo_gsup_req_respond(struct osmo_gsup_req *req, struct osmo_gsup_message *response)
{
	int rc = osmo_gsup_req_respond_nonfinal(req, response);
	osmo_gsup_req_free(req);
	return rc;
}

int osmo_gsup_req_respond_msgt(struct osmo_gsup_req *req, enum osmo_gsup_message_type message_type)
{
	struct osmo_gsup_message response = {
		.message_type = message_type,
	};
	return osmo_gsup_req_respond(req, &response);
}

#define osmo_gsup_req_respond_err(REQ, CAUSE, FMT, args...) do { \
		LOG_GSUP_REQ(REQ, LOGL_ERROR, "%s: " FMT "\n", \
			     get_value_string(gsm48_gmm_cause_names, CAUSE), ##args); \
		_osmo_gsup_req_respond_err(REQ, CAUSE); \
	} while(0)
void _osmo_gsup_req_respond_err(struct osmo_gsup_req *req, enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message response = {
		.cause = cause,
		.message_type = OSMO_GSUP_TO_MSGT_ERROR(req->gsup.message_type),
	};

	/* No need to answer if we couldn't parse an ERROR message type, only REQUESTs need an error reply. */
	if (!OSMO_GSUP_IS_MSGT_REQUEST(req->gsup.message_type)) {
		osmo_gsup_req_free(req);
		return;
	}

	if (req->gsup.session_state != OSMO_GSUP_SESSION_STATE_NONE)
		response.session_state = OSMO_GSUP_SESSION_STATE_END;

	osmo_gsup_req_respond(req, &response);
}

/* Encode an error reponse to the given GSUP message with the given cause.
 * Determine the error message type via OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type).
 * Only send an error response if the original message is a Request message.
 * On failure, log an error, but don't return anything: if an error occurs while trying to report an earlier error,
 * there is nothing we can do really except log the error (there are no callers that would use the return code).
 */
void osmo_gsup_conn_send_err_reply(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup_orig,
				   enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply;
	struct msgb *msg_out;
	int rc;

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
	osmo_gsup_set_reply(gsup_orig, &gsup_reply);

	if (gsup_orig->session_state != OSMO_GSUP_SESSION_STATE_NONE)
		gsup_reply.session_state = OSMO_GSUP_SESSION_STATE_END;

	msg_out = osmo_gsup_msgb_alloc("GSUP ERR response");
	rc = osmo_gsup_encode(msg_out, &gsup_reply);
	if (rc) {
		LOGP(DLGSUP, LOGL_ERROR, "%s: Unable to encode error response %s (rc=%d)\n",
		     osmo_quote_str(gsup_orig->imsi, -1), osmo_gsup_message_type_name(gsup_reply.message_type),
		     rc);
		return;
	}

	LOGP(DLGSUP, LOGL_DEBUG, "%s: GSUP tx %s\n",
	     osmo_quote_str(gsup_orig->imsi, -1), osmo_gsup_message_type_name(gsup_reply.message_type));

	rc = osmo_gsup_conn_send(conn, msg_out);
	if (rc)
		LOGP(DLGSUP, LOGL_ERROR, "%s: Unable to send error response %s (rc=%d)\n",
		     osmo_quote_str(gsup_orig->imsi, -1), osmo_gsup_message_type_name(gsup_reply.message_type),
		     rc);
}

static int osmo_gsup_conn_oap_handle(struct osmo_gsup_conn *conn,
				struct msgb *msg_rx)
{
#if 0
	int rc;
	struct msgb *msg_tx;
	rc = oap_handle(&conn->oap_state, msg_rx, &msg_tx);
	msgb_free(msg_rx);
	if (rc < 0)
		return rc;

	if (msg_tx)
		osmo_gsup_conn_send(conn, IPAC_PROTO_EXT_OAP, msg_tx);
#endif
	return 0;
}

/* Data from a given client has arrived over the socket */
static int osmo_gsup_server_read_cb(struct ipa_server_conn *conn,
			       struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct osmo_gsup_conn *clnt = (struct osmo_gsup_conn *)conn->data;
	int rc;

	msg->l2h = &hh->data[0];

	if (hh->proto == IPAC_PROTO_IPACCESS) {
		rc = ipa_server_conn_ccm(conn, msg);
		if (rc < 0) {
			/* conn is already invalid here! */
			return -1;
		}
		msgb_free(msg);
		return 0;
	}

	if (hh->proto != IPAC_PROTO_OSMO) {
		LOGP(DLGSUP, LOGL_NOTICE, "Unsupported IPA stream ID 0x%02x\n",
			hh->proto);
		goto invalid;
	}

	if (!he || msgb_l2len(msg) < sizeof(*he)) {
		LOGP(DLGSUP, LOGL_NOTICE, "short IPA message\n");
		goto invalid;
	}

	msg->l2h = &he->data[0];

	if (he->proto == IPAC_PROTO_EXT_GSUP) {
		OSMO_ASSERT(clnt->server->read_cb != NULL);
		clnt->server->read_cb(clnt, msg);
		/* expecting read_cb() to free msg */
	} else if (he->proto == IPAC_PROTO_EXT_OAP) {
		return osmo_gsup_conn_oap_handle(clnt, msg);
		/* osmo_gsup_client_oap_handle frees msg */
	} else {
		LOGP(DLGSUP, LOGL_NOTICE, "Unsupported IPA Osmo Proto 0x%02x\n",
			hh->proto);
		goto invalid;
	}

	return 0;

invalid:
	LOGP(DLGSUP, LOGL_NOTICE,
	     "GSUP received an invalid IPA message from %s:%d: %s\n",
	     conn->addr, conn->port, osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));
	msgb_free(msg);
	return -1;

}

static void osmo_tlvp_dump(const struct tlv_parsed *tlvp,
			   int subsys, int level)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tlvp->lv); i++) {
		if (!TLVP_PRESENT(tlvp, i))
			continue;

		LOGP(subsys, level, "%u: %s\n", i,
			TLVP_VAL(tlvp, i));
		LOGP(subsys, level, "%u: %s\n", i,
			osmo_hexdump(TLVP_VAL(tlvp, i),
				     TLVP_LEN(tlvp, i)));
	}
}

/* FIXME: should this be parrt of ipas_server handling, not GSUP? */
static void tlvp_copy(void *ctx, struct tlv_parsed *out, const struct tlv_parsed *in)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(out->lv); i++) {
		if (!TLVP_PRESENT(in, i)) {
			if (TLVP_PRESENT(out, i)) {
				talloc_free((void *) out->lv[i].val);
				out->lv[i].val = NULL;
				out->lv[i].len = 0;
			}
			continue;
		}
		out->lv[i].val = talloc_memdup(ctx, in->lv[i].val, in->lv[i].len);
		out->lv[i].len = in->lv[i].len;
	}
}

int osmo_gsup_conn_ccm_get(const struct osmo_gsup_conn *clnt, uint8_t **addr,
			   uint8_t tag)
{
	if (!TLVP_PRESENT(&clnt->ccm, tag))
		return -ENODEV;
	*addr = (uint8_t *) TLVP_VAL(&clnt->ccm, tag);

	return TLVP_LEN(&clnt->ccm, tag);
}

static int osmo_gsup_server_ccm_cb(struct ipa_server_conn *conn,
				   struct msgb *msg, struct tlv_parsed *tlvp,
				   struct ipaccess_unit *unit)
{
	struct osmo_gsup_conn *clnt = (struct osmo_gsup_conn *)conn->data;
	uint8_t *addr = NULL;
	size_t addr_len;

	LOGP(DLGSUP, LOGL_INFO, "CCM Callback\n");

	/* FIXME: should this be parrt of ipas_server handling, not
	 * GSUP? */
	tlvp_copy(clnt, &clnt->ccm, tlvp);
	osmo_tlvp_dump(tlvp, DLGSUP, LOGL_INFO);

	addr_len = osmo_gsup_conn_ccm_get(clnt, &addr, IPAC_IDTAG_SERNR);
	if (addr_len <= 0) {
		LOGP(DLGSUP, LOGL_ERROR, "GSUP client %s:%u has no %s IE and"
		     " cannot be routed\n",
		     conn->addr, conn->port,
		     ipa_ccm_idtag_name(IPAC_IDTAG_SERNR));
		return -EINVAL;
	}

	global_title_set(&clnt->peer_name, addr, addr_len);
	gsup_route_add_gt(clnt, &clnt->peer_name);
	return 0;
}

static void osmo_gsup_conn_free(struct osmo_gsup_conn *conn)
{
	gsup_route_del_conn(conn);
	llist_del(&conn->list);
	talloc_free(conn);
}

static int osmo_gsup_server_closed_cb(struct ipa_server_conn *conn)
{
	struct osmo_gsup_conn *clnt = (struct osmo_gsup_conn *)conn->data;

	LOGP(DLGSUP, LOGL_INFO, "Lost GSUP client %s:%d\n",
		conn->addr, conn->port);

	osmo_gsup_conn_free(clnt);
	return 0;
}

/* Add conn to the clients list in a way that conn->auc_3g_ind takes the lowest
 * unused integer and the list of clients remains sorted by auc_3g_ind.
 * Keep this function non-static to allow linking in a unit test. */
void osmo_gsup_server_add_conn(struct llist_head *clients,
			       struct osmo_gsup_conn *conn)
{
	struct osmo_gsup_conn *c;
	struct osmo_gsup_conn *prev_conn;

	c = llist_first_entry_or_null(clients, struct osmo_gsup_conn, list);

	/* Is the first index, 0, unused? */
	if (!c || c->auc_3g_ind > 0) {
		conn->auc_3g_ind = 0;
		llist_add(&conn->list, clients);
		return;
	}

	/* Look for a gap later on */
	prev_conn = NULL;
	llist_for_each_entry(c, clients, list) {
		/* skip first item, we know it has auc_3g_ind == 0. */
		if (!prev_conn) {
			prev_conn = c;
			continue;
		}
		if (c->auc_3g_ind > prev_conn->auc_3g_ind + 1)
			break;
		prev_conn = c;
	}

	OSMO_ASSERT(prev_conn);

	conn->auc_3g_ind = prev_conn->auc_3g_ind + 1;
	llist_add(&conn->list, &prev_conn->list);
}

/* a client has connected to the server socket and we have accept()ed it */
static int osmo_gsup_server_accept_cb(struct ipa_server_link *link, int fd)
{
	struct osmo_gsup_conn *conn;
	struct osmo_gsup_server *gsups =
		(struct osmo_gsup_server *) link->data;
	int rc;

	conn = talloc_zero(gsups, struct osmo_gsup_conn);
	OSMO_ASSERT(conn);

	conn->conn = ipa_server_conn_create(gsups, link, fd,
					   osmo_gsup_server_read_cb,
					   osmo_gsup_server_closed_cb, conn);
	OSMO_ASSERT(conn->conn);
	conn->conn->ccm_cb = osmo_gsup_server_ccm_cb;

	/* link data structure with server structure */
	conn->server = gsups;
	osmo_gsup_server_add_conn(&gsups->clients, conn);

	LOGP(DLGSUP, LOGL_INFO, "New GSUP client %s:%d (IND=%u)\n",
	     conn->conn->addr, conn->conn->port, conn->auc_3g_ind);

	/* request the identity of the client */
	rc = ipa_ccm_send_id_req(fd);
	if (rc < 0)
		goto failed;
#if 0
	rc = oap_init(&gsups->oap_config, &conn->oap_state);
	if (rc != 0)
		goto failed;
#endif
	return 0;
failed:
	ipa_server_conn_destroy(conn->conn);
	return -1;
}

struct osmo_gsup_server *
osmo_gsup_server_create(void *ctx, const char *ip_addr, uint16_t tcp_port,
			osmo_gsup_read_cb_t read_cb, void *priv)
{
	struct osmo_gsup_server *gsups;
	int rc;

	gsups = talloc_zero(ctx, struct osmo_gsup_server);
	OSMO_ASSERT(gsups);

	INIT_LLIST_HEAD(&gsups->clients);
	INIT_LLIST_HEAD(&gsups->routes);

	gsups->link = ipa_server_link_create(gsups,
					/* no e1inp */ NULL,
					ip_addr, tcp_port,
					osmo_gsup_server_accept_cb,
					gsups);
	if (!gsups->link)
		goto failed;

	gsups->read_cb = read_cb;
	gsups->priv = priv;

	rc = ipa_server_link_open(gsups->link);
	if (rc < 0)
		goto failed;

	return gsups;

failed:
	osmo_gsup_server_destroy(gsups);
	return NULL;
}

void osmo_gsup_server_destroy(struct osmo_gsup_server *gsups)
{
	if (gsups->link) {
		ipa_server_link_close(gsups->link);
		ipa_server_link_destroy(gsups->link);
		gsups->link = NULL;
	}
	talloc_free(gsups);
}

/* Set GSUP message's pdp_infos[0] to a wildcard APN.
 * Use the provided apn_buf to store the produced APN data. This must remain valid until
 * osmo_gsup_encode() is done. Return 0 if an entry was added, -ENOMEM if the provided buffer is too
 * small. */
int osmo_gsup_configure_wildcard_apn(struct osmo_gsup_message *gsup,
				     uint8_t *apn_buf, size_t apn_buf_size)
{
	int l;

	l = osmo_apn_from_str(apn_buf, apn_buf_size, "*");
	if (l <= 0)
		return -ENOMEM;

	gsup->pdp_infos[0].apn_enc = apn_buf;
	gsup->pdp_infos[0].apn_enc_len = l;
	gsup->pdp_infos[0].have_info = 1;
	gsup->num_pdp_infos = 1;
	/* FIXME: use real value: */
	gsup->pdp_infos[0].context_id = 1;

	return 0;
}


/**
 * Populate a gsup message structure with an Insert Subscriber Data Message.
 * All required memory buffers for data pointed to by pointers in struct omso_gsup_message
 * must be allocated by the caller and should have the same lifetime as the gsup parameter.
 *
 * \param[out] gsup  The gsup message to populate.
 * \param[in] imsi  The subscriber's IMSI.
 * \param[in] msisdn The subscriber's MSISDN.
 * \param[out] msisdn_enc A buffer large enough to store the MSISDN in encoded form.
 * \param[in] msisdn_enc_size Size of the buffer (must be >= OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN).
 * \param[out] apn_buf A buffer large enough to store an APN (required if cn_domain is OSMO_GSUP_CN_DOMAIN_PS).
 * \param[in] apn_buf_size Size of APN buffer (must be >= APN_MAXLEN).
 * \param[in] cn_domain The CN Domain of the subscriber connection.
 * \returns 0 on success, and negative on error.
 */
int osmo_gsup_create_insert_subscriber_data_msg(struct osmo_gsup_message *gsup, const char *imsi, const char *msisdn,
                                               uint8_t *msisdn_enc, size_t msisdn_enc_size,
                                               uint8_t *apn_buf, size_t apn_buf_size,
                                               enum osmo_gsup_cn_domain cn_domain)
{
       int len;

       OSMO_ASSERT(gsup);
       *gsup = (struct osmo_gsup_message){
	       .message_type = OSMO_GSUP_MSGT_INSERT_DATA_REQUEST,
       };

       osmo_strlcpy(gsup->imsi, imsi, sizeof(gsup->imsi));

       if (msisdn_enc_size < OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN)
               return -ENOSPC;

       OSMO_ASSERT(msisdn_enc);
       len = gsm48_encode_bcd_number(msisdn_enc, msisdn_enc_size, 0, msisdn);
       if (len < 1) {
               LOGP(DLGSUP, LOGL_ERROR, "%s: Error: cannot encode MSISDN '%s'\n", imsi, msisdn);
               return -ENOSPC;
       }
       gsup->msisdn_enc = msisdn_enc;
       gsup->msisdn_enc_len = len;

       #pragma message "FIXME: deal with encoding the following data: gsup.hlr_enc"

       gsup->cn_domain = cn_domain;
       if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS) {
               OSMO_ASSERT(apn_buf_size >= APN_MAXLEN);
               OSMO_ASSERT(apn_buf);
               /* FIXME: PDP infos - use more fine-grained access control
                  instead of wildcard APN */
               osmo_gsup_configure_wildcard_apn(gsup, apn_buf, apn_buf_size);
       }

       return 0;
}
