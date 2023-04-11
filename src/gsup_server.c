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
#include <netinet/tcp.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/hlr/gsup_server.h>
#include <osmocom/hlr/gsup_router.h>
#include <osmocom/hlr/hlr.h>

#define LOG_GSUP_CONN(conn, level, fmt, args...) \
	LOGP(DLGSUP, level, "GSUP peer %s: " fmt, \
	     (conn) ? osmo_ipa_name_to_str(&(conn)->peer_name) : "NULL", ##args)

struct msgb *osmo_gsup_msgb_alloc(const char *label)
{
	struct msgb *msg = msgb_alloc_headroom(1024+512, 512, label);
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

static void gsup_server_send_req_response(struct osmo_gsup_req *req, struct osmo_gsup_message *response)
{
	struct osmo_gsup_server *server = req->cb_data;
	struct osmo_cni_peer_id *routing;
	struct osmo_gsup_conn *conn = NULL;
	struct msgb *msg = osmo_gsup_msgb_alloc("GSUP Tx");
	int rc;

	if (response->message_type == OSMO_GSUP_MSGT_ROUTING_ERROR
	    && !osmo_cni_peer_id_is_empty(&req->via_proxy)) {
		/* If a routing error occured, we need to route back via the immediate sending peer, not via the
		 * intended final recipient -- because one source of routing errors is a duplicate name for a recipient.
		 * If we resolve to req->source_name, we may send to a completely unrelated recipient. */
		routing = &req->via_proxy;
	} else {
		routing = &req->source_name;
	}
	switch (routing->type) {
	case OSMO_CNI_PEER_ID_IPA_NAME:
		conn = gsup_route_find_by_ipa_name(server, &routing->ipa_name);
		break;
	default:
		LOG_GSUP_REQ(req, LOGL_ERROR, "GSUP peer id kind not supported: %s\n",
			     osmo_cni_peer_id_type_name(routing->type));
		break;
	}

	if (!conn) {
		LOG_GSUP_REQ(req, LOGL_ERROR, "GSUP client that sent this request not found, cannot respond\n");
		msgb_free(msg);
		return;
	}

	rc = osmo_gsup_encode(msg, response);
	if (rc) {
		LOG_GSUP_REQ(req, LOGL_ERROR, "Unable to encode: {%s}\n",
			     osmo_gsup_message_to_str_c(OTC_SELECT, response));
		msgb_free(msg);
		return;
	}

	rc = osmo_gsup_conn_send(conn, msg);
	if (rc)
		LOG_GSUP_CONN(conn, LOGL_ERROR, "Unable to send: %s\n", osmo_gsup_message_to_str_c(OTC_SELECT, response));
}

struct osmo_gsup_req *osmo_gsup_conn_rx(struct osmo_gsup_conn *conn, struct msgb *msg)
{
	struct osmo_gsup_req *req;
	struct osmo_cni_peer_id cpi = {
		.type = OSMO_CNI_PEER_ID_IPA_NAME,
		.ipa_name = conn->peer_name,
	};

	req = osmo_gsup_req_new(conn->server, &cpi, msg, gsup_server_send_req_response, conn->server, NULL);
	if (!req)
		return NULL;

	if (!osmo_cni_peer_id_is_empty(&req->via_proxy)) {
		switch (req->via_proxy.type) {
		case OSMO_CNI_PEER_ID_IPA_NAME:
			break;
		default:
			LOG_GSUP_REQ(req, LOGL_ERROR, "GSUP peer id kind not supported: %s\n",
				     osmo_cni_peer_id_type_name(req->source_name.type));
			osmo_gsup_req_respond_msgt(req, OSMO_GSUP_MSGT_ROUTING_ERROR, true);
			return NULL;
		}

		/* The source of the GSUP message is not the immediate GSUP peer, but that peer is our proxy for that
		 * source. Add it to the routes for this conn (so we can route responses back). */
		if (gsup_route_add_ipa_name(conn, &req->source_name.ipa_name)) {
			LOG_GSUP_REQ(req, LOGL_ERROR,
				     "GSUP message received from %s via peer %s, but there already exists a"
				     " different route to this source, message is not routable\n",
				     osmo_cni_peer_id_to_str(&req->source_name),
				     osmo_ipa_name_to_str(&conn->peer_name));
			osmo_gsup_req_respond_msgt(req, OSMO_GSUP_MSGT_ROUTING_ERROR, true);
			return NULL;
		}
	}

	return req;
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
		msgb_free(msg);
		if (rc < 0) /* conn is already invalid here! */
			return -1;
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
	int addr_len;

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

	osmo_ipa_name_set(&clnt->peer_name, addr, addr_len);
	gsup_route_add_ipa_name(clnt, &clnt->peer_name);
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

static void update_fd_settings(int fd)
{
	int ret;
	int val;

	/*TODO: Set keepalive settings here. See OS#4312 */

	val = 1;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (ret < 0)
		LOGP(DLGSUP, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));
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
	llist_add_tail(&conn->list, &gsups->clients);

	LOGP(DLGSUP, LOGL_INFO, "New GSUP client %s:%d\n", conn->conn->addr, conn->conn->port);

	update_fd_settings(fd);

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
 * All required memory buffers for data pointed to by pointers in struct osmo_gsup_message
 * must be allocated by the caller and should have the same lifetime as the gsup parameter.
 *
 * \param[out] gsup  The gsup message to populate.
 * \param[in] imsi  The subscriber's IMSI.
 * \param[in] msisdn The subscriber's MSISDN.
 * \param[in] cn_domain The CN Domain of the subscriber connection.
 * \param[in] talloc_ctx To allocation memory for dynamic fields (msisdn, apn) in the gsup field
 * \returns 0 on success, and negative on error.
 */
int osmo_gsup_create_insert_subscriber_data_msg(struct osmo_gsup_message *gsup, const char *imsi, const char *msisdn,
						enum osmo_gsup_cn_domain cn_domain,
						void *talloc_ctx)
{
	int len;
	uint8_t *msisdn_buf = talloc_size(talloc_ctx, OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN);

	OSMO_ASSERT(gsup);
	*gsup = (struct osmo_gsup_message){
		.message_type = OSMO_GSUP_MSGT_INSERT_DATA_REQUEST,
	};

	osmo_strlcpy(gsup->imsi, imsi, sizeof(gsup->imsi));

	len = gsm48_encode_bcd_number(msisdn_buf, OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN, 0, msisdn);
	if (len < 1) {
		LOGP(DLGSUP, LOGL_ERROR, "%s: Error: cannot encode MSISDN '%s'\n", imsi, msisdn);
		return -ENOSPC;
	}
	gsup->msisdn_enc = msisdn_buf;
	gsup->msisdn_enc_len = len;

	#pragma message "FIXME: deal with encoding the following data: gsup.hlr_enc"

	gsup->cn_domain = cn_domain;
	if (gsup->cn_domain == OSMO_GSUP_CN_DOMAIN_PS) {
		if (g_hlr->ps.pdp_profile.enabled) {
			OSMO_ASSERT(g_hlr->ps.pdp_profile.num_pdp_infos <= ARRAY_SIZE(g_hlr->ps.pdp_profile.pdp_infos));
			OSMO_ASSERT(g_hlr->ps.pdp_profile.num_pdp_infos <= ARRAY_SIZE(gsup->pdp_infos));
			memcpy(gsup->pdp_infos,
			       g_hlr->ps.pdp_profile.pdp_infos,
			       sizeof(struct osmo_gsup_pdp_info) * g_hlr->ps.pdp_profile.num_pdp_infos);
			gsup->num_pdp_infos = g_hlr->ps.pdp_profile.num_pdp_infos;
		} else {
			uint8_t *apn_buf = talloc_size(talloc_ctx, APN_MAXLEN);
			osmo_gsup_configure_wildcard_apn(gsup, apn_buf, APN_MAXLEN);
		}
	}

	return 0;
}

int osmo_gsup_forward_to_local_peer(struct osmo_gsup_server *server, const struct osmo_cni_peer_id *to_peer,
				    struct osmo_gsup_req *req, struct osmo_gsup_message *modified_gsup)
{
	int rc;
	/* To forward to a remote entity (HLR, SMSC,...), we need to indicate the original source name in the Source
	 * Name IE to make sure the reply can be routed back. Store the sender in gsup->source_name -- the remote entity
	 * is required to return this as gsup->destination_name so that the reply gets routed to the original sender. */
	struct osmo_gsup_message forward = *(modified_gsup? : &req->gsup);

	if (req->source_name.type != OSMO_CNI_PEER_ID_IPA_NAME) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "Unsupported GSUP peer id type: %s",
					  osmo_cni_peer_id_type_name(req->source_name.type));
		rc = -ENOTSUP;
		goto routing_error;
	}
	forward.source_name = req->source_name.ipa_name.val;
	forward.source_name_len = req->source_name.ipa_name.len;

	if (to_peer->type != OSMO_CNI_PEER_ID_IPA_NAME) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_NET_FAIL, "Unsupported GSUP peer id type: %s",
					  osmo_cni_peer_id_type_name(to_peer->type));
		rc = -ENOTSUP;
		goto routing_error;
	}
	LOG_GSUP_REQ(req, LOGL_INFO, "Forwarding to %s\n", osmo_cni_peer_id_to_str(to_peer));
	rc = osmo_gsup_enc_send_to_ipa_name(server, &to_peer->ipa_name, &forward);
	if (rc)
		goto routing_error;
	osmo_gsup_req_free(req);
	return 0;

routing_error:
	osmo_gsup_req_respond_msgt(req, OSMO_GSUP_MSGT_ROUTING_ERROR, true);
	return rc;
}
