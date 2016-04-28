#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/abis/ipaccess.h>

#include "gsup_server.h"

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

static int osmo_gsup_conn_oap_handle(struct osmo_gsup_conn *conn,
				struct msgb *msg_rx)
{
	int rc;
	struct msgb *msg_tx;
#if 0
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

static int osmo_gsup_server_ccm_cb(struct ipa_server_conn *conn,
				   struct msgb *msg, struct tlv_parsed *tlvp,
				   struct ipaccess_unit *unit)
{
	LOGP(DLGSUP, LOGL_INFO, "CCM Callback\n");
	/* TODO: ? */
	return 0;
}

static int osmo_gsup_server_closed_cb(struct ipa_server_conn *conn)
{
	struct osmo_gsup_conn *clnt = (struct osmo_gsup_conn *)conn->data;

	LOGP(DLGSUP, LOGL_INFO, "Lost GSUP client %s:%d\n",
		conn->addr, conn->port);

	llist_del(&clnt->list);
	talloc_free(clnt);

	return 0;
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
	conn->conn->ccm_cb = osmo_gsup_server_ccm_cb;
	OSMO_ASSERT(conn->conn);

	/* link data structure with server structure */
	conn->server = gsups;
	llist_add_tail(&conn->list, &gsups->clients);

	LOGP(DLGSUP, LOGL_INFO, "New GSUP client %s:%d\n",
		conn->conn->addr, conn->conn->port);

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
osmo_gsup_server_create(void *ctx, const char *ip_addr,
			uint16_t tcp_port,
			osmo_gsup_read_cb_t read_cb)
{
	struct osmo_gsup_server *gsups;
	int rc;

	gsups = talloc_zero(ctx, struct osmo_gsup_server);
	OSMO_ASSERT(gsups);

	INIT_LLIST_HEAD(&gsups->clients);

	gsups->link = ipa_server_link_create(gsups,
					/* no e1inp */ NULL,
					ip_addr, tcp_port,
					osmo_gsup_server_accept_cb,
					gsups);
	if (!gsups->link)
		goto failed;

	gsups->read_cb = read_cb;

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
