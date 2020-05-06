#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/abis/ipa.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsupclient/cni_peer_id.h>
#include <osmocom/gsupclient/gsup_req.h>

#ifndef OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN
#define OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN	43 /* TS 24.008 10.5.4.7 */
#endif

struct osmo_gsup_conn;

/* Expects message in msg->l2h */
typedef int (*osmo_gsup_read_cb_t)(struct osmo_gsup_conn *conn, struct msgb *msg);

struct osmo_gsup_server {
	/* private data of the application/user */
	void *priv;

	/* list of osmo_gsup_conn */
	struct llist_head clients;

	struct ipa_server_link *link;
	osmo_gsup_read_cb_t read_cb;
	struct llist_head routes;

	/* Proxy requests from this server's clients to remote GSUP servers. */
	struct proxy *proxy;
};


/* a single connection to a given client (SGSN, MSC) */
struct osmo_gsup_conn {
	struct llist_head list;

	struct osmo_gsup_server *server;
	struct ipa_server_conn *conn;
	//struct oap_state oap_state;
	struct tlv_parsed ccm;

	unsigned int auc_3g_ind; /*!< IND index used for UMTS AKA SQN */

	/* Set when Location Update is received: */
	bool supports_cs; /* client supports OSMO_GSUP_CN_DOMAIN_CS */
	bool supports_ps; /* client supports OSMO_GSUP_CN_DOMAIN_PS */

	/* The IPA unit name received on this link. Routes with more unit names serviced by this link may exist in
	 * osmo_gsup_server->routes, but this is the name the immediate peer identified as in the IPA handshake. */
	struct osmo_ipa_name peer_name;
};

struct msgb *osmo_gsup_msgb_alloc(const char *label);

struct osmo_gsup_req *osmo_gsup_conn_rx(struct osmo_gsup_conn *conn, struct msgb *msg);
int osmo_gsup_conn_send(struct osmo_gsup_conn *conn, struct msgb *msg);
int osmo_gsup_conn_ccm_get(const struct osmo_gsup_conn *clnt, uint8_t **addr,
			   uint8_t tag);

struct osmo_gsup_server *osmo_gsup_server_create(void *ctx,
						 const char *ip_addr,
						 uint16_t tcp_port,
						 osmo_gsup_read_cb_t read_cb,
						 void *priv);

void osmo_gsup_server_destroy(struct osmo_gsup_server *gsups);

int osmo_gsup_configure_wildcard_apn(struct osmo_gsup_message *gsup,
				     uint8_t *apn_buf, size_t apn_buf_size);
int osmo_gsup_create_insert_subscriber_data_msg(struct osmo_gsup_message *gsup, const char *imsi, const char *msisdn,
					    uint8_t *msisdn_enc, size_t msisdn_enc_size,
				            uint8_t *apn_buf, size_t apn_buf_size,
					    enum osmo_gsup_cn_domain cn_domain);
void osmo_gsup_create_location_cancel_msg(struct osmo_gsup_message *gsup, const char *imsi,
					  enum osmo_gsup_cn_domain cn_domain, enum osmo_gsup_cancel_type cancel_type);
int osmo_gsup_forward_to_local_peer(struct osmo_gsup_server *server, const struct osmo_cni_peer_id *to_peer,
				    struct osmo_gsup_req *req, struct osmo_gsup_message *modified_gsup);
