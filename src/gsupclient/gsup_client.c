/* Generic Subscriber Update Protocol client */

/* (C) 2014-2016 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/gsupclient/gsup_client.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/oap_client.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <errno.h>
#include <string.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

static void start_test_procedure(struct osmo_gsup_client *gsupc);

static void gsup_client_send_ping(struct osmo_gsup_client *gsupc)
{
	struct msgb *msg = osmo_gsup_client_msgb_alloc();

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;
	ipa_prepend_header(msg, IPAC_PROTO_IPACCESS);
	ipa_client_conn_send(gsupc->link, msg);
}

static int gsup_client_connect(struct osmo_gsup_client *gsupc)
{
	int rc;

	if (gsupc->is_connected)
		return 0;

	if (osmo_timer_pending(&gsupc->connect_timer)) {
		LOGP(DLGSUP, LOGL_DEBUG,
		     "GSUP connect: connect timer already running\n");
		osmo_timer_del(&gsupc->connect_timer);
	}

	if (osmo_timer_pending(&gsupc->ping_timer)) {
		LOGP(DLGSUP, LOGL_DEBUG,
		     "GSUP connect: ping timer already running\n");
		osmo_timer_del(&gsupc->ping_timer);
	}

	if (ipa_client_conn_clear_queue(gsupc->link) > 0)
		LOGP(DLGSUP, LOGL_DEBUG, "GSUP connect: discarded stored messages\n");

	rc = ipa_client_conn_open(gsupc->link);

	if (rc >= 0) {
		LOGP(DLGSUP, LOGL_NOTICE, "GSUP connecting to %s:%d\n",
		     gsupc->link->addr, gsupc->link->port);
		return 0;
	}

	LOGP(DLGSUP, LOGL_ERROR, "GSUP failed to connect to %s:%d: %s\n",
	     gsupc->link->addr, gsupc->link->port, strerror(-rc));

	if (rc == -EBADF || rc == -ENOTSOCK || rc == -EAFNOSUPPORT ||
	    rc == -EINVAL)
		return rc;

	osmo_timer_schedule(&gsupc->connect_timer,
			    OSMO_GSUP_CLIENT_RECONNECT_INTERVAL, 0);

	LOGP(DLGSUP, LOGL_INFO, "Scheduled timer to retry GSUP connect to %s:%d\n",
	     gsupc->link->addr, gsupc->link->port);

	return 0;
}

static void connect_timer_cb(void *gsupc_)
{
	struct osmo_gsup_client *gsupc = gsupc_;

	if (gsupc->is_connected)
		return;

	if (gsupc->up_down_cb) {
		/* When the up_down_cb() returns false, the user asks us not to retry connecting. */
		if (!gsupc->up_down_cb(gsupc, false))
			return;
	}

	gsup_client_connect(gsupc);
}

static void client_send(struct osmo_gsup_client *gsupc, int proto_ext,
			struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, proto_ext);
	ipa_prepend_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_client_conn_send(gsupc->link, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

static void gsup_client_oap_register(struct osmo_gsup_client *gsupc)
{
	struct msgb *msg_tx;
	int rc;
	rc = osmo_oap_client_register(&gsupc->oap_state, &msg_tx);

	if ((rc < 0) || (!msg_tx)) {
		LOGP(DLGSUP, LOGL_ERROR, "GSUP OAP set up, but cannot register.\n");
		return;
	}

	client_send(gsupc, IPAC_PROTO_EXT_OAP, msg_tx);
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

static void gsup_client_updown_cb(struct ipa_client_conn *link, int up)
{
	struct osmo_gsup_client *gsupc = link->data;

	LOGP(DLGSUP, LOGL_INFO, "GSUP link to %s:%d %s\n",
		     link->addr, link->port, up ? "UP" : "DOWN");

	gsupc->is_connected = up;

	if (up) {
		update_fd_settings(link->ofd->fd);
		start_test_procedure(gsupc);

		if (gsupc->oap_state.state == OSMO_OAP_INITIALIZED)
			gsup_client_oap_register(gsupc);

		osmo_timer_del(&gsupc->connect_timer);

		if (gsupc->up_down_cb)
			gsupc->up_down_cb(gsupc, true);
	} else {
		osmo_timer_del(&gsupc->ping_timer);

		if (gsupc->up_down_cb) {
			/* When the up_down_cb() returns false, the user asks us not to retry connecting. */
			if (!gsupc->up_down_cb(gsupc, false))
				return;
		}

		osmo_timer_schedule(&gsupc->connect_timer,
				    OSMO_GSUP_CLIENT_RECONNECT_INTERVAL, 0);
	}
}

static int gsup_client_oap_handle(struct osmo_gsup_client *gsupc, struct msgb *msg_rx)
{
	int rc;
	struct msgb *msg_tx;

	/* If the oap_state is disabled, this will reject the messages. */
	rc = osmo_oap_client_handle(&gsupc->oap_state, msg_rx, &msg_tx);
	msgb_free(msg_rx);
	if (rc < 0)
		return rc;

	if (msg_tx)
		client_send(gsupc, IPAC_PROTO_EXT_OAP, msg_tx);

	return 0;
}

static int gsup_client_read_cb(struct ipa_client_conn *link, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct osmo_gsup_client *gsupc = (struct osmo_gsup_client *)link->data;
	int rc;

	OSMO_ASSERT(gsupc->unit_name);

	msg->l2h = &hh->data[0];

	rc = ipaccess_bts_handle_ccm(link, gsupc->ipa_dev, msg);

	if (rc < 0) {
		LOGP(DLGSUP, LOGL_NOTICE,
		     "GSUP received an invalid IPA/CCM message from %s:%d\n",
		     link->addr, link->port);
		/* Link has been closed */
		gsupc->is_connected = 0;
		msgb_free(msg);
		return -1;
	}

	if (rc == 1) {
		uint8_t msg_type = *(msg->l2h);
		/* CCM message */
		if (msg_type == IPAC_MSGT_PONG) {
			LOGP(DLGSUP, LOGL_DEBUG, "GSUP receiving PONG\n");
			gsupc->got_ipa_pong = 1;
		}

		msgb_free(msg);
		return 0;
	}

	if (hh->proto != IPAC_PROTO_OSMO)
		goto invalid;

	if (!he || msgb_l2len(msg) < sizeof(*he))
		goto invalid;

	msg->l2h = &he->data[0];

	if (he->proto == IPAC_PROTO_EXT_GSUP) {
		OSMO_ASSERT(gsupc->read_cb != NULL);
		gsupc->read_cb(gsupc, msg);
		/* expecting read_cb() to free msg */
	} else if (he->proto == IPAC_PROTO_EXT_OAP) {
		return gsup_client_oap_handle(gsupc, msg);
		/* gsup_client_oap_handle frees msg */
	} else
		goto invalid;

	return 0;

invalid:
	LOGP(DLGSUP, LOGL_NOTICE,
	     "GSUP received an invalid IPA message from %s:%d, size = %d\n",
	     link->addr, link->port, msgb_length(msg));

	msgb_free(msg);
	return -1;
}

static void ping_timer_cb(void *gsupc_)
{
	struct osmo_gsup_client *gsupc = gsupc_;

	LOGP(DLGSUP, LOGL_INFO, "GSUP ping callback (%s, %s PONG)\n",
	     gsupc->is_connected ? "connected" : "not connected",
	     gsupc->got_ipa_pong ? "got" : "didn't get");

	if (gsupc->got_ipa_pong) {
		start_test_procedure(gsupc);
		return;
	}

	LOGP(DLGSUP, LOGL_NOTICE, "GSUP ping timed out, reconnecting\n");
	ipa_client_conn_close(gsupc->link);
	gsupc->is_connected = 0;

	gsup_client_connect(gsupc);
}

static void start_test_procedure(struct osmo_gsup_client *gsupc)
{
	osmo_timer_setup(&gsupc->ping_timer, ping_timer_cb, gsupc);

	gsupc->got_ipa_pong = 0;
	osmo_timer_schedule(&gsupc->ping_timer, OSMO_GSUP_CLIENT_PING_INTERVAL, 0);
	LOGP(DLGSUP, LOGL_DEBUG, "GSUP sending PING\n");
	gsup_client_send_ping(gsupc);
}

/*!
 * Create a gsup client connecting to the specified IP address and TCP port.
 * Use the provided ipaccess unit as the client-side identifier; ipa_dev should
 * be allocated in talloc_ctx talloc_ctx as well.
 * \param[in] talloc_ctx talloc context.
 * \param[in] config  Parameters for setting up the GSUP client.
 * \return a GSUP client connection, or NULL on failure.
 */
struct osmo_gsup_client *osmo_gsup_client_create3(void *talloc_ctx, struct osmo_gsup_client_config *config)
{
	struct osmo_gsup_client *gsupc;
	int rc;

	OSMO_ASSERT(config->ipa_dev->unit_name);

	gsupc = talloc(talloc_ctx, struct osmo_gsup_client);
	OSMO_ASSERT(gsupc);
	*gsupc = (struct osmo_gsup_client){
		.unit_name = (const char *)config->ipa_dev->unit_name, /* API backwards compat */
		.ipa_dev = config->ipa_dev,
		.read_cb = config->read_cb,
		.up_down_cb = config->up_down_cb,
		.data = config->data,
	};

	/* a NULL oapc_config will mark oap_state disabled. */
	rc = osmo_oap_client_init(config->oapc_config, &gsupc->oap_state);
	if (rc != 0)
		goto failed;

	gsupc->link = ipa_client_conn_create2(gsupc,
					      /* no e1inp */ NULL,
					      0,
					      /* no specific local IP:port */ NULL, 0,
					      config->ip_addr, config->tcp_port,
					      gsup_client_updown_cb,
					      gsup_client_read_cb,
					      /* default write_cb */ NULL,
					      gsupc);
	if (!gsupc->link)
		goto failed;

	osmo_timer_setup(&gsupc->connect_timer, connect_timer_cb, gsupc);

	rc = gsup_client_connect(gsupc);

	if (rc < 0)
		goto failed;
	return gsupc;

failed:
	osmo_gsup_client_destroy(gsupc);
	return NULL;
}

/*! Like osmo_gsup_client_create3() but without the up_down_cb and data arguments, and with the oapc_config argument in
 * a different position.
 */
struct osmo_gsup_client *osmo_gsup_client_create2(void *talloc_ctx,
						  struct ipaccess_unit *ipa_dev,
						  const char *ip_addr,
						  unsigned int tcp_port,
						  osmo_gsup_client_read_cb_t read_cb,
						  struct osmo_oap_client_config *oapc_config)
{
	struct osmo_gsup_client_config cfg = {
		.ipa_dev = ipa_dev,
		.ip_addr = ip_addr,
		.tcp_port = tcp_port,
		.oapc_config = oapc_config,
		.read_cb = read_cb,
	};
	return osmo_gsup_client_create3(talloc_ctx, &cfg);
}

/**
 * Like osmo_gsup_client_create2() except it expects a unit name instead
 * of a full-blown ipacess_unit as the client-side identifier.
 */
struct osmo_gsup_client *osmo_gsup_client_create(void *talloc_ctx,
						 const char *unit_name,
						 const char *ip_addr,
						 unsigned int tcp_port,
						 osmo_gsup_client_read_cb_t read_cb,
						 struct osmo_oap_client_config *oapc_config)
{
	struct ipaccess_unit *ipa_dev = talloc_zero(talloc_ctx, struct ipaccess_unit);
	ipa_dev->unit_name = talloc_strdup(ipa_dev, unit_name);
	return osmo_gsup_client_create2(talloc_ctx, ipa_dev, ip_addr, tcp_port, read_cb, oapc_config);
}

void osmo_gsup_client_destroy(struct osmo_gsup_client *gsupc)
{
	osmo_timer_del(&gsupc->connect_timer);
	osmo_timer_del(&gsupc->ping_timer);

	if (gsupc->link) {
		ipa_client_conn_close(gsupc->link);
		ipa_client_conn_destroy(gsupc->link);
		gsupc->link = NULL;
	}
	talloc_free(gsupc);
}

int osmo_gsup_client_send(struct osmo_gsup_client *gsupc, struct msgb *msg)
{
	if (!gsupc || !gsupc->is_connected) {
		LOGP(DLGSUP, LOGL_ERROR, "GSUP not connected, unable to send %s\n", msgb_hexdump(msg));
		msgb_free(msg);
		return -ENOTCONN;
	}

	client_send(gsupc, IPAC_PROTO_EXT_GSUP, msg);

	return 0;
}

/*! Encode and send a GSUP message.
 * \param[in] gsupc    GSUP client.
 * \param[in] gsup_msg GSUP message to be sent.
 * \returns 0 in case of success, negative on error.
 */
int osmo_gsup_client_enc_send(struct osmo_gsup_client *gsupc,
			      const struct osmo_gsup_message *gsup_msg)
{
	struct msgb *gsup_msgb;
	int rc;

	gsup_msgb = osmo_gsup_client_msgb_alloc();
	if (!gsup_msgb) {
		LOGP(DLGSUP, LOGL_ERROR, "Couldn't allocate GSUP message\n");
		return -ENOMEM;
	}

	rc = osmo_gsup_encode(gsup_msgb, gsup_msg);
	if (rc) {
		LOGP(DLGSUP, LOGL_ERROR, "Couldn't encode GSUP message\n");
		goto error;
	}

	rc = osmo_gsup_client_send(gsupc, gsup_msgb);
	if (rc) {
		LOGP(DLGSUP, LOGL_ERROR, "Couldn't send GSUP message\n");
		/* Do not free, osmo_gsup_client_send() already has. */
		return rc;
	}

	return 0;

error:
	talloc_free(gsup_msgb);
	return rc;
}

struct msgb *osmo_gsup_client_msgb_alloc(void)
{
	return msgb_alloc_headroom(4000, 64, __func__);
}

void *osmo_gsup_client_get_data(const struct osmo_gsup_client *gsupc)
{
	return gsupc->data;
}

void osmo_gsup_client_set_data(struct osmo_gsup_client *gsupc, void *data)
{
	gsupc->data = data;
}

const char *osmo_gsup_client_get_rem_addr(const struct osmo_gsup_client *gsupc)
{
	if (!gsupc->link)
		return NULL;
	return gsupc->link->addr;
}
uint16_t osmo_gsup_client_get_rem_port(const struct osmo_gsup_client *gsupc)
{
	if (!gsupc->link)
		return 0;
	return gsupc->link->port;
}

bool osmo_gsup_client_is_connected(const struct osmo_gsup_client *gsupc)
{
	return gsupc->is_connected;
}

const struct ipaccess_unit *osmo_gsup_client_get_ipaccess_unit(const struct osmo_gsup_client *gsupc)
{
	return gsupc->ipa_dev;
}
