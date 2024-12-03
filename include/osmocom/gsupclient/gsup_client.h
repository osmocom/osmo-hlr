/* GPRS Subscriber Update Protocol client */

/* (C) 2014 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
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
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/timer.h>
#include <osmocom/gsm/oap_client.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/gsup.h>

/* a loss of GSUP between MSC and HLR is considered quite serious, let's try to recover as quickly as
 * possible.  Even one new connection attempt per second should be quite acceptable until the link is
 * re-established */
#define OSMO_GSUP_CLIENT_RECONNECT_INTERVAL 1
#define OSMO_GSUP_CLIENT_PING_INTERVAL 20

struct msgb;
struct ipa_client_conn;
struct osmo_gsup_client;

/* Expects message in msg->l2h */
typedef int (*osmo_gsup_client_read_cb_t)(struct osmo_gsup_client *gsupc, struct msgb *msg);

typedef bool (*osmo_gsup_client_up_down_cb_t)(struct osmo_gsup_client *gsupc, bool up);

/* NOTE: THIS STRUCT IS CONSIDERED PRIVATE, AVOID ACCESSING ITS FIELDS! */
struct osmo_gsup_client {
	const char *unit_name; /* same as ipa_dev->unit_name, for backwards compat */

	struct ipa_client_conn *link;
	osmo_gsup_client_read_cb_t read_cb;
	void *data;

	struct osmo_oap_client_state oap_state;

	struct osmo_timer_list ping_timer;
	struct osmo_timer_list connect_timer;
	int is_connected;
	int got_ipa_pong;

	struct ipaccess_unit *ipa_dev; /* identification information sent to IPA server */

	osmo_gsup_client_up_down_cb_t up_down_cb;
};

struct osmo_gsup_client_config {
	/*! IP access unit which contains client identification information; must be allocated in talloc_ctx as well to
	 * ensure it lives throughout the lifetime of the connection. */
	struct ipaccess_unit *ipa_dev;
	/*! GSUP server IP address to connect to. */
	const char *ip_addr;
	/*! GSUP server TCP port to connect to. */
	unsigned int tcp_port;
	/*! OPA client configuration, or NULL. */
	struct osmo_oap_client_config *oapc_config;
	/*! callback for reading from the GSUP connection. */
	osmo_gsup_client_read_cb_t read_cb;
	/*! Invoked when the GSUP link is ready for communication, and when the link drops. */
	osmo_gsup_client_up_down_cb_t up_down_cb;
	/*! User data stored in the returned gsupc->data, as context for the callbacks. */
	void *data;
	/*! Marker for future extension, always pass this as false. */
	bool more;
};
struct osmo_gsup_client *osmo_gsup_client_create3(void *talloc_ctx, struct osmo_gsup_client_config *config);

struct osmo_gsup_client *osmo_gsup_client_create2(void *talloc_ctx,
						  struct ipaccess_unit *ipa_dev,
						  const char *ip_addr,
						  unsigned int tcp_port,
						  osmo_gsup_client_read_cb_t read_cb,
						  struct osmo_oap_client_config *oapc_config);
struct osmo_gsup_client *osmo_gsup_client_create(void *talloc_ctx,
						 const char *unit_name,
						 const char *ip_addr,
						 unsigned int tcp_port,
						 osmo_gsup_client_read_cb_t read_cb,
						 struct osmo_oap_client_config *oapc_config);

void osmo_gsup_client_destroy(struct osmo_gsup_client *gsupc);
int osmo_gsup_client_send(struct osmo_gsup_client *gsupc, struct msgb *msg);
int osmo_gsup_client_enc_send(struct osmo_gsup_client *gsupc,
			      const struct osmo_gsup_message *gsup_msg);
struct msgb *osmo_gsup_client_msgb_alloc(void);

void *osmo_gsup_client_get_data(const struct osmo_gsup_client *gsupc);
void osmo_gsup_client_set_data(struct osmo_gsup_client *gsupc, void *data);

const char *osmo_gsup_client_get_rem_addr(const struct osmo_gsup_client *gsupc);
uint16_t osmo_gsup_client_get_rem_port(const struct osmo_gsup_client *gsupc);

bool osmo_gsup_client_is_connected(const struct osmo_gsup_client *gsupc);
const struct ipaccess_unit *osmo_gsup_client_get_ipaccess_unit(const struct osmo_gsup_client *gsupc);

