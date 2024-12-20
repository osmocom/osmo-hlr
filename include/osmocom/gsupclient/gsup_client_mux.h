/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
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
 */

#pragma once

#include <osmocom/gsm/gsup.h>

struct gsup_client_mux;
struct ipaccess_unit;

struct gsup_client_mux_rx_cb {
	int (*func)(struct gsup_client_mux *gcm, void *data, const struct osmo_gsup_message *gsup_msg);
	void *data;
};

/* A GSUP client shared between code paths for various GSUP Message Classes.
 * The main task is to dispatch GSUP messages to code paths corresponding to the respective Message Class, i.e.
 * subscriber management, SMS, SS/USSD and inter-MSC messaging.
 * If a GSUP Message Class IE is present in the message, the received message is dispatched directly to the rx_cb entry
 * for that Message Class. Otherwise, the Message Class is determined by a switch() on the Message Type.*/
struct gsup_client_mux {
	struct osmo_gsup_client *gsup_client;

	/* Target clients by enum osmo_gsup_message_class */
	struct gsup_client_mux_rx_cb rx_cb[OSMO_GSUP_MESSAGE_CLASS_ARRAYSIZE];
};

struct gsup_client_mux *gsup_client_mux_alloc(void *talloc_ctx);
int gsup_client_mux_start(struct gsup_client_mux *gcm, const char *gsup_server_addr_str, uint16_t gsup_server_port,
			  struct ipaccess_unit *ipa_dev);

int gsup_client_mux_tx(struct gsup_client_mux *gcm, const struct osmo_gsup_message *gsup_msg);
void gsup_client_mux_tx_set_source(const struct gsup_client_mux *gcm, struct osmo_gsup_message *gsup_msg);
void gsup_client_mux_tx_error_reply(struct gsup_client_mux *gcm, const struct osmo_gsup_message *gsup_orig,
				    enum gsm48_gmm_cause cause);

int gsup_client_mux_rx(struct osmo_gsup_client *gsup_client, struct msgb *msg);
