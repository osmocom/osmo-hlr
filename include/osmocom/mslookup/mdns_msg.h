/* Copyright 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
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
#include "mdns_rfc.h"

struct osmo_mdns_record {
	struct llist_head list;
	enum osmo_mdns_rfc_record_type type;
	uint16_t length;
	uint8_t *data;
};

struct osmo_mdns_msg_request {
	uint16_t id;
	char *domain;
	enum osmo_mdns_rfc_record_type type;
};

struct osmo_mdns_msg_answer {
	uint16_t id;
	char *domain;
	/*! list of osmo_mdns_record. */
	struct llist_head records;
};

int osmo_mdns_msg_request_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_request *req);
struct osmo_mdns_msg_request *osmo_mdns_msg_request_decode(void *ctx, const uint8_t *data, size_t data_len);

void osmo_mdns_msg_answer_init(struct osmo_mdns_msg_answer *answer);
int osmo_mdns_msg_answer_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_answer *ans);
struct osmo_mdns_msg_answer *osmo_mdns_msg_answer_decode(void *ctx, const uint8_t *data, size_t data_len);
int osmo_mdns_result_from_answer(struct osmo_mslookup_result *result, const struct osmo_mdns_msg_answer *ans);

struct osmo_mdns_record *osmo_mdns_record_txt_keyval_encode(void *ctx, const char *key, const char *value_fmt, ...);
int osmo_mdns_record_txt_keyval_decode(const struct osmo_mdns_record *rec,
				       char *key_buf, size_t key_size, char *value_buf, size_t value_size);
