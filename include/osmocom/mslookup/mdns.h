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

/*! \file mdns.h */

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/mslookup/mslookup.h>

struct msgb *osmo_mdns_query_encode(void *ctx, uint16_t packet_id, const struct osmo_mslookup_query *query);

struct osmo_mslookup_query *osmo_mdns_query_decode(void *ctx, const uint8_t *data, size_t data_len,
						   uint16_t *packet_id);

struct msgb *osmo_mdns_result_encode(void *ctx, uint16_t packet_id, const struct osmo_mslookup_query *query,
				     const struct osmo_mslookup_result *result);

int osmo_mdns_result_decode(void *ctx, const uint8_t *data, size_t data_len, uint16_t *packet_id,
			    struct osmo_mslookup_query *query, struct osmo_mslookup_result *result);
