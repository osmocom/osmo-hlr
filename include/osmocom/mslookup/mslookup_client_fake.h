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

/*! MS lookup fake API for testing purposes. */
#include <osmocom/mslookup/mslookup_client.h>

struct osmo_mslookup_fake_response {
	struct timeval time_to_reply;
	struct osmo_mslookup_id for_id;
	const char *for_service;
	struct osmo_mslookup_result result;
	bool sent;
};

struct osmo_mslookup_client_method *osmo_mslookup_client_add_fake(struct osmo_mslookup_client *client,
								  struct osmo_mslookup_fake_response *responses,
								  size_t responses_len);
