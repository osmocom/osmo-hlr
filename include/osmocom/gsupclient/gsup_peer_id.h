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
#include <unistd.h>
#include <stdint.h>
#include <osmocom/core/utils.h>

/*! IPA Name: Arbitrary length blob, not necessarily zero-terminated.
 * In osmo-hlr, struct hlr_subscriber is mostly used as static reference and cannot serve as talloc context, which is
 * why this is also implemented as a fixed-maximum-size buffer instead of a talloc'd arbitrary sized buffer.
 * NOTE: The length of val may be extended in the future if it becomes necessary.
 * At the time of writing, this holds IPA unit name strings of very limited length.
 */
struct osmo_ipa_name {
	size_t len;
	uint8_t val[128];
};

bool osmo_ipa_name_is_empty(struct osmo_ipa_name *ipa_name);
int osmo_ipa_name_set(struct osmo_ipa_name *ipa_name, const uint8_t *val, size_t len);
int osmo_ipa_name_set_str(struct osmo_ipa_name *ipa_name, const char *str_fmt, ...);
int osmo_ipa_name_cmp(const struct osmo_ipa_name *a, const struct osmo_ipa_name *b);
const char *osmo_ipa_name_to_str(const struct osmo_ipa_name *ipa_name);

enum osmo_gsup_peer_id_type {
	OSMO_GSUP_PEER_ID_EMPTY=0,
	OSMO_GSUP_PEER_ID_IPA_NAME,
	/* OSMO_GSUP_PEER_ID_GLOBAL_TITLE, <-- currently not implemented, but likely future possibility */
};

extern const struct value_string osmo_gsup_peer_id_type_names[];
static inline const char *osmo_gsup_peer_id_type_name(enum osmo_gsup_peer_id_type val)
{ return get_value_string(osmo_gsup_peer_id_type_names, val); }

struct osmo_gsup_peer_id {
	enum osmo_gsup_peer_id_type type;
	union {
		struct osmo_ipa_name ipa_name;
	};
};

bool osmo_gsup_peer_id_is_empty(struct osmo_gsup_peer_id *gsup_peer_id);
int osmo_gsup_peer_id_set(struct osmo_gsup_peer_id *gsup_peer_id, enum osmo_gsup_peer_id_type type,
			  const uint8_t *val, size_t len);
int osmo_gsup_peer_id_set_str(struct osmo_gsup_peer_id *gsup_peer_id, enum osmo_gsup_peer_id_type type,
			      const char *str_fmt, ...);
int osmo_gsup_peer_id_cmp(const struct osmo_gsup_peer_id *a, const struct osmo_gsup_peer_id *b);
const char *osmo_gsup_peer_id_to_str(const struct osmo_gsup_peer_id *gsup_peer_id);
