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

int osmo_ipa_name_set(struct osmo_ipa_name *ipa_name, const uint8_t *val, size_t len);
int osmo_ipa_name_set_str(struct osmo_ipa_name *ipa_name, const char *str_fmt, ...);
int osmo_ipa_name_cmp(const struct osmo_ipa_name *a, const struct osmo_ipa_name *b);
const char *osmo_ipa_name_to_str_c(void *ctx, const struct osmo_ipa_name *ipa_name);
const char *osmo_ipa_name_to_str(const struct osmo_ipa_name *ipa_name);
