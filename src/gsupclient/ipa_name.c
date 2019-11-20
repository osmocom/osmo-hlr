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

#include <errno.h>
#include <string.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsupclient/ipa_name.h>

int osmo_ipa_name_set(struct osmo_ipa_name *ipa_name, const uint8_t *val, size_t len)
{
	if (!val || !len) {
		*ipa_name = (struct osmo_ipa_name){};
		return 0;
	}
	if (len > sizeof(ipa_name->val))
		return -ENOSPC;
	ipa_name->len = len;
	memcpy(ipa_name->val, val, len);
	return 0;
}

int osmo_ipa_name_set_str(struct osmo_ipa_name *ipa_name, const char *str_fmt, ...)
{
	va_list ap;
	if (!str_fmt)
		return osmo_ipa_name_set(ipa_name, NULL, 0);

	va_start(ap, str_fmt);
	vsnprintf((char*)(ipa_name->val), sizeof(ipa_name->val), str_fmt, ap);
	va_end(ap);
	ipa_name->len = strlen((char*)(ipa_name->val))+1;
	return 0;
}

int osmo_ipa_name_cmp(const struct osmo_ipa_name *a, const struct osmo_ipa_name *b)
{
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	if (!a->len && !b->len)
		return 0;
	if (!a->len && b->len)
		return -1;
	if (!b->len && a->len)
		return 1;

	if (a->len == b->len)
		return memcmp(a->val, b->val, a->len);
	else if (a->len < b->len) {
		cmp = memcmp(a->val, b->val, a->len);
		if (!cmp)
			cmp = -1;
		return cmp;
	} else {
		/* a->len > b->len */
		cmp = memcmp(a->val, b->val, b->len);
		if (!cmp)
			cmp = 1;
		return cmp;
	}
}

/* Call osmo_ipa_name_to_str_c with OTC_SELECT. */
const char *osmo_ipa_name_to_str(const struct osmo_ipa_name *ipa_name)
{
	return osmo_ipa_name_to_str_c(OTC_SELECT, ipa_name);
}

/* Return an unquoted string, not including the terminating zero. Used for writing VTY config. */
const char *osmo_ipa_name_to_str_c(void *ctx, const struct osmo_ipa_name *ipa_name)
{
	size_t len = ipa_name->len;
	if (!len)
		return talloc_strdup(ctx, "");
	if (ipa_name->val[len-1] == '\0')
		len--;
	return osmo_escape_str_c(ctx, (char*)ipa_name->val, len);
}
