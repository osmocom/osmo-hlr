/* Supplementary Services signalling implementation */

/* (C) 2018 by Harald Welte <laforge@gnumonks.org>
 * (C) 2018 by Vadim Yanitskiy <axilirator@gmail.com>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <string.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>

#include "hlr.h"
#include "hlr_ss_ussd.h"

struct hlr_usse *hlr_usse_find(struct hlr *hlr, const char *name)
{
	struct hlr_usse *usse;

	llist_for_each_entry(usse, &hlr->usse_list, list) {
		if (!strcmp(usse->name, name))
			return usse;
	}

	return NULL;
}

struct hlr_usse *hlr_usse_alloc(struct hlr *hlr, const char *name)
{
	struct hlr_usse *usse;

	usse = hlr_usse_find(hlr, name);
	if (usse)
		return NULL;

	usse = talloc(hlr, struct hlr_usse);
	usse->name = talloc_strdup(usse, name);
	usse->description = NULL;
	usse->hlr = hlr;

	INIT_LLIST_HEAD(&usse->patterns);
	llist_add_tail(&usse->list, &hlr->usse_list);

	return usse;
}

void hlr_usse_del(struct hlr_usse *usse)
{
	struct hlr_usse_pattern *pt, *_pt;

	/* Release linked patterns */
	llist_for_each_entry_safe(pt, _pt, &usse->patterns, list)
		hlr_usse_pattern_del(pt);

	/* Unlink from the HLR's USSE list */
	llist_del(&usse->list);

	/* Release memory */
	talloc_free(usse);
}

struct hlr_usse_pattern *hlr_usse_pattern_find(struct hlr_usse *usse,
	enum hlr_usse_pattern_type type, const char *pattern)
{
	struct hlr_usse_pattern *pt;

	llist_for_each_entry(pt, &usse->patterns, list) {
		if (pt->type != type)
			continue;
		if (strcmp(pt->pattern, pattern))
			continue;

		return pt;
	}

	return NULL;
}

struct hlr_usse_pattern *hlr_usse_pattern_add(struct hlr_usse *usse,
	enum hlr_usse_pattern_type type, const char *pattern)
{
	struct hlr_usse_pattern *pt;

	pt = hlr_usse_pattern_find(usse, type, pattern);
	if (pt)
		return NULL;

	pt = talloc(usse, struct hlr_usse_pattern);
	pt->pattern = talloc_strdup(pt, pattern);
	pt->rsp_fmt = NULL;
	pt->type = type;
	pt->usse = usse;

	llist_add_tail(&pt->list, &usse->patterns);
	return pt;
}

void hlr_usse_pattern_del(struct hlr_usse_pattern *pt)
{
	/* Unlink from the USSE's list */
	llist_del(&pt->list);

	/* Release memory */
	talloc_free(pt);
}

void hlr_usse_clean_up(struct hlr *hlr)
{
	struct hlr_usse *usse, *_usse;

	llist_for_each_entry_safe(usse, _usse, &hlr->usse_list, list)
		hlr_usse_del(usse);
}
