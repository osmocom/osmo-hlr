/* OsmoHLR SMS routing implementation */

/* (C) 2019 by Vadim Yanitskiy <axilirator@gmail.com>
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
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsup.h>

#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/hlr_sms.h>
#include <osmocom/hlr/hlr_ussd.h>
#include <osmocom/hlr/gsup_server.h>
#include <osmocom/hlr/gsup_router.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/db.h>

struct hlr_sms_route *sms_route_find(struct hlr *hlr,
				     enum hlr_sms_route_type type,
				     const char *pattern)
{
	struct hlr_sms_route *rt;

	llist_for_each_entry(rt, &hlr->sms_routes, list) {
		if (rt->type != type)
			continue;
		if (!strcmp(rt->match_pattern, pattern))
			return rt;
	}

	return NULL;
}

struct hlr_sms_route *sms_route_alloc(struct hlr *hlr,
				      enum hlr_sms_route_type type,
				      const char *pattern,
				      const struct hlr_euse *euse)
{
	struct hlr_sms_route *rt;

	if (sms_route_find(hlr, type, pattern))
		return NULL;

	rt = talloc(hlr, struct hlr_sms_route);
	OSMO_ASSERT(rt != NULL);

	rt->match_pattern = talloc_strdup(rt, pattern);
	rt->type = type;
	rt->euse = euse;

	llist_add_tail(&rt->list, &hlr->sms_routes);

	return rt;
}

void sms_route_del(struct hlr_sms_route *rt)
{
	llist_del(&rt->list);
	talloc_free(rt);
}
