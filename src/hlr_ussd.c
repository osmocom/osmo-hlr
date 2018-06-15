/* OsmoHLR VTY implementation */

/* (C) 2018 Harald Welte <laforge@gnumonks.org>
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


#include <osmocom/core/talloc.h>
#include <stdint.h>
#include <string.h>

#include "hlr.h"
#include "hlr_ussd.h"

struct hlr_euse *euse_find(struct hlr *hlr, const char *name)
{
	struct hlr_euse *euse;

	llist_for_each_entry(euse, &hlr->euse_list, list) {
		if (!strcmp(euse->name, name))
			return euse;
	}
	return NULL;
}

struct hlr_euse *euse_alloc(struct hlr *hlr, const char *name)
{
	struct hlr_euse *euse = euse_find(hlr, name);
	if (euse)
		return NULL;

	euse = talloc_zero(hlr, struct hlr_euse);
	euse->name = talloc_strdup(euse, name);
	euse->hlr = hlr;
	INIT_LLIST_HEAD(&euse->routes);
	llist_add_tail(&euse->list, &hlr->euse_list);

	return euse;
}

void euse_del(struct hlr_euse *euse)
{
	llist_del(&euse->list);
	talloc_free(euse);
}


struct hlr_euse_route *euse_route_find(struct hlr_euse *euse, const char *prefix)
{
	struct hlr_euse_route *rt;

	llist_for_each_entry(rt, &euse->routes, list) {
		if (!strcmp(rt->prefix, prefix))
			return rt;
	}
	return NULL;
}

struct hlr_euse_route *euse_route_prefix_alloc(struct hlr_euse *euse, const char *prefix)
{
	struct hlr_euse_route *rt;

	if (euse_route_find(euse, prefix))
		return NULL;

	rt = talloc_zero(euse, struct hlr_euse_route);
	rt->prefix = talloc_strdup(rt, prefix);
	rt->euse = euse;
	llist_add_tail(&rt->list, &euse->routes);

	return rt;
}

void euse_route_del(struct hlr_euse_route *rt)
{
	llist_del(&rt->list);
	talloc_free(rt);
}
