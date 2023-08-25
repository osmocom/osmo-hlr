/* OsmoHLR SMS-over-GSUP routing implementation */

/* Author: Mychaela N. Falconia <falcon@freecalypso.org>, 2023 - however,
 * Mother Mychaela's contributions are NOT subject to copyright.
 * No rights reserved, all rights relinquished.
 *
 * Based on earlier unmerged work by Vadim Yanitskiy, 2019.
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
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsup.h>

#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/hlr_sms.h>
#include <osmocom/hlr/gsup_server.h>
#include <osmocom/hlr/gsup_router.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/db.h>

/***********************************************************************
 * core data structures expressing config from VTY
 ***********************************************************************/

struct hlr_smsc *smsc_find(struct hlr *hlr, const char *name)
{
	struct hlr_smsc *smsc;

	llist_for_each_entry(smsc, &hlr->smsc_list, list) {
		if (!strcmp(smsc->name, name))
			return smsc;
	}
	return NULL;
}

struct hlr_smsc *smsc_alloc(struct hlr *hlr, const char *name)
{
	struct hlr_smsc *smsc = smsc_find(hlr, name);
	if (smsc)
		return NULL;

	smsc = talloc_zero(hlr, struct hlr_smsc);
	smsc->name = talloc_strdup(smsc, name);
	smsc->hlr = hlr;
	llist_add_tail(&smsc->list, &hlr->smsc_list);

	return smsc;
}

void smsc_del(struct hlr_smsc *smsc)
{
	llist_del(&smsc->list);
	talloc_free(smsc);
}

struct hlr_smsc_route *smsc_route_find(struct hlr *hlr, const char *num_addr)
{
	struct hlr_smsc_route *rt;

	llist_for_each_entry(rt, &hlr->smsc_routes, list) {
		if (!strcmp(rt->num_addr, num_addr))
			return rt;
	}
	return NULL;
}

struct hlr_smsc_route *smsc_route_alloc(struct hlr *hlr, const char *num_addr,
					struct hlr_smsc *smsc)
{
	struct hlr_smsc_route *rt;

	if (smsc_route_find(hlr, num_addr))
		return NULL;

	rt = talloc_zero(hlr, struct hlr_smsc_route);
	rt->num_addr = talloc_strdup(rt, num_addr);
	rt->smsc = smsc;
	llist_add_tail(&rt->list, &hlr->smsc_routes);

	return rt;
}

void smsc_route_del(struct hlr_smsc_route *rt)
{
	llist_del(&rt->list);
	talloc_free(rt);
}
