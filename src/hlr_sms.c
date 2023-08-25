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
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

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

/***********************************************************************
 * forwarding of MO SMS to SMSCs based on SM-RP-DA
 ***********************************************************************/

static const struct hlr_smsc *find_smsc_route(const char *smsc_addr)
{
	const struct hlr_smsc_route *rt;

	rt = smsc_route_find(g_hlr, smsc_addr);
	if (rt)
		return rt->smsc;
	return g_hlr->smsc_default;
}

static void respond_with_sm_rp_cause(struct osmo_gsup_req *req,
				     uint8_t sm_rp_cause)
{
	struct osmo_gsup_message rsp_msg = { };

	rsp_msg.sm_rp_cause = &sm_rp_cause;
	osmo_gsup_req_respond(req, &rsp_msg, true, true);
}

/* Short Message from MSC/VLR towards SMSC */
void forward_mo_sms(struct osmo_gsup_req *req)
{
	/* The length limit on the SMSC address is 20 digits, stated
	 * indirectly in GSM 04.11 section 8.2.5.2. */
	uint8_t gsm48_decode_buffer[11];
	char smsc_addr[21];
	const struct hlr_smsc *smsc;
	struct osmo_cni_peer_id dest_peer;

	/* Make sure SM-RP-DA (SMSC address) is present */
	if (req->gsup.sm_rp_da == NULL || !req->gsup.sm_rp_da_len) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO,
					  "missing SM-RP-DA");
		return;
	}

	if (req->gsup.sm_rp_da_type != OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO,
					  "SM-RP-DA type is not SMSC");
		return;
	}

	/* Enforce the length constrainst on SM-RP-DA, as specified in
	 * GSM 04.11 section 8.2.5.2.  Also enforce absence of ToN/NPI
	 * extension octets at the same time. */
	if (req->gsup.sm_rp_da_len < 2 || req->gsup.sm_rp_da_len > 11 ||
	    !(req->gsup.sm_rp_da[0] & 0x80)) {
		/* This form of bogosity originates from the MS,
		 * not from OsmoMSC or any other Osmocom network elements! */
		LOGP(DLSMS, LOGL_NOTICE,
		     "Rx '%s' (IMSI-%s) contains invalid SM-RP-DA from MS\n",
		     osmo_gsup_message_type_name(req->gsup.message_type),
		     req->gsup.imsi);
		respond_with_sm_rp_cause(req, GSM411_RP_CAUSE_SEMANT_INC_MSG);
		return;
	}

	/* Decode SMSC address from SM-RP-DA */
	gsm48_decode_buffer[0] = req->gsup.sm_rp_da_len - 1;
	memcpy(gsm48_decode_buffer + 1, req->gsup.sm_rp_da + 1,
		req->gsup.sm_rp_da_len - 1);
	gsm48_decode_bcd_number2(smsc_addr, sizeof(smsc_addr),
				 gsm48_decode_buffer,
				 req->gsup.sm_rp_da_len, 0);

	/* Look for a route to this SMSC */
	smsc = find_smsc_route(smsc_addr);
	if (smsc == NULL) {
		LOGP(DLSMS, LOGL_NOTICE,
		     "Failed to find a route for '%s' (IMSI-%s, SMSC-Addr-%s)\n",
		     osmo_gsup_message_type_name(req->gsup.message_type),
		     req->gsup.imsi, smsc_addr);
		respond_with_sm_rp_cause(req,
					 GSM411_RP_CAUSE_MO_NUM_UNASSIGNED);
		return;
	}

	/* We got the IPA name of our SMSC - forward the message */
	osmo_cni_peer_id_set(&dest_peer, OSMO_CNI_PEER_ID_IPA_NAME,
			     (const uint8_t *) smsc->name,
			     strlen(smsc->name) + 1);
	osmo_gsup_forward_to_local_peer(req->cb_data, &dest_peer, req, NULL);
}