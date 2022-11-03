/* Roughly following "Process Update_Location_HLR" of TS 09.02 */

/* Copyright 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm48_ie.h>

#include <osmocom/gsupclient/cni_peer_id.h>
#include <osmocom/gsupclient/gsup_req.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/gsup_server.h>

#include <osmocom/hlr/db.h>

#define LOG_LU(lu, level, fmt, args...) \
	LOGPFSML((lu)? (lu)->fi : NULL, level, fmt, ##args)

#define LOG_LU_REQ(lu, req, level, fmt, args...) \
	LOGPFSML((lu)? (lu)->fi : NULL, level, "%s:" fmt, \
		 osmo_gsup_message_type_name((req)->gsup.message_type), ##args)

struct lu {
	struct llist_head entry;
	struct osmo_fsm_inst *fi;

	struct osmo_gsup_req *update_location_req;

	/* Subscriber state at time of initial Update Location Request */
	struct hlr_subscriber subscr;
	bool is_ps;

	/* VLR requesting the LU. */
	struct osmo_cni_peer_id vlr_name;

	/* If the LU request was received via a proxy and not immediately from a local VLR, this indicates the closest
	 * peer that forwarded the GSUP message. */
	struct osmo_cni_peer_id via_proxy;
};
LLIST_HEAD(g_all_lu);

enum lu_fsm_event {
	LU_EV_RX_GSUP,
};

enum lu_fsm_state {
	LU_ST_UNVALIDATED,
	LU_ST_WAIT_INSERT_DATA_RESULT,
	LU_ST_WAIT_LOCATION_CANCEL_RESULT,
};

static const struct value_string lu_fsm_event_names[] = {
	OSMO_VALUE_STRING(LU_EV_RX_GSUP),
	{}
};

static struct osmo_tdef_state_timeout lu_fsm_timeouts[32] = {
	[LU_ST_WAIT_INSERT_DATA_RESULT] = { .T = -4222 },
	[LU_ST_WAIT_LOCATION_CANCEL_RESULT] = { .T = -4222 },
};

#define lu_state_chg(lu, state) \
	osmo_tdef_fsm_inst_state_chg((lu)->fi, state, lu_fsm_timeouts, g_hlr_tdefs, 5)

static void lu_success(struct lu *lu)
{
	if (!lu->update_location_req)
		LOG_LU(lu, LOGL_ERROR, "No request for this LU\n");
	else
		osmo_gsup_req_respond_msgt(lu->update_location_req, OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT, true);
	lu->update_location_req = NULL;
	osmo_fsm_inst_term(lu->fi, OSMO_FSM_TERM_REGULAR, NULL);
}

#define lu_failure(LU, CAUSE, log_msg, args...) do { \
		if (!(LU)->update_location_req) \
			LOG_LU(LU, LOGL_ERROR, "No request for this LU\n"); \
		else \
			osmo_gsup_req_respond_err((LU)->update_location_req, CAUSE, log_msg, ##args); \
		(LU)->update_location_req = NULL; \
		osmo_fsm_inst_term((LU)->fi, OSMO_FSM_TERM_REGULAR, NULL); \
	} while(0)

static struct osmo_fsm lu_fsm;

static void lu_start(struct osmo_gsup_req *update_location_req)
{
	struct osmo_fsm_inst *fi;
	struct lu *lu;

	OSMO_ASSERT(update_location_req);
	OSMO_ASSERT(update_location_req->gsup.message_type == OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST);

	fi = osmo_fsm_inst_alloc(&lu_fsm, g_hlr, NULL, LOGL_DEBUG, update_location_req->gsup.imsi);
	OSMO_ASSERT(fi);

	lu = talloc(fi, struct lu);
	OSMO_ASSERT(lu);
	fi->priv = lu;
	*lu = (struct lu){
		.fi = fi,
		.update_location_req = update_location_req,
		.vlr_name = update_location_req->source_name,
		.via_proxy = update_location_req->via_proxy,
		/* According to GSUP specs, OSMO_GSUP_CN_DOMAIN_PS is the default. */
		.is_ps = (update_location_req->gsup.cn_domain != OSMO_GSUP_CN_DOMAIN_CS),
	};
	llist_add(&lu->entry, &g_all_lu);

	osmo_fsm_inst_update_id_f_sanitize(fi, '_', "%s:IMSI-%s", lu->is_ps ? "PS" : "CS", update_location_req->gsup.imsi);

	if (osmo_cni_peer_id_is_empty(&lu->vlr_name)) {
		lu_failure(lu, GMM_CAUSE_NET_FAIL, "LU without a VLR");
		return;
	}

	if (db_subscr_get_by_imsi(g_hlr->dbc, update_location_req->gsup.imsi, &lu->subscr) < 0) {
		lu_failure(lu, GMM_CAUSE_IMSI_UNKNOWN, "Subscriber does not exist");
		return;
	}

	/* Check if subscriber is generally permitted on CS or PS
	 * service (as requested) */
	if (!lu->is_ps && !lu->subscr.nam_cs) {
		lu_failure(lu, GMM_CAUSE_PLMN_NOTALLOWED, "nam_cs == false");
		return;
	}
	if (lu->is_ps && !lu->subscr.nam_ps) {
		lu_failure(lu, GMM_CAUSE_GPRS_NOTALLOWED, "nam_ps == false");
		return;
	}

	/* TODO: Set subscriber tracing = deactive in VLR/SGSN */

#if 0
	/* Cancel in old VLR/SGSN, if new VLR/SGSN differs from old (FIXME: OS#4491) */
	if (!lu->is_ps && strcmp(subscr->vlr_number, vlr_number)) {
		lu_op_tx_cancel_old(lu);
	} else if (lu->is_ps && strcmp(subscr->sgsn_number, sgsn_number)) {
		lu_op_tx_cancel_old(lu);
	}
#endif

	/* Store the VLR / SGSN number with the subscriber, so we know where it was last seen. */
	if (!osmo_cni_peer_id_is_empty(&lu->via_proxy)) {
		LOG_GSUP_REQ(update_location_req, LOGL_DEBUG, "storing %s = %s, via proxy %s\n",
			     lu->is_ps ? "SGSN number" : "VLR number",
			     osmo_cni_peer_id_to_str(&lu->vlr_name),
			     osmo_cni_peer_id_to_str(&lu->via_proxy));
	} else {
		LOG_GSUP_REQ(update_location_req, LOGL_DEBUG, "storing %s = %s\n",
		     lu->is_ps ? "SGSN number" : "VLR number",
		     osmo_cni_peer_id_to_str(&lu->vlr_name));
	}

	if (osmo_cni_peer_id_is_empty(&lu->vlr_name)
	    || (lu->vlr_name.type != OSMO_CNI_PEER_ID_IPA_NAME)) {
		lu_failure(lu, GMM_CAUSE_PROTO_ERR_UNSPEC, "Unsupported GSUP peer id type for vlr_name: %s",
			   osmo_cni_peer_id_type_name(lu->vlr_name.type));
		return;
	}
	if (!osmo_cni_peer_id_is_empty(&lu->via_proxy) && (lu->via_proxy.type != OSMO_CNI_PEER_ID_IPA_NAME)) {
		lu_failure(lu, GMM_CAUSE_PROTO_ERR_UNSPEC, "Unsupported GSUP peer id type for via_proxy: %s",
			   osmo_cni_peer_id_type_name(lu->via_proxy.type));
		return;
	}
	if (db_subscr_lu(g_hlr->dbc, lu->subscr.id, &lu->vlr_name.ipa_name, lu->is_ps,
			 osmo_cni_peer_id_is_empty(&lu->via_proxy)? NULL : &lu->via_proxy.ipa_name)) {
		lu_failure(lu, GMM_CAUSE_NET_FAIL, "Cannot update %s in the database",
			   lu->is_ps ? "SGSN number" : "VLR number");
		return;
	}

	/* TODO: Subscriber allowed to roam in PLMN? */
	/* TODO: Update RoutingInfo */
	/* TODO: Reset Flag MS Purged (cs/ps) */
	/* TODO: Control_Tracing_HLR / Control_Tracing_HLR_with_SGSN */

	lu_state_chg(lu, LU_ST_WAIT_INSERT_DATA_RESULT);
}

void lu_rx_gsup(struct osmo_gsup_req *req)
{
	struct lu *lu;
	if (req->gsup.message_type == OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST)
		return lu_start(req);

	llist_for_each_entry(lu, &g_all_lu, entry) {
		if (strcmp(lu->subscr.imsi, req->gsup.imsi))
			continue;
		if (osmo_fsm_inst_dispatch(lu->fi, LU_EV_RX_GSUP, req)) {
			LOG_LU_REQ(lu, req, LOGL_ERROR, "Cannot receive GSUP messages in this state\n");
			osmo_gsup_req_respond_err(req, GMM_CAUSE_MSGT_INCOMP_P_STATE,
						  "LU does not accept GSUP rx");
		}
		return;
	}
	osmo_gsup_req_respond_err(req, GMM_CAUSE_MSGT_INCOMP_P_STATE, "No Location Updating in progress for this IMSI");
}

static int lu_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct lu *lu = fi->priv;
	lu_failure(lu, GSM_CAUSE_NET_FAIL, "Timeout");
	return 0;
}

static void lu_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct lu *lu = fi->priv;
	if (lu->update_location_req)
		osmo_gsup_req_respond_err(lu->update_location_req, GSM_CAUSE_NET_FAIL, "LU aborted");
	lu->update_location_req = NULL;
	llist_del(&lu->entry);
}

static void lu_fsm_wait_insert_data_result_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	/* Transmit Insert Data Request to the VLR */
	struct lu *lu = fi->priv;
	struct hlr_subscriber *subscr = &lu->subscr;
	struct osmo_gsup_message gsup;
	uint8_t msisdn_enc[OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN];
	uint8_t apn[APN_MAXLEN];

	if (osmo_gsup_create_insert_subscriber_data_msg(&gsup, subscr->imsi,
							subscr->msisdn, msisdn_enc, sizeof(msisdn_enc),
							apn, sizeof(apn),
							lu->is_ps? OSMO_GSUP_CN_DOMAIN_PS : OSMO_GSUP_CN_DOMAIN_CS)) {
		lu_failure(lu, GMM_CAUSE_NET_FAIL, "cannot encode Insert Subscriber Data message");
		return;
	}

	if (osmo_gsup_req_respond(lu->update_location_req, &gsup, false, false))
		lu_failure(lu, GMM_CAUSE_NET_FAIL, "cannot send %s", osmo_gsup_message_type_name(gsup.message_type));
}

void lu_fsm_wait_insert_data_result(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct lu *lu = fi->priv;
	struct osmo_gsup_req *req;

	switch (event) {
	case LU_EV_RX_GSUP:
		req = data;
		break;
	default:
		OSMO_ASSERT(false);
	}

	switch (req->gsup.message_type) {
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
		osmo_gsup_req_free(req);
		lu_success(lu);
		break;

	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
		lu_failure(lu, GMM_CAUSE_NET_FAIL, "Rx %s", osmo_gsup_message_type_name(req->gsup.message_type));
		break;

	default:
		osmo_gsup_req_respond_err(req, GMM_CAUSE_MSGT_INCOMP_P_STATE, "unexpected message type in this state");
		break;
	}
}

#define S(x) (1 << (x))

static const struct osmo_fsm_state lu_fsm_states[] = {
	[LU_ST_UNVALIDATED] = {
		.name = "UNVALIDATED",
		.out_state_mask = 0
			| S(LU_ST_WAIT_INSERT_DATA_RESULT)
			,
	},
	[LU_ST_WAIT_INSERT_DATA_RESULT] = {
		.name = "WAIT_INSERT_DATA_RESULT",
		.in_event_mask = 0
			| S(LU_EV_RX_GSUP)
			,
		.onenter = lu_fsm_wait_insert_data_result_onenter,
		.action = lu_fsm_wait_insert_data_result,
	},
};

static struct osmo_fsm lu_fsm = {
	.name = "lu",
	.states = lu_fsm_states,
	.num_states = ARRAY_SIZE(lu_fsm_states),
	.log_subsys = DLU,
	.event_names = lu_fsm_event_names,
	.timer_cb = lu_fsm_timer_cb,
	.cleanup = lu_fsm_cleanup,
};

static __attribute__((constructor)) void lu_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&lu_fsm) == 0);
}
