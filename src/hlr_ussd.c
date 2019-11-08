/* OsmoHLR SS/USSD implementation */

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
#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "hlr.h"
#include "hlr_ussd.h"
#include "gsup_server.h"
#include "gsup_router.h"
#include "logging.h"
#include "db.h"

/***********************************************************************
 * core data structures expressing config from VTY
 ***********************************************************************/

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
	llist_add_tail(&euse->list, &hlr->euse_list);

	return euse;
}

void euse_del(struct hlr_euse *euse)
{
	llist_del(&euse->list);
	talloc_free(euse);
}


struct hlr_ussd_route *ussd_route_find_prefix(struct hlr *hlr, const char *prefix)
{
	struct hlr_ussd_route *rt;

	llist_for_each_entry(rt, &hlr->ussd_routes, list) {
		if (!strcmp(rt->prefix, prefix))
			return rt;
	}
	return NULL;
}

struct hlr_ussd_route *ussd_route_prefix_alloc_int(struct hlr *hlr, const char *prefix,
						   const struct hlr_iuse *iuse)
{
	struct hlr_ussd_route *rt;

	if (ussd_route_find_prefix(hlr, prefix))
		return NULL;

	rt = talloc_zero(hlr, struct hlr_ussd_route);
	rt->prefix = talloc_strdup(rt, prefix);
	rt->u.iuse = iuse;
	llist_add_tail(&rt->list, &hlr->ussd_routes);

	return rt;
}

struct hlr_ussd_route *ussd_route_prefix_alloc_ext(struct hlr *hlr, const char *prefix,
						   struct hlr_euse *euse)
{
	struct hlr_ussd_route *rt;

	if (ussd_route_find_prefix(hlr, prefix))
		return NULL;

	rt = talloc_zero(hlr, struct hlr_ussd_route);
	rt->prefix = talloc_strdup(rt, prefix);
	rt->is_external = true;
	rt->u.euse = euse;
	llist_add_tail(&rt->list, &hlr->ussd_routes);

	return rt;
}

void ussd_route_del(struct hlr_ussd_route *rt)
{
	llist_del(&rt->list);
	talloc_free(rt);
}

static struct hlr_ussd_route *ussd_route_lookup_7bit(struct hlr *hlr, const char *ussd_code)
{
	struct hlr_ussd_route *rt;
	llist_for_each_entry(rt, &hlr->ussd_routes, list) {
		if (!strncmp(ussd_code, rt->prefix, strlen(rt->prefix))) {
			LOGP(DSS, LOGL_DEBUG, "Found %s '%s' (prefix '%s') for USSD "
				"Code '%s'\n", rt->is_external ? "EUSE" : "IUSE",
				rt->is_external ? rt->u.euse->name : rt->u.iuse->name,
				rt->prefix, ussd_code);
			return rt;
		}
	}

	LOGP(DSS, LOGL_DEBUG, "Could not find Route for USSD Code '%s'\n", ussd_code);
	return NULL;
}

/***********************************************************************
 * handling functions for individual GSUP messages
 ***********************************************************************/

#define LOGPSS(ss, lvl, fmt, args...) \
	LOGP(DSS, lvl, "%s/0x%08x: " fmt, (ss)->imsi, (ss)->session_id, ## args)

struct ss_session {
	/* link us to hlr->ss_sessions */
	struct llist_head list;
	/* imsi of this session */
	char imsi[OSMO_IMSI_BUF_SIZE];
	/* ID of this session (unique per IMSI) */
	uint32_t session_id;
	/* state of the session */
	enum osmo_gsup_session_state state;
	/* time-out when we will delete the session */
	struct osmo_timer_list timeout;

	/* is this USSD for an external handler (EUSE): true */
	bool is_external;
	union {
		/* external USSD Entity responsible for this session */
		struct hlr_euse *euse;
		/* internal USSD Entity responsible for this session */
		const struct hlr_iuse *iuse;
	} u;

	/* subscriber's vlr_number
	 * MO USSD: originating MSC's vlr_number
	 * MT USSD: looked up once per session and cached here */
	struct global_title vlr_name;

	/* we don't keep a pointer to the osmo_gsup_{route,conn} towards the MSC/VLR here,
	 * as this might change during inter-VLR hand-over, and we simply look-up the serving MSC/VLR
	 * every time we receive an USSD component from the EUSE */

	struct osmo_gsup_req *initial_req_from_ms;
	struct osmo_gsup_req *initial_req_from_euse;
};

struct ss_session *ss_session_find(struct hlr *hlr, const char *imsi, uint32_t session_id)
{
	struct ss_session *ss;
	llist_for_each_entry(ss, &hlr->ss_sessions, list) {
		if (!strcmp(ss->imsi, imsi) && ss->session_id == session_id)
			return ss;
	}
	return NULL;
}

void ss_session_free(struct ss_session *ss)
{
	osmo_timer_del(&ss->timeout);
	if (ss->initial_req_from_ms)
		osmo_gsup_req_free(ss->initial_req_from_ms);
	if (ss->initial_req_from_euse)
		osmo_gsup_req_free(ss->initial_req_from_euse);
	llist_del(&ss->list);
	talloc_free(ss);
}

static void ss_session_timeout(void *data)
{
	struct ss_session *ss = data;

	LOGPSS(ss, LOGL_NOTICE, "SS Session Timeout, destroying\n");
	/* FIXME: should we send a ReturnError component to the MS? */
	ss_session_free(ss);
}

struct ss_session *ss_session_alloc(struct hlr *hlr, const char *imsi, uint32_t session_id)
{
	struct ss_session *ss;

	OSMO_ASSERT(!ss_session_find(hlr, imsi, session_id));

	ss = talloc_zero(hlr, struct ss_session);
	OSMO_ASSERT(ss);

	OSMO_STRLCPY_ARRAY(ss->imsi, imsi);
	ss->session_id = session_id;

	/* Schedule self-destruction timer */
	osmo_timer_setup(&ss->timeout, ss_session_timeout, ss);
	if (g_hlr->ncss_guard_timeout > 0)
		osmo_timer_schedule(&ss->timeout, g_hlr->ncss_guard_timeout, 0);

	llist_add_tail(&ss->list, &hlr->ss_sessions);
	return ss;
}

/***********************************************************************
 * handling functions for encoding SS messages + wrapping them in GSUP
 ***********************************************************************/

/* Resolve the target MSC by ss->imsi and send GSUP message. */
static int ss_gsup_send_to_ms(struct ss_session *ss, struct osmo_gsup_server *gs, struct osmo_gsup_message *gsup)
{
	struct hlr_subscriber subscr = {};
	struct msgb *msg;
	int rc;

	if (ss->initial_req_from_ms) {
		/* If this is a response to an incoming GSUP request from the MS, respond via osmo_gsup_req_respond() to
		 * make sure that all required routing information is kept intact.
		 * Use osmo_gsup_req_respond_nonfinal() to not deallocate the ss->initial_req_from_ms */
		osmo_gsup_req_respond_nonfinal(ss->initial_req_from_ms, gsup);
		return 0;
	}

	msg = osmo_gsup_msgb_alloc("GSUP USSD FW");
	rc = osmo_gsup_encode(msg, gsup);
	if (rc) {
		LOGPSS(ss, LOGL_ERROR, "Failed to encode GSUP message\n");
		return rc;
	}

	/* Use vlr_number as looked up by the caller, or look up now. */
	if (!ss->vlr_name.len) {
		rc = db_subscr_get_by_imsi(g_hlr->dbc, ss->imsi, &subscr);
		if (rc < 0) {
			LOGPSS(ss, LOGL_ERROR, "Cannot find subscriber, cannot route GSUP message\n");
			msgb_free(msg);
			return -EINVAL;
		}
		global_title_set_str(&ss->vlr_name, subscr.vlr_number);
	}

	/* Check for empty string (all vlr_number strings end in "\0", because otherwise gsup_route_find() fails) */
	if (ss->vlr_name.len <= 1) {
		LOGPSS(ss, LOGL_ERROR, "Cannot send GSUP message, no VLR number stored for subscriber\n");
		msgb_free(msg);
		return -EINVAL;
	}

	LOGPSS(ss, LOGL_DEBUG, "Tx SS/USSD to VLR %s\n", global_title_name(&ss->vlr_name));
	return osmo_gsup_gt_send(gs, &ss->vlr_name, msg);
}

static int ss_tx_to_ms(struct ss_session *ss, enum osmo_gsup_message_type gsup_msg_type,
		       bool final, struct msgb *ss_msg)

{
	struct osmo_gsup_message resp = {
		.message_type = gsup_msg_type,
		.session_id = ss->session_id,
	};
	int rc;

	OSMO_STRLCPY_ARRAY(resp.imsi, ss->imsi);
	if (final)
		resp.session_state = OSMO_GSUP_SESSION_STATE_END;
	else
		resp.session_state = OSMO_GSUP_SESSION_STATE_CONTINUE;
	if (ss_msg) {
		resp.ss_info = msgb_data(ss_msg);
		resp.ss_info_len = msgb_length(ss_msg);
	}

	rc = ss_gsup_send_to_ms(ss, g_hlr->gs, &resp);

	msgb_free(ss_msg);
	return rc;
}

#if 0
static int ss_tx_reject(struct ss_session *ss, int invoke_id, uint8_t problem_tag,
			uint8_t problem_code)
{
	struct msgb *msg = gsm0480_gen_reject(invoke_id, problem_tag, problem_code);
	LOGPSS(ss, LOGL_NOTICE, "Tx Reject(%u, 0x%02x, 0x%02x)\n", invoke_id,
		problem_tag, problem_code);
	OSMO_ASSERT(msg);
	return ss_tx_to_ms(ss, OSMO_GSUP_MSGT_PROC_SS_RESULT, true, msg);
}
#endif

static int ss_tx_to_ms_error(struct ss_session *ss, uint8_t invoke_id, uint8_t error_code)
{
	struct msgb *msg = gsm0480_gen_return_error(invoke_id, error_code);
	LOGPSS(ss, LOGL_NOTICE, "Tx ReturnError(%u, 0x%02x)\n", invoke_id, error_code);
	OSMO_ASSERT(msg);
	return ss_tx_to_ms(ss, OSMO_GSUP_MSGT_PROC_SS_RESULT, true, msg);
}

static int ss_tx_to_ms_ussd_7bit(struct ss_session *ss, bool final, uint8_t invoke_id, const char *text)
{
	struct msgb *msg = gsm0480_gen_ussd_resp_7bit(invoke_id, text);
	LOGPSS(ss, LOGL_INFO, "Tx USSD '%s'\n", text);
	OSMO_ASSERT(msg);
	return ss_tx_to_ms(ss, OSMO_GSUP_MSGT_PROC_SS_RESULT, final, msg);
}

/***********************************************************************
 * Internal USSD Handlers
 ***********************************************************************/

#include "db.h"

static int handle_ussd_own_msisdn(struct ss_session *ss,
				  const struct osmo_gsup_message *gsup, const struct ss_request *req)
{
	struct hlr_subscriber subscr;
	char buf[GSM0480_USSD_7BIT_STRING_LEN+1];
	int rc;

	rc = db_subscr_get_by_imsi(g_hlr->dbc, ss->imsi, &subscr);
	switch (rc) {
	case 0:
		if (strlen(subscr.msisdn) == 0)
			snprintf(buf, sizeof(buf), "You have no MSISDN!");
		else
			snprintf(buf, sizeof(buf), "Your extension is %s", subscr.msisdn);
		ss_tx_to_ms_ussd_7bit(ss, true, req->invoke_id, buf);
		break;
	case -ENOENT:
		ss_tx_to_ms_error(ss, req->invoke_id, GSM0480_ERR_CODE_UNKNOWN_SUBSCRIBER);
		break;
	case -EIO:
	default:
		ss_tx_to_ms_error(ss, req->invoke_id, GSM0480_ERR_CODE_SYSTEM_FAILURE);
		break;
	}
	return 0;
}

static int handle_ussd_own_imsi(struct ss_session *ss,
				const struct osmo_gsup_message *gsup, const struct ss_request *req)
{
	char buf[GSM0480_USSD_7BIT_STRING_LEN+1];
	snprintf(buf, sizeof(buf), "Your IMSI is %s", ss->imsi);
	ss_tx_to_ms_ussd_7bit(ss, true, req->invoke_id, buf);
	return 0;
}


static const struct hlr_iuse hlr_iuses[] = {
	{
		.name = "own-msisdn",
		.handle_ussd = handle_ussd_own_msisdn,
	},
	{
		.name = "own-imsi",
		.handle_ussd = handle_ussd_own_imsi,
	},
};

const struct hlr_iuse *iuse_find(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(hlr_iuses); i++) {
		const struct hlr_iuse *iuse = &hlr_iuses[i];
		if (!strcmp(name, iuse->name))
			return iuse;
	}
	return NULL;
}


/***********************************************************************
 * handling functions for individual GSUP messages
 ***********************************************************************/

static bool ss_op_is_ussd(uint8_t opcode)
{
	switch (opcode) {
	case GSM0480_OP_CODE_PROCESS_USS_DATA:
	case GSM0480_OP_CODE_PROCESS_USS_REQ:
	case GSM0480_OP_CODE_USS_REQUEST:
	case GSM0480_OP_CODE_USS_NOTIFY:
		return true;
	default:
		return false;
	}
}

/* is this GSUP connection an EUSE (true) or not (false)? */
static bool peer_name_is_euse(const struct global_title *peer_name)
{
	if (peer_name->len <= 5)
		return false;
	if (!strncmp((char *)(peer_name->val), "EUSE-", 5))
		return true;
	else
		return false;
}

static struct hlr_euse *euse_by_name(const struct global_title *peer_name)
{
	if (!peer_name_is_euse(peer_name))
		return NULL;

	return euse_find(g_hlr, (const char*)(peer_name->val)+5);
}

static int handle_ss(struct ss_session *ss, bool is_euse_originated, const struct osmo_gsup_message *gsup,
		     const struct ss_request *req)
{
	uint8_t comp_type = gsup->ss_info[0];

	LOGPSS(ss, LOGL_INFO, "SS CompType=%s, OpCode=%s\n",
		gsm0480_comp_type_name(comp_type), gsm0480_op_code_name(req->opcode));

	/**
	 * FIXME: As we don't store any SS related information
	 * (e.g. call forwarding preferences) in the database,
	 * we don't handle "structured" SS requests at all.
	 */
	LOGPSS(ss, LOGL_NOTICE, "Structured SS requests are not supported, rejecting...\n");
	ss_tx_to_ms_error(ss, req->invoke_id, GSM0480_ERR_CODE_FACILITY_NOT_SUPPORTED);
	return -ENOTSUP;
}

/* Handle a USSD GSUP message for a given SS Session received from VLR or EUSE */
static int handle_ussd(struct ss_session *ss, bool is_euse_originated, const struct osmo_gsup_message *gsup,
		       const struct ss_request *req)
{
	uint8_t comp_type = gsup->ss_info[0];
	struct msgb *msg_out;

	LOGPSS(ss, LOGL_INFO, "USSD CompType=%s, OpCode=%s '%s'\n",
		gsm0480_comp_type_name(comp_type), gsm0480_op_code_name(req->opcode),
		req->ussd_text);

	if ((ss->is_external && !ss->u.euse) || !ss->u.iuse) {
		LOGPSS(ss, LOGL_NOTICE, "USSD for unknown code '%s'\n", req->ussd_text);
		ss_tx_to_ms_error(ss, req->invoke_id, GSM0480_ERR_CODE_SS_NOT_AVAILABLE);
		return 0;
	}

	if (is_euse_originated) {
		/* Received from EUSE, Forward to VLR */
		/* Need a non-const osmo_gsup_message, because sending might modify some (routing related?) parts. */
		struct osmo_gsup_message forward = *gsup;
		ss_gsup_send_to_ms(ss, g_hlr->gs, &forward);
	} else {
		/* Received from VLR (MS) */
		if (ss->is_external) {
			/* Forward to EUSE */
			struct global_title euse_name;
			struct osmo_gsup_conn *conn;
			global_title_set_str(&euse_name, "EUSE-%s", ss->u.euse->name);
			conn = gsup_route_find_gt(g_hlr->gs, &euse_name);
			if (!conn) {
				LOGPSS(ss, LOGL_ERROR, "Cannot find conn for EUSE %s\n",
				       global_title_name(&euse_name));
				ss_tx_to_ms_error(ss, req->invoke_id, GSM0480_ERR_CODE_SYSTEM_FAILURE);
			} else {
				msg_out = osmo_gsup_msgb_alloc("GSUP USSD FW");
				OSMO_ASSERT(msg_out);
				osmo_gsup_encode(msg_out, gsup);
				osmo_gsup_conn_send(conn, msg_out);
			}
		} else {
			/* Handle internally */
			ss->u.iuse->handle_ussd(ss, gsup, req);
			/* Release session immediately */
			ss_session_free(ss);
			return 0;
		}
	}

	return 0;
}


/* this function is called for any SS_REQ/SS_RESP messages from both the MSC/VLR side as well
 * as from the EUSE side */
void rx_proc_ss_req(struct osmo_gsup_req *gsup_req)
{
	struct hlr *hlr = g_hlr;
	struct ss_session *ss;
	struct ss_request req = {0};
	const struct osmo_gsup_message *gsup = &gsup_req->gsup;
	/* Remember whether this function should free the incoming gsup_req: if it is placed as ss->initial_req_from_*,
	 * do not free it here. If not, free it here. */
	struct osmo_gsup_req *free_gsup_req = gsup_req;
	bool is_euse_originated = peer_name_is_euse(&gsup_req->source_name);

	LOGP(DSS, LOGL_DEBUG, "%s/0x%08x: Process SS (%s)\n", gsup->imsi, gsup->session_id,
		osmo_gsup_session_state_name(gsup->session_state));

	/* decode and find out what kind of SS message it is */
	if (gsup->ss_info && gsup->ss_info_len) {
		if (gsm0480_parse_facility_ie(gsup->ss_info, gsup->ss_info_len, &req)) {
			LOGP(DSS, LOGL_ERROR, "%s/0x%082x: Unable to parse SS request: %s\n",
				gsup->imsi, gsup->session_id,
				osmo_hexdump(gsup->ss_info, gsup->ss_info_len));
			osmo_gsup_req_respond_err(gsup_req, GMM_CAUSE_INV_MAND_INFO, "error parsing SS request");
			return;
		}
	} else if (gsup->session_state != OSMO_GSUP_SESSION_STATE_END) {
		LOGP(DSS, LOGL_ERROR, "%s/0x%082x: Missing SS payload for '%s'\n",
		     gsup->imsi, gsup->session_id,
		     osmo_gsup_session_state_name(gsup->session_state));
		osmo_gsup_req_respond_err(gsup_req, GMM_CAUSE_INV_MAND_INFO, "missing SS payload");
		return;
	}

	switch (gsup->session_state) {
	case OSMO_GSUP_SESSION_STATE_BEGIN:
		/* Check for overlapping Session ID usage */
		if (ss_session_find(hlr, gsup->imsi, gsup->session_id)) {
			LOGP(DSS, LOGL_ERROR, "%s/0x%08x: BEGIN with non-unique session ID!\n",
				gsup->imsi, gsup->session_id);
			osmo_gsup_req_respond_err(gsup_req, GMM_CAUSE_INV_MAND_INFO, "BEGIN with non-unique session ID");
			return;
		}
		ss = ss_session_alloc(hlr, gsup->imsi, gsup->session_id);
		if (!ss) {
			LOGP(DSS, LOGL_ERROR, "%s/0x%08x: Unable to allocate SS session\n",
				gsup->imsi, gsup->session_id);
			osmo_gsup_req_respond_err(gsup_req, GMM_CAUSE_NET_FAIL, "Unable to allocate SS session");
			return;
		}
		/* Get IPA name from VLR conn and save as ss->vlr_number */
		if (!is_euse_originated) {
			ss->initial_req_from_ms = gsup_req;
			free_gsup_req = NULL;
			ss->vlr_name = gsup_req->source_name;
		} else {
			ss->initial_req_from_euse = gsup_req;
			free_gsup_req = NULL;
		}
		if (ss_op_is_ussd(req.opcode)) {
			if (is_euse_originated) {
				/* EUSE->VLR: MT USSD. EUSE is known ('conn'), VLR is to be resolved */
				ss->u.euse = euse_by_name(&gsup_req->source_name);
			} else {
				/* VLR->EUSE: MO USSD. VLR is known ('conn'), EUSE is to be resolved */
				struct hlr_ussd_route *rt;
				rt = ussd_route_lookup_7bit(hlr, (const char *) req.ussd_text);
				if (rt) {
					if (rt->is_external) {
						ss->is_external = true;
						ss->u.euse = rt->u.euse;
					} else if (rt) {
						ss->is_external = false;
						ss->u.iuse = rt->u.iuse;
					}
				} else {
					if (hlr->euse_default) {
						ss->is_external = true;
						ss->u.euse = hlr->euse_default;
					}
				}
			}
			/* dispatch unstructured SS to routing */
			handle_ussd(ss, is_euse_originated, &gsup_req->gsup, &req);
		} else {
			/* dispatch non-call SS to internal code */
			handle_ss(ss, is_euse_originated, &gsup_req->gsup, &req);
		}
		break;
	case OSMO_GSUP_SESSION_STATE_CONTINUE:
		ss = ss_session_find(hlr, gsup->imsi, gsup->session_id);
		if (!ss) {
			LOGP(DSS, LOGL_ERROR, "%s/0x%08x: CONTINUE for unknown SS session\n",
				gsup->imsi, gsup->session_id);
			osmo_gsup_req_respond_err(gsup_req, GMM_CAUSE_INV_MAND_INFO, "CONTINUE for unknown SS session");
			return;
		}

		/* Reschedule self-destruction timer */
		if (g_hlr->ncss_guard_timeout > 0)
			osmo_timer_schedule(&ss->timeout, g_hlr->ncss_guard_timeout, 0);

		if (ss_op_is_ussd(req.opcode)) {
			/* dispatch unstructured SS to routing */
			handle_ussd(ss, is_euse_originated, &gsup_req->gsup, &req);
		} else {
			/* dispatch non-call SS to internal code */
			handle_ss(ss, is_euse_originated, &gsup_req->gsup, &req);
		}
		break;
	case OSMO_GSUP_SESSION_STATE_END:
		ss = ss_session_find(hlr, gsup->imsi, gsup->session_id);
		if (!ss) {
			LOGP(DSS, LOGL_ERROR, "%s/0x%08x: END for unknown SS session\n",
				gsup->imsi, gsup->session_id);
			return;
		}

		/* SS payload is optional for END */
		if (gsup->ss_info && gsup->ss_info_len) {
			if (ss_op_is_ussd(req.opcode)) {
				/* dispatch unstructured SS to routing */
				handle_ussd(ss, is_euse_originated, &gsup_req->gsup, &req);
			} else {
				/* dispatch non-call SS to internal code */
				handle_ss(ss, is_euse_originated, &gsup_req->gsup, &req);
			}
		}

		ss_session_free(ss);
		break;
	default:
		LOGP(DSS, LOGL_ERROR, "%s/0x%08x: Unknown SS State %d\n", gsup->imsi,
			gsup->session_id, gsup->session_state);
		break;
	}

	if (free_gsup_req)
		osmo_gsup_req_free(free_gsup_req);
}

void rx_proc_ss_error(struct osmo_gsup_req *req)
{
	LOGP(DSS, LOGL_NOTICE, "%s/0x%08x: Process SS ERROR (%s)\n", req->gsup.imsi, req->gsup.session_id,
		osmo_gsup_session_state_name(req->gsup.session_state));
}
