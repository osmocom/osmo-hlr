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

#include "hlr.h"
#include "hlr_ussd.h"
#include "gsup_server.h"
#include "gsup_router.h"
#include "logging.h"

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

struct hlr_euse *ussd_euse_find_7bit_gsm(struct hlr *hlr, const char *ussd_code)
{
	struct hlr_euse *euse;

	llist_for_each_entry(euse, &hlr->euse_list, list) {
		struct hlr_euse_route *rt;
		llist_for_each_entry(rt, &euse->routes, list) {
			if (!strncmp(ussd_code, rt->prefix, strlen(rt->prefix))) {
				LOGP(DMAIN, LOGL_DEBUG, "Found EUSE %s (prefix %s) for USSD Code '%s'\n",
					rt->euse->name, rt->prefix, ussd_code);
				return rt->euse;
			}
		}
	}

	LOGP(DMAIN, LOGL_DEBUG, "Could not find Route/EUSE for USSD Code '%s'\n", ussd_code);
	return NULL;
}

/***********************************************************************
 * handling functions for individual GSUP messages
 ***********************************************************************/

#define LOGPSS(ss, lvl, fmt, args...) \
	LOGP(DMAIN, lvl, "%s/0x%08x: " fmt, (ss)->imsi, (ss)->session_id, ## args)

struct ss_session {
	/* link us to hlr->ss_sessions */
	struct llist_head list;
	/* imsi of this session */
	char imsi[GSM23003_IMSI_MAX_DIGITS+2];
	/* ID of this session (unique per IMSI) */
	uint32_t session_id;
	/* state of the session */
	enum osmo_gsup_session_state state;
	/* time-out when we will delete the session */
	struct osmo_timer_list timeout;

	/* external USSD Entity responsible for this session */
	struct hlr_euse *euse;
	/* we don't keep a pointer to the osmo_gsup_{route,conn} towards the MSC/VLR here,
	 * as this might change during inter-VLR hand-over, and we simply look-up the serving MSC/VLR
	 * every time we receive an USSD component from the EUSE */
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
	osmo_timer_setup(&ss->timeout, ss_session_timeout, ss);
	/* NOTE: The timeout is currently global and not refreshed with subsequent messages
	 * within the SS/USSD session.  So 30s after the initial SS message, the session will
	 * timeout! */
	osmo_timer_schedule(&ss->timeout, 30, 0);

	llist_add_tail(&ss->list, &hlr->ss_sessions);
	return ss;
}

/***********************************************************************
 * handling functions for encoding SS messages + wrapping them in GSUP
 ***********************************************************************/

static int ss_tx_to_ms(struct ss_session *ss, enum osmo_gsup_message_type gsup_msg_type,
			bool final, struct msgb *ss_msg)

{
	struct osmo_gsup_message resp = {0};
	struct msgb *resp_msg;

	resp.message_type = gsup_msg_type;
	OSMO_STRLCPY_ARRAY(resp.imsi, ss->imsi);
	if (final)
		resp.session_state = OSMO_GSUP_SESSION_STATE_END;
	else
		resp.session_state = OSMO_GSUP_SESSION_STATE_CONTINUE;
	resp.session_id = ss->session_id;
	if (ss_msg) {
		resp.ss_info = msgb_data(ss_msg);
		resp.ss_info_len = msgb_length(ss_msg);
	}

	resp_msg = gsm0480_msgb_alloc_name(__func__);
	OSMO_ASSERT(resp_msg);
	osmo_gsup_encode(resp_msg, &resp);
	msgb_free(ss_msg);

	/* FIXME: resolve this based on the database vlr_addr */
	return osmo_gsup_addr_send(g_hlr->gs, (uint8_t *)"MSC-00-00-00-00-00-00", 22, resp_msg);
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

static int ss_tx_error(struct ss_session *ss, uint8_t invoke_id, uint8_t error_code)
{
	struct msgb *msg = gsm0480_gen_return_error(invoke_id, error_code);
	LOGPSS(ss, LOGL_NOTICE, "Tx ReturnError(%u, 0x%02x)\n", invoke_id, error_code);
	OSMO_ASSERT(msg);
	return ss_tx_to_ms(ss, OSMO_GSUP_MSGT_PROC_SS_RESULT, true, msg);
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
static bool conn_is_euse(struct osmo_gsup_conn *conn)
{
	int rc;
	uint8_t *addr;

	rc = osmo_gsup_conn_ccm_get(conn, &addr, IPAC_IDTAG_SERNR);
	if (rc <= 5)
		return false;
	if (!strncmp((char *)addr, "EUSE-", 5))
		return true;
	else
		return false;
}

static struct hlr_euse *euse_by_conn(struct osmo_gsup_conn *conn)
{
	int rc;
	char *addr;
	struct hlr *hlr = conn->server->priv;

	rc = osmo_gsup_conn_ccm_get(conn, (uint8_t **) &addr, IPAC_IDTAG_SERNR);
	if (rc <= 5)
		return NULL;
	if (strncmp(addr, "EUSE-", 5))
		return NULL;

	return euse_find(hlr, addr+5);
}

static int handle_ss(struct ss_session *ss, const struct osmo_gsup_message *gsup,
			const struct ss_request *req)
{
	uint8_t comp_type = gsup->ss_info[0];

	LOGPSS(ss, LOGL_INFO, "SS CompType=%s, OpCode=%s\n",
		gsm0480_comp_type_name(comp_type), gsm0480_op_code_name(req->opcode));
	/* FIXME */
	return 0;
}

static int handle_ussd(struct osmo_gsup_conn *conn, struct ss_session *ss,
			const struct osmo_gsup_message *gsup, const struct ss_request *req)
{
	uint8_t comp_type = gsup->ss_info[0];
	struct msgb *msg_out;
	bool is_euse_originated = conn_is_euse(conn);

	LOGPSS(ss, LOGL_INFO, "USSD CompType=%s, OpCode=%s '%s'\n",
		gsm0480_comp_type_name(comp_type), gsm0480_op_code_name(req->opcode),
		req->ussd_text);


	if (!ss->euse) {
		LOGPSS(ss, LOGL_NOTICE, "USSD for unknown code '%s'\n", req->ussd_text);
		ss_tx_error(ss, req->invoke_id, GSM0480_ERR_CODE_SS_NOT_AVAILABLE);
		return 0;
	}

	if (is_euse_originated) {
		msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP USSD FW");
		OSMO_ASSERT(msg_out);
		/* Received from EUSE, Forward to VLR */
		osmo_gsup_encode(msg_out, gsup);
		/* FIXME: resolve this based on the database vlr_addr */
		osmo_gsup_addr_send(conn->server, (uint8_t *)"MSC-00-00-00-00-00-00", 22, msg_out);
	} else {
		/* Received from VLR, Forward to EUSE */
		char addr[128];
		strcpy(addr, "EUSE-");
		osmo_strlcpy(addr+5, ss->euse->name, sizeof(addr)-5);
		conn = gsup_route_find(conn->server, (uint8_t *)addr, strlen(addr)+1);
		if (!conn) {
			LOGPSS(ss, LOGL_ERROR, "Cannot find conn for EUSE %s\n", addr);
			ss_tx_error(ss, req->invoke_id, GSM0480_ERR_CODE_SYSTEM_FAILURE);
		} else {
			msg_out = msgb_alloc_headroom(1024+16, 16, "GSUP USSD FW");
			OSMO_ASSERT(msg_out);
			osmo_gsup_encode(msg_out, gsup);
			osmo_gsup_conn_send(conn, msg_out);
		}
	}

	return 0;
}


/* this function is called for any SS_REQ/SS_RESP messages from both the MSC/VLR side as well
 * as from the EUSE side */
int rx_proc_ss_req(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup)
{
	struct hlr *hlr = conn->server->priv;
	struct ss_session *ss;
	struct ss_request req = {0};

	LOGP(DMAIN, LOGL_INFO, "%s/0x%08x: Process SS (%s)\n", gsup->imsi, gsup->session_id,
		osmo_gsup_session_state_name(gsup->session_state));

	/* decode and find out what kind of SS message it is */
	if (gsup->ss_info && gsup->ss_info_len) {
		if (gsm0480_parse_facility_ie(gsup->ss_info, gsup->ss_info_len, &req)) {
			LOGP(DMAIN, LOGL_ERROR, "%s/0x%082x: Unable to parse SS request: %s\n",
				gsup->imsi, gsup->session_id,
				osmo_hexdump(gsup->ss_info, gsup->ss_info_len));
			/* FIXME: Send a Reject component? */
			goto out_err;
		}
	}

	switch (gsup->session_state) {
	case OSMO_GSUP_SESSION_STATE_BEGIN:
		/* Check for overlapping Session ID usage */
		if (ss_session_find(hlr, gsup->imsi, gsup->session_id)) {
			LOGP(DMAIN, LOGL_ERROR, "%s/0x%08x: BEGIN with non-unique session ID!\n",
				gsup->imsi, gsup->session_id);
			goto out_err;
		}
		ss = ss_session_alloc(hlr, gsup->imsi, gsup->session_id);
		if (!ss) {
			LOGP(DMAIN, LOGL_ERROR, "%s/0x%08x: Unable to allocate SS session\n",
				gsup->imsi, gsup->session_id);
			goto out_err;
		}
		if (ss_op_is_ussd(req.opcode)) {
			if (conn_is_euse(conn)) {
				/* EUSE->VLR: MT USSD. EUSE is known ('conn'), VLR is to be resolved */
				ss->euse = euse_by_conn(conn);
			} else {
				/* VLR->EUSE: MO USSD. VLR is known ('conn'), EUSE is to be resolved */
				ss->euse = ussd_euse_find_7bit_gsm(hlr, (const char *) req.ussd_text);
			}
			/* dispatch unstructured SS to routing */
			handle_ussd(conn, ss, gsup, &req);
		} else {
			/* dispatch non-call SS to internal code */
			handle_ss(ss, gsup, &req);
		}
		break;
	case OSMO_GSUP_SESSION_STATE_CONTINUE:
		ss = ss_session_find(hlr, gsup->imsi, gsup->session_id);
		if (!ss) {
			LOGP(DMAIN, LOGL_ERROR, "%s/0x%08x: CONTINUE for unknown SS session\n",
				gsup->imsi, gsup->session_id);
			goto out_err;
		}
		if (ss_op_is_ussd(req.opcode)) {
			/* dispatch unstructured SS to routing */
			handle_ussd(conn, ss, gsup, &req);
		} else {
			/* dispatch non-call SS to internal code */
			handle_ss(ss, gsup, &req);
		}
		break;
	case OSMO_GSUP_SESSION_STATE_END:
		ss = ss_session_find(hlr, gsup->imsi, gsup->session_id);
		if (!ss) {
			LOGP(DMAIN, LOGL_ERROR, "%s/0x%08x: END for unknown SS session\n",
				gsup->imsi, gsup->session_id);
			goto out_err;
		}
		if (ss_op_is_ussd(req.opcode)) {
			/* dispatch unstructured SS to routing */
			handle_ussd(conn, ss, gsup, &req);
		} else {
			/* dispatch non-call SS to internal code */
			handle_ss(ss, gsup, &req);
		}
		ss_session_free(ss);
		break;
	default:
		LOGP(DMAIN, LOGL_ERROR, "%s/0x%08x: Unknown SS State %d\n", gsup->imsi,
			gsup->session_id, gsup->session_state);
		goto out_err;
	}

	return 0;

out_err:
	return 0;
}

int rx_proc_ss_error(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup)
{
	LOGP(DMAIN, LOGL_NOTICE, "%s/0x%08x: Process SS ERROR (%s)\n", gsup->imsi, gsup->session_id,
		osmo_gsup_session_state_name(gsup->session_state));
	return 0;
}
