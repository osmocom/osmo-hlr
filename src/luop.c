/* OsmoHLR TX/RX lu operations */

/* (C) 2017 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Harald Welte <laforge@gnumonks.org>
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

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <osmocom/core/logging.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/apn.h>

#include "gsup_server.h"
#include "gsup_router.h"
#include "logging.h"
#include "luop.h"

const struct value_string lu_state_names[] = {
	{ LU_S_NULL,			"NULL" },
	{ LU_S_LU_RECEIVED,		"LU RECEIVED" },
	{ LU_S_CANCEL_SENT,		"CANCEL SENT" },
	{ LU_S_CANCEL_ACK_RECEIVED,	"CANCEL-ACK RECEIVED" },
	{ LU_S_ISD_SENT,		"ISD SENT" },
	{ LU_S_ISD_ACK_RECEIVED,	"ISD-ACK RECEIVED" },
	{ LU_S_COMPLETE,		"COMPLETE" },
	{ 0, NULL }
};

/* Transmit a given GSUP message for the given LU operation */
static void _luop_tx_gsup(struct lu_operation *luop,
			  const struct osmo_gsup_message *gsup)
{
	struct msgb *msg_out;

	msg_out = osmo_gsup_msgb_alloc("GSUP LUOP");
	OSMO_ASSERT(msg_out);
	osmo_gsup_encode(msg_out, gsup);

	osmo_gsup_gt_send(luop->gsup_server, &luop->peer, msg_out);
}

static inline void fill_gsup_msg(struct osmo_gsup_message *out,
				 const struct lu_operation *lu,
				 enum osmo_gsup_message_type mt)
{
	memset(out, 0, sizeof(struct osmo_gsup_message));
	if (lu)
		osmo_strlcpy(out->imsi, lu->subscr.imsi,
			     GSM23003_IMSI_MAX_DIGITS + 1);
	out->message_type = mt;
}

/* timer call-back in case LU operation doesn't receive an response */
static void lu_op_timer_cb(void *data)
{
	struct lu_operation *luop = data;

	DEBUGP(DMAIN, "LU OP timer expired in state %s\n",
		get_value_string(lu_state_names, luop->state));

	switch (luop->state) {
	case LU_S_CANCEL_SENT:
		break;
	case LU_S_ISD_SENT:
		break;
	default:
		break;
	}

	lu_op_tx_error(luop, GMM_CAUSE_NET_FAIL);
}

bool lu_op_fill_subscr(struct lu_operation *luop, struct db_context *dbc,
		       const char *imsi)
{
	struct hlr_subscriber *subscr = &luop->subscr;

	if (db_subscr_get_by_imsi(dbc, imsi, subscr) < 0)
		return false;

	return true;
}

struct lu_operation *lu_op_alloc(struct osmo_gsup_server *srv)
{
	struct lu_operation *luop;

	luop = talloc_zero(srv, struct lu_operation);
	OSMO_ASSERT(luop);
	luop->gsup_server = srv;
	osmo_timer_setup(&luop->timer, lu_op_timer_cb, luop);

	return luop;
}

void lu_op_free(struct lu_operation *luop)
{
	/* Only attempt to remove when it was ever added to a list. */
	if (luop->list.next)
		llist_del(&luop->list);

	/* Delete timer just in case it is still pending. */
	osmo_timer_del(&luop->timer);

	talloc_free(luop);
}

struct lu_operation *lu_op_alloc_conn(struct osmo_gsup_conn *conn)
{
	uint8_t *peer_addr;
	struct lu_operation *luop = lu_op_alloc(conn->server);
	int rc = osmo_gsup_conn_ccm_get(conn, &peer_addr, IPAC_IDTAG_SERNR);
	if (rc < 0) {
		lu_op_free(luop);
		return NULL;
	}

	if (global_title_set(&luop->peer, peer_addr, rc)) {
		LOGP(DMAIN, LOGL_ERROR, "Invalid GSUP peer name: %s\n",
		     osmo_quote_str((char*)peer_addr, rc));
		lu_op_free(luop);
		return NULL;
	}

	return luop;
}

/* FIXME: this doesn't seem to work at all */
struct lu_operation *lu_op_by_imsi(const char *imsi,
				   const struct llist_head *lst)
{
	struct lu_operation *luop;

	llist_for_each_entry(luop, lst, list) {
		if (!strcmp(imsi, luop->subscr.imsi))
			return luop;
	}
	return NULL;
}

void lu_op_statechg(struct lu_operation *luop, enum lu_state new_state)
{
	enum lu_state old_state = luop->state;

	DEBUGP(DMAIN, "LU OP state change: %s -> ",
		get_value_string(lu_state_names, old_state));
	DEBUGPC(DMAIN, "%s\n",
		get_value_string(lu_state_names, new_state));

	luop->state = new_state;
}

/*! Transmit UPD_LOC_ERROR and destroy lu_operation */
void lu_op_tx_error(struct lu_operation *luop, enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup;

	DEBUGP(DMAIN, "%s: LU OP Tx Error (cause %s)\n",
	       luop->subscr.imsi, get_value_string(gsm48_gmm_cause_names,
						   cause));

	fill_gsup_msg(&gsup, luop, OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR);
	gsup.cause = cause;

	_luop_tx_gsup(luop, &gsup);

	lu_op_free(luop);
}

/*! Transmit UPD_LOC_RESULT and destroy lu_operation */
void lu_op_tx_ack(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	fill_gsup_msg(&gsup, luop, OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT);
	//FIXME gsup.hlr_enc;

	_luop_tx_gsup(luop, &gsup);

	lu_op_free(luop);
}

/*! Send Cancel Location to old VLR/SGSN */
void lu_op_tx_cancel_old(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	OSMO_ASSERT(luop->state == LU_S_LU_RECEIVED);

	fill_gsup_msg(&gsup, NULL, OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST);
	//gsup.cause = FIXME;
	//gsup.cancel_type = FIXME;

	_luop_tx_gsup(luop, &gsup);

	lu_op_statechg(luop, LU_S_CANCEL_SENT);
	osmo_timer_schedule(&luop->timer, CANCEL_TIMEOUT_SECS, 0);
}

/*! Transmit Insert Subscriber Data to new VLR/SGSN */
void lu_op_tx_insert_subscr_data(struct lu_operation *luop)
{
	struct hlr_subscriber *subscr = &luop->subscr;
	struct osmo_gsup_message gsup = { };
	uint8_t msisdn_enc[OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN];
	uint8_t apn[APN_MAXLEN];
	enum osmo_gsup_cn_domain cn_domain;

	OSMO_ASSERT(luop->state == LU_S_LU_RECEIVED ||
		    luop->state == LU_S_CANCEL_ACK_RECEIVED);

	if (luop->is_ps)
		cn_domain = OSMO_GSUP_CN_DOMAIN_PS;
	else
		cn_domain = OSMO_GSUP_CN_DOMAIN_CS;

	if (osmo_gsup_create_insert_subscriber_data_msg(&gsup, subscr->imsi, subscr->msisdn, msisdn_enc,
							sizeof(msisdn_enc), apn, sizeof(apn), cn_domain) != 0) {
		LOGP(DMAIN, LOGL_ERROR,
		     "IMSI='%s': Cannot notify GSUP client; could not create gsup message for %s\n",
		     subscr->imsi, global_title_name(&luop->peer));
		return;
	}

	/* Send ISD to new VLR/SGSN */
	_luop_tx_gsup(luop, &gsup);

	lu_op_statechg(luop, LU_S_ISD_SENT);
	osmo_timer_schedule(&luop->timer, ISD_TIMEOUT_SECS, 0);
}

/*! Transmit Delete Subscriber Data to new VLR/SGSN.
 * The luop is not freed. */
void lu_op_tx_del_subscr_data(struct lu_operation *luop)
{
	struct osmo_gsup_message gsup;

	fill_gsup_msg(&gsup, luop, OSMO_GSUP_MSGT_DELETE_DATA_REQUEST);

	gsup.cn_domain = OSMO_GSUP_CN_DOMAIN_PS;

	/* Send ISD to new VLR/SGSN */
	_luop_tx_gsup(luop, &gsup);
}
