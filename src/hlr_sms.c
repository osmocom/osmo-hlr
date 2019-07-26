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
#include <osmocom/core/utils.h>

#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/gsm/gsm48_ie.h>
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

/* Common helper for preparing to be encoded GSUP message */
static void gsup_prepare_sm_error(struct osmo_gsup_message *msg,
				  const struct osmo_gsup_message *src_msg)
{
	/* Init a mew GSUP message */
	*msg = (struct osmo_gsup_message) {
		.message_type = OSMO_GSUP_TO_MSGT_ERROR(src_msg->message_type),
		.message_class = OSMO_GSUP_MESSAGE_CLASS_SMS,
		.sm_rp_mr = src_msg->sm_rp_mr,

		/* Swap optional source and destination addresses */
		.destination_name_len = src_msg->source_name_len,
		.destination_name = src_msg->source_name,
	};

	/* Fill in subscriber's IMSI */
	OSMO_STRLCPY_ARRAY(msg->imsi, src_msg->imsi);
}

static int gsup_conn_enc_send(struct osmo_gsup_conn *conn,
			      struct osmo_gsup_message *msg)
{
	struct msgb *gsup_msgb;
	int rc;

	gsup_msgb = msgb_alloc_headroom(512, 64, __func__);
	if (!gsup_msgb) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to allocate a GSUP message\n");
		return -ENOMEM;
	}

	rc = osmo_gsup_encode(gsup_msgb, msg);
	if (rc) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to encode GSUP message '%s' (rc=%d)\n",
		     osmo_gsup_message_type_name(msg->message_type), rc);
		return rc;
	}

	rc = osmo_gsup_conn_send(conn, gsup_msgb);
	if (rc) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to send GSUP message '%s' (rc=%d)\n",
		     osmo_gsup_message_type_name(msg->message_type), rc);
		return rc;
	}

	return 0;
}

/* Short Message delivery status, to be forwarded 'as-is' */
int forward_sm_res_or_err(struct osmo_gsup_conn *conn,
			  const struct osmo_gsup_message *gsup,
			  struct msgb *msg)
{
	struct hlr_subscriber subscr;
	char src_name_buf[32];
	char dst_name_buf[32];
	int rc;

	rc = db_subscr_get_by_imsi(g_hlr->dbc, gsup->imsi, &subscr);
	if (rc) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' for unknown subscriber IMSI-%s\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi);
		/* TODO: send some error back? */
		msgb_free(msg);
		return -ENODEV;
	}

	/* Make sure destination name is present */
	if (gsup->destination_name == NULL || !gsup->destination_name_len) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' (IMSI-%s) without destination name\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi);
		/* TODO: send some error back? */
		msgb_free(msg);
		return -EINVAL;
	}

	/* Make sure source name is present */
	if (gsup->source_name == NULL || !gsup->source_name_len) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' (IMSI-%s) without source name\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi);
		/* TODO: send some error back? */
		msgb_free(msg);
		return -EINVAL;
	}

	LOGP(DLSMS, LOGL_INFO, "Forward '%s' (IMSI-%s) from %s to %s\n",
	     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi,
	     osmo_quote_str_buf2(src_name_buf, sizeof(src_name_buf),
				 (const char *) gsup->source_name,
				 gsup->source_name_len),
	     osmo_quote_str_buf2(dst_name_buf, sizeof(dst_name_buf),
				 (const char *) gsup->destination_name,
				 gsup->destination_name_len));

	rc = osmo_gsup_addr_send(conn->server, gsup->destination_name,
				 gsup->destination_name_len, msg);
	if (rc) {
		LOGP(DLSMS, LOGL_NOTICE, "Failed to forward '%s' (IMSI-%s)\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi);
		/* osmo_gsup_addr_send() free()d msg */
		return rc;
	}

	return 0;
}

static const struct hlr_euse *find_euse(const struct hlr_subscriber *subscr,
					const char *smsc_addr)
{
	struct hlr_sms_route *rt;
	const char *pattern;

	/* Iterate over all known routes */
	llist_for_each_entry(rt, &g_hlr->sms_routes, list) {
		switch (rt->type) {
		case HLR_SMS_RT_SMSC_ADDR:
			pattern = smsc_addr;
			break;
		case HLR_SMS_RT_SENDER_MSISDN:
			pattern = subscr->msisdn;
			break;
		case HLR_SMS_RT_SENDER_IMSI:
			pattern = subscr->imsi;
			break;
		default:
			/* Shall not happen, make Coverity happy */
			continue;
		}

		if (strcmp(rt->match_pattern, pattern) == 0)
			return rt->euse;
	}

	/* Fall-back to default route if nothing will be found */
	return g_hlr->sms_euse_default;
}

static const struct osmo_gsup_conn *find_conn(struct osmo_gsup_server *srv,
					      const struct hlr_euse *euse)
{
	char euse_addr[128];
	int rc;

	rc = snprintf(euse_addr, sizeof(euse_addr), "EUSE-%s", euse->name);
	return gsup_route_find(srv, (uint8_t *) euse_addr, rc + 1);
}

/* Short Message from MSC/VLR towards SMSC */
int forward_mo_sms(struct osmo_gsup_conn *conn,
		   const struct osmo_gsup_message *gsup,
		   struct msgb *msg)
{
	char smsc_addr[GSM23003_MSISDN_MAX_DIGITS + 1];
	struct osmo_gsup_message rsp_msg;
	struct hlr_subscriber subscr;
	uint8_t ext, ton, npi;
	uint8_t sm_rp_cause;
	int rc;

	rc = db_subscr_get_by_imsi(g_hlr->dbc, gsup->imsi, &subscr);
	if (rc) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' for unknown subscriber IMSI-%s\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		rsp_msg.cause = GMM_CAUSE_IMSI_UNKNOWN;
		goto exit_error;
	}

	/* Make sure SM-RP-DA (SMSC address) is present */
	if (gsup->sm_rp_da == NULL || !gsup->sm_rp_da_len) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' (IMSI-%s) without mandatory SM-RP-DA\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		rsp_msg.cause = GMM_CAUSE_INV_MAND_INFO;
		goto exit_error;
	}

	if (gsup->sm_rp_da_type != OSMO_GSUP_SMS_SM_RP_ODA_SMSC_ADDR) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' (IMSI-%s) with unexpected SM-RP-DA 0x%02x\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi,
		     gsup->sm_rp_da_type);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		rsp_msg.cause = GMM_CAUSE_INV_MAND_INFO;
		goto exit_error;
	}

	/* Parse ToN (Type of Number) / NPI (Numbering Plan Indicator) */
	ext = (gsup->sm_rp_da[0] >> 7) ^ 0x01; /* NOTE: inversed */
	ton = (gsup->sm_rp_da[0] >> 4) & 0x07;
	npi = gsup->sm_rp_da[0] & 0x0f;

	/* We only support International ISDN/telephone format */
	if (ext || ton != 0x01 || npi != 0x01) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' (IMSI-%s) with unsupported SMSC address format: "
					 "ToN=0x%02x, NPI=0x%02x\n, extension=%s\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi,
		     ton, npi, ext ? "yes" : "no");
		gsup_prepare_sm_error(&rsp_msg, gsup);
		rsp_msg.cause = GMM_CAUSE_SEM_INCORR_MSG;
		goto exit_error;
	}

	/* Decode SMSC address from SM-RP-DA */
	rc = osmo_bcd2str(smsc_addr, sizeof(smsc_addr), gsup->sm_rp_da + 1,
			  2, (gsup->sm_rp_da_len - 1) * 2, true);
	if (rc < 0 || rc >= sizeof(smsc_addr)) {
		LOGP(DLSMS, LOGL_NOTICE, "Failed to decode SMSC address from '%s' (IMSI-%s): rc=%d\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi, rc);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		rsp_msg.cause = GMM_CAUSE_SEM_INCORR_MSG;
		goto exit_error;
	}

	/* Attempt to find a EUSE */
	const struct hlr_euse *euse = find_euse(&subscr, smsc_addr);
	if (euse == NULL) {
		LOGP(DLSMS, LOGL_NOTICE, "Failed to find a route for '%s' (IMSI-%s, MR-0x%02x)\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi, *gsup->sm_rp_mr);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		sm_rp_cause = GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;
		rsp_msg.sm_rp_cause = &sm_rp_cause;
		goto exit_error;
	}

	const struct osmo_gsup_conn *euse_conn = find_conn(conn->server, euse);
	if (euse_conn == NULL) {
		LOGP(DLSMS, LOGL_ERROR, "EUSE '%s' is not connected!\n", euse->name);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		sm_rp_cause = GSM411_RP_CAUSE_MO_TEMP_FAIL;
		rsp_msg.sm_rp_cause = &sm_rp_cause;
		goto exit_error;
	}

	LOGP(DLSMS, LOGL_INFO, "Forwarding '%s' (IMSI-%s, MR-0x%02x) to SMSC '%s'\n",
	     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi,
	     *gsup->sm_rp_mr, euse->name);

	/* HACK: make sure source name is present, fill in if needed */
	if (gsup->source_name == NULL || !gsup->source_name_len) {
		/* FIXME: distinguish between MSC/VLR and SGSN */
		msgb_tlv_put(msg, OSMO_GSUP_SOURCE_NAME_IE,
			     strlen(subscr.vlr_number) + 1,
			     (uint8_t *) subscr.vlr_number);
	}

	/* Ensure the buffer has enough headroom to put IPA headers */
	msgb_pull_to_l2(msg);

	/* Finally forward the original message */
	rc = osmo_gsup_conn_send((struct osmo_gsup_conn *) euse_conn, msg);
	if (rc) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to send GSUP message '%s' (rc=%d)\n",
		     osmo_gsup_message_type_name(gsup->message_type), rc);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		sm_rp_cause = GSM411_RP_CAUSE_MO_TEMP_FAIL;
		rsp_msg.sm_rp_cause = &sm_rp_cause;
		msg = NULL; /* free()d by osmo_gsup_conn_send() */
		goto exit_error;
	}

	return 0;

exit_error:
	gsup_conn_enc_send(conn, &rsp_msg);
	if (msg != NULL)
		talloc_free(msg);
	return rc;
}

/* Short Message from SMSC towards MSC/VLR */
int forward_mt_sms(struct osmo_gsup_conn *conn,
		   const struct osmo_gsup_message *gsup,
		   struct msgb *msg)
{
	struct osmo_gsup_message rsp_msg;
	struct hlr_subscriber subscr;
	uint8_t sm_rp_cause;
	int rc;

	rc = db_subscr_get_by_imsi(g_hlr->dbc, gsup->imsi, &subscr);
	if (rc) {
		LOGP(DLSMS, LOGL_NOTICE, "Rx '%s' for unknown subscriber IMSI-%s\n",
		     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		rsp_msg.cause = GMM_CAUSE_IMSI_UNKNOWN;
		goto exit_error;
	}

#if 0
	LOGP(DLSMS, LOGL_INFO, "Forwarding '%s' (IMSI-%s, MR-0x%02x) to MSC/VLR '%s'\n",
	     osmo_gsup_message_type_name(gsup->message_type), gsup->imsi,
	     *gsup->sm_rp_mr, FIXME!);

	/* Finally forward the original message */
	rc = osmo_gsup_conn_send(subscr_conn, msg);
	if (rc) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to send GSUP message '%s' (rc=%d)\n",
		     osmo_gsup_message_type_name(gsup->message_type), rc);
		gsup_prepare_sm_error(&rsp_msg, gsup);
		sm_rp_cause = GSM411_RP_CAUSE_MO_TEMP_FAIL;
		rsp_msg.sm_rp_cause = &sm_rp_cause;
		msg = NULL; /* free()d by osmo_gsup_conn_send() */
		goto exit_error;
	}
#endif

	return 0;

exit_error:
	gsup_conn_enc_send(conn, &rsp_msg);
	if (msg != NULL)
		talloc_free(msg);
	return rc;
}
