#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/gsm/gsm0411_utils.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#include <osmocom/mslookup/mslookup_client.h>

#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/remote_hlr.h>
#include <osmocom/hlr/mslookup_server.h>
#include <osmocom/hlr/db.h>
#include <osmocom/hlr/sms_over_gsup.h>

static int sms_extract_destination_msisdn(char *msisdn, size_t msisdn_size, struct osmo_gsup_req *req)
{
	int rc;
	if (req->gsup.sm_rp_da_type == OSMO_GSUP_SMS_SM_RP_ODA_MSISDN
	    && req->gsup.sm_rp_da_len > 0) {
		LOG_GSUP_REQ(req, LOGL_INFO, "Extracting destination MSISDN from GSUP SM_RP_DA IE: %s\n",
			     osmo_hexdump(req->gsup.sm_rp_da, req->gsup.sm_rp_da_len));
		rc = gsm48_decode_bcd_number2(msisdn, msisdn_size, req->gsup.sm_rp_da, req->gsup.sm_rp_da_len, 0);
		if (!rc)
			LOG_GSUP_REQ(req, LOGL_INFO, "success -> %s\n", msisdn);
		else
			LOG_GSUP_REQ(req, LOGL_ERROR, "fail %d\n", rc);
		return rc;
	}

	/* The DA was not an MSISDN -- get from inside the SMS PDU */
	if (req->gsup.sm_rp_ui_len > 3) {
		const uint8_t *da = req->gsup.sm_rp_ui + 2;
		uint8_t da_len = *da;
		uint8_t da_len_bytes;
		uint8_t address_lv[12] = {};

		da_len_bytes = 2 + da_len/2 + da_len%2;

		if (da_len_bytes < 4 || da_len_bytes > 12
		    || da_len_bytes > req->gsup.sm_rp_ui_len - 2) {
			LOG_GSUP_REQ(req, LOGL_ERROR, "Invalid da_len_bytes %u\n", da_len_bytes);
			return -EINVAL;
		}

		memcpy(address_lv, da, da_len_bytes);
		address_lv[0] = da_len_bytes - 1;

		LOG_GSUP_REQ(req, LOGL_INFO, "Extracting destination MSISDN from SMS PDU DA: %s\n",
			     osmo_hexdump(address_lv, da_len_bytes));
		rc = gsm48_decode_bcd_number2(msisdn, msisdn_size, address_lv, da_len_bytes, 1);
		if (!rc)
			LOG_GSUP_REQ(req, LOGL_INFO, "success -> %s\n", msisdn);
		else
			LOG_GSUP_REQ(req, LOGL_ERROR, "fail %d\n", rc);
		return rc;
	}

	LOG_GSUP_REQ(req, LOGL_ERROR, "fail: no SM_RP_DA nor SMS PDU (sm_rp_ui_len > 3)\n");
	return -ENOTSUP;
}

static int sms_extract_sender_msisdn(char *msisdn, size_t msisdn_size, struct osmo_gsup_req *req)
{
	int rc;
	if (req->gsup.sm_rp_oa_type == OSMO_GSUP_SMS_SM_RP_ODA_MSISDN
	    && req->gsup.sm_rp_oa_len > 0) {
		LOG_GSUP_REQ(req, LOGL_INFO, "Extracting sender MSISDN from GSUP SM_RP_OA IE: %s\n",
			     osmo_hexdump(req->gsup.sm_rp_oa, req->gsup.sm_rp_oa_len));
		rc = gsm48_decode_bcd_number2(msisdn, msisdn_size, req->gsup.sm_rp_oa, req->gsup.sm_rp_oa_len, 0);
		if (!rc)
			LOG_GSUP_REQ(req, LOGL_INFO, "success -> %s\n", msisdn);
		else
			LOG_GSUP_REQ(req, LOGL_ERROR, "fail %d\n", rc);
		return rc;
	}

	LOG_GSUP_REQ(req, LOGL_ERROR, "fail: no MSISDN obtained from SM_RP_OA\n");
	return -ENOTSUP;
}

static struct msgb *sms_mo_pdu_to_mt_pdu(const uint8_t *mo_pdu, size_t mo_pdu_len, const char *sender_msisdn)
{
	/* Hacky shortened copy-paste of osmo-msc's gsm340_rx_tpdu() */

	uint8_t protocol_id;
	uint8_t data_coding_scheme;
	uint8_t user_data_len;
	uint8_t user_data_octet_len;
	const uint8_t *user_data;
	uint8_t status_rep_req;
	uint8_t ud_hdr_ind;

	{
		const uint8_t *smsp = mo_pdu;
		enum sms_alphabet sms_alphabet;
		uint8_t sms_vpf;
		uint8_t da_len_bytes;

		sms_vpf = (*smsp & 0x18) >> 3;
		status_rep_req = (*smsp & 0x20) >> 5;
		ud_hdr_ind = (*smsp & 0x40);

		smsp += 2;

		/* length in bytes of the destination address */
		da_len_bytes = 2 + *smsp/2 + *smsp%2;
		if (da_len_bytes < 4 || da_len_bytes > 12)
			return NULL;
		smsp += da_len_bytes;

		protocol_id = *smsp++;
		data_coding_scheme = *smsp++;

		sms_alphabet = gsm338_get_sms_alphabet(data_coding_scheme);
		if (sms_alphabet == 0xffffffff)
			return NULL;

		switch (sms_vpf) {
		case GSM340_TP_VPF_RELATIVE:
			smsp++;
			break;
		case GSM340_TP_VPF_ABSOLUTE:
		case GSM340_TP_VPF_ENHANCED:
			/* the additional functionality indicator... */
			if (sms_vpf == GSM340_TP_VPF_ENHANCED && *smsp & (1<<7))
				smsp++;
			smsp += 7;
			break;
		case GSM340_TP_VPF_NONE:
			break;
		default:
			return NULL;
		}

		/* As per 3GPP TS 03.40, section 9.2.3.16, TP-User-Data-Length (TP-UDL)
		 * may indicate either the number of septets, or the number of octets,
		 * depending on Data Coding Scheme. We store TP-UDL value as-is,
		 * so this should be kept in mind to avoid buffer overruns. */
		user_data_len = *smsp++;
		user_data = smsp;
		if (user_data_len > 0) {
			if (sms_alphabet == DCS_7BIT_DEFAULT) {
				/* TP-UDL is indicated in septets (up to 160) */
				if (user_data_len > GSM340_UDL_SPT_MAX) {
					user_data_len = GSM340_UDL_SPT_MAX;
				}
				user_data_octet_len = gsm_get_octet_len(user_data_len);
			} else {
				/* TP-UDL is indicated in octets (up to 140) */
				if (user_data_len > GSM340_UDL_OCT_MAX) {
					user_data_len = GSM340_UDL_OCT_MAX;
				}
				user_data_octet_len = user_data_len;
			}
		}
	}

	{

		/* The following is a hacky copy pasted and shortened version of osmo-msc's gsm340_gen_sms_deliver_tpdu() */
		struct msgb *msg = gsm411_msgb_alloc();
		uint8_t *smsp;
		uint8_t oa[12];	/* max len per 03.40 */
		int oa_len;

		if (!msg)
			return NULL;

		/* generate first octet with masked bits */
		smsp = msgb_put(msg, 1);
		/* TP-MTI (message type indicator) */
		*smsp = GSM340_SMS_DELIVER_SC2MS;
		/* TP-MMS (more messages to send) */
		if (0 /* FIXME */)
			*smsp |= 0x04;
		/* TP-SRI(deliver)/SRR(submit) */
		if (status_rep_req)
			*smsp |= 0x20;
		/* TP-UDHI (indicating TP-UD contains a header) */
		if (ud_hdr_ind)
			*smsp |= 0x40;

		/* generate originator address */
		oa_len = gsm340_gen_oa(oa, sizeof(oa), 0, 0, sender_msisdn);
		if (oa_len < 0) {
			msgb_free(msg);
			return NULL;
		}

		smsp = msgb_put(msg, oa_len);
		memcpy(smsp, oa, oa_len);

		/* generate TP-PID */
		smsp = msgb_put(msg, 1);
		*smsp = protocol_id;

		/* generate TP-DCS */
		smsp = msgb_put(msg, 1);
		*smsp = data_coding_scheme;

		/* generate TP-SCTS */
		smsp = msgb_put(msg, 7);
		gsm340_gen_scts(smsp, time(NULL));

		/* generate TP-UDL */
		smsp = msgb_put(msg, 1);
		*smsp = user_data_len;
		smsp = msgb_put(msg, user_data_octet_len);
		memcpy(smsp, user_data, user_data_octet_len);

		return msg;
	}
}


static void sms_recipient_up_cb(const struct osmo_sockaddr_str *addr, struct remote_hlr *remote_hlr, void *data)
{
	struct osmo_gsup_req *req = data;
	struct osmo_gsup_message modified_gsup = req->gsup;
//	struct msgb *mt_pdu = NULL;
	if (!remote_hlr) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_MSC_TEMP_NOTREACH,
					  "Failed to connect to SMS recipient: " OSMO_SOCKADDR_STR_FMT,
					  OSMO_SOCKADDR_STR_FMT_ARGS(addr));
		return;
	}
	/* We must not send out another MO request, to make sure we don't send the request in an infinite loop. */
#if 0
	if (req->gsup.message_type == OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST) {
		char sender_msisdn[GSM23003_MSISDN_MAX_DIGITS+1];
		if (sms_extract_sender_msisdn(sender_msisdn, sizeof(sender_msisdn), req)) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "Cannot find sender MSISDN");
			return;
		}
		mt_pdu = sms_mo_pdu_to_mt_pdu(req->gsup.sm_rp_ui, req->gsup.sm_rp_ui_len, sender_msisdn);
		if (!mt_pdu) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO,
						  "Cannot translate PDU to a DELIVER PDU");
			return;
		}
		modified_gsup.message_type = OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST;
		modified_gsup.sm_rp_ui = mt_pdu->data;
		modified_gsup.sm_rp_ui_len = mt_pdu->len;
	}
#endif
	LOG_GSUP_REQ(req, LOGL_INFO, "Forwarding to remote HLR " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&remote_hlr->addr));
	remote_hlr_gsup_forward_to_remote_hlr(remote_hlr, req, &modified_gsup);
}

static void sms_over_gsup_mt(struct osmo_gsup_req *req)
{
	/* Find a locally connected MSC that knows this MSISDN. */
	uint32_t lu_age;
	struct osmo_gsup_peer_id local_msc_id;
	struct osmo_mslookup_query query = {
		.service = OSMO_MSLOOKUP_SERVICE_SMS_GSUP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
		},
	};
	struct osmo_gsup_message modified_gsup = req->gsup;
	struct msgb *mt_pdu = NULL;

	if (sms_extract_destination_msisdn(query.id.msisdn, sizeof(query.id.msisdn), req)) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "invalid MSISDN");
		return;
	}

	LOG_GSUP_REQ(req, LOGL_NOTICE, "SMS to MSISDN: %s\n", query.id.msisdn);

	/* If a local attach is found, write the subscriber's IMSI to the modified_gsup buffer */
	if (!subscriber_has_done_lu_here(&query, &lu_age, &local_msc_id.ipa_name,
					 modified_gsup.imsi, sizeof(modified_gsup.imsi))) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_MSC_TEMP_NOTREACH,
					  "SMS recipient not reachable: %s\n",
					  osmo_mslookup_result_name_c(OTC_SELECT, &query, NULL));
		return;
	}
	local_msc_id.type = OSMO_GSUP_PEER_ID_IPA_NAME;
	/* A local MSC indeed has an active subscription for the recipient. Deliver there. */

	if (modified_gsup.message_type == OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST) {
		/* This is a direct local delivery, and sms_over_gsup_mo_directly_to_mt() just passed the MO request
		 * altough here we are on the MT side. We must not send out another MO request, to make sure we don't
		 * send the request in an infinite loop.
		 * Also patch in the recipient's IMSI.
		 */
		char sender_msisdn[GSM23003_MSISDN_MAX_DIGITS+1];
		if (sms_extract_sender_msisdn(sender_msisdn, sizeof(sender_msisdn), req)) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "Cannot find sender MSISDN");
			return;
		}
		mt_pdu = sms_mo_pdu_to_mt_pdu(req->gsup.sm_rp_ui, req->gsup.sm_rp_ui_len, sender_msisdn);
		if (!mt_pdu) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO,
						  "Cannot translate PDU to a DELIVER PDU");
			return;
		}
		modified_gsup.message_type = OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST;
		modified_gsup.sm_rp_ui = mt_pdu->data;
		modified_gsup.sm_rp_ui_len = mt_pdu->len;
	}

	osmo_gsup_forward_to_local_peer(g_hlr->gs, &local_msc_id, req, &modified_gsup);

	if (mt_pdu)
		msgb_free(mt_pdu);
}

static void resolve_sms_recipient_cb(struct osmo_mslookup_client *client,
				     uint32_t request_handle,
				     const struct osmo_mslookup_query *query,
				     const struct osmo_mslookup_result *result)
{
	struct osmo_gsup_req *req = query->priv;
	const struct osmo_sockaddr_str *remote_hlr_addr = NULL;
	const struct mslookup_service_host *local_gsup;

	if (result->rc == OSMO_MSLOOKUP_RC_RESULT) {
		if (osmo_sockaddr_str_is_nonzero(&result->host_v4))
			remote_hlr_addr = &result->host_v4;
		else if (osmo_sockaddr_str_is_nonzero(&result->host_v6))
			remote_hlr_addr = &result->host_v6;
	}

	if (!remote_hlr_addr) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_MSC_TEMP_NOTREACH,
					  "Failed to resolve SMS recipient: %s\n",
					  osmo_mslookup_result_name_c(OTC_SELECT, query, result));
		return;
	}

	/* Possibly, this HLR here has responded to itself via mslookup. Don't make a GSUP connection to ourselves,
	 * instead go directly to the MT path. */
	local_gsup = mslookup_server_get_local_gsup_addr();
	LOG_GSUP_REQ(req, LOGL_NOTICE, "local_gsup " OSMO_SOCKADDR_STR_FMT " " OSMO_SOCKADDR_STR_FMT
		     "  remote_hlr_addr " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(&local_gsup->host_v4),
		     OSMO_SOCKADDR_STR_FMT_ARGS(&local_gsup->host_v6),
		     OSMO_SOCKADDR_STR_FMT_ARGS(remote_hlr_addr));
	if (local_gsup
	    && (!osmo_sockaddr_str_cmp(&local_gsup->host_v4, remote_hlr_addr)
		|| !osmo_sockaddr_str_cmp(&local_gsup->host_v6, remote_hlr_addr))) {
		sms_over_gsup_mt(req);
		return;
	}

	remote_hlr_get_or_connect(remote_hlr_addr, true, sms_recipient_up_cb, req);
}

static void sms_over_gsup_mo_directly_to_mt(struct osmo_gsup_req *req)
{
	/* Figure out the location of the SMS recipient by mslookup */
	if (osmo_mslookup_client_active(g_hlr->mslookup.client.client)) {
		/* D-GSM is active. Kick off an mslookup for the current location of the MSISDN. */
		uint32_t request_handle;
		struct osmo_mslookup_query_handling handling = {
			.min_wait_milliseconds = g_hlr->mslookup.client.result_timeout_milliseconds,
			.result_cb = resolve_sms_recipient_cb,
		};
		struct osmo_mslookup_query query = {
			.id = {
				.type = OSMO_MSLOOKUP_ID_MSISDN,
			},
			.priv = req,
		};
		if (sms_extract_destination_msisdn(query.id.msisdn, sizeof(query.id.msisdn), req)
		    || !osmo_msisdn_str_valid(query.id.msisdn)) {
			osmo_gsup_req_respond_err(req, GMM_CAUSE_INV_MAND_INFO, "invalid MSISDN");
			return;
		}
		OSMO_STRLCPY_ARRAY(query.service, OSMO_MSLOOKUP_SERVICE_SMS_GSUP);

		request_handle = osmo_mslookup_client_request(g_hlr->mslookup.client.client, &query, &handling);
		if (request_handle) {
			/* Querying succeeded. Wait for resolve_sms_recipient_cb() to be called. */
			return;
		}
		/* Querying failed. Try whether delivering to a locally connected MSC works out. */
		LOG_DGSM(req->gsup.imsi, LOGL_ERROR,
			 "Error dispatching mslookup query for SMS: %s -- trying local delivery\n",
			 osmo_mslookup_result_name_c(OTC_SELECT, &query, NULL));
	}

	/* Attempt direct delivery */
	sms_over_gsup_mt(req);
}

static void sms_over_gsup_mo(struct osmo_gsup_req *req)
{
	if (!osmo_gsup_peer_id_is_empty(&g_hlr->sms_over_gsup.smsc)) {
		/* Forward to SMSC */
		/* FIXME actually use branch fixeria/sms for this */
		osmo_gsup_forward_to_local_peer(g_hlr->gs, &g_hlr->sms_over_gsup.smsc, req, NULL);
		return;
	}

	if (!g_hlr->sms_over_gsup.try_direct_delivery) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_PROTO_ERR_UNSPEC,
					  "cannot deliver SMS over GSUP: No SMSC (and direct delivery disabled)");
		return;
	}

	sms_over_gsup_mo_directly_to_mt(req);
}

bool sms_over_gsup_check_handle_msg(struct osmo_gsup_req *req)
{
	switch (req->gsup.message_type) {
	case OSMO_GSUP_MSGT_MO_FORWARD_SM_REQUEST:
		sms_over_gsup_mo(req);
		return true;

	case OSMO_GSUP_MSGT_MT_FORWARD_SM_REQUEST:
		sms_over_gsup_mt(req);
		return true;

	default:
		return false;
	}
}
