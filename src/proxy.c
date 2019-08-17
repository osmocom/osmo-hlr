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

#include <string.h>
#include <talloc.h>
#include <errno.h>
#include <inttypes.h>

#include <osmocom/core/timer.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/gsm48_ie.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/gsupclient/gsup_req.h>

#include <osmocom/hlr/logging.h>
#include <osmocom/hlr/proxy.h>
#include <osmocom/hlr/remote_hlr.h>
#include <osmocom/hlr/gsup_server.h>
#include <osmocom/hlr/gsup_router.h>

#define LOG_PROXY_SUBSCR(proxy_subscr, level, fmt, args...) \
	LOGP(DDGSM, level, "(Proxy IMSI-%s MSISDN-%s HLR-" OSMO_SOCKADDR_STR_FMT ") " fmt, \
	     ((proxy_subscr) && *(proxy_subscr)->imsi)? (proxy_subscr)->imsi : "?", \
	     ((proxy_subscr) && *(proxy_subscr)->msisdn)? (proxy_subscr)->msisdn : "?", \
	     OSMO_SOCKADDR_STR_FMT_ARGS((proxy_subscr)? &(proxy_subscr)->remote_hlr_addr : NULL), \
	     ##args)

#define LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup_msg, level, fmt, args...) \
		     LOG_PROXY_SUBSCR(proxy_subscr, level, "%s: " fmt, \
				      (gsup_msg) ? osmo_gsup_message_type_name((gsup_msg)->message_type) : "NULL", \
				      ##args)

/* The proxy subscriber database.
 * Why have a separate struct to add an llist_head entry?
 * This is to keep the option open to store the proxy data in the database instead, without any visible effect outside
 * of proxy.c. */
struct proxy_subscr_listentry {
	struct llist_head entry;
	timestamp_t last_update;
	struct proxy_subscr data;
};

struct proxy_pending_gsup_req {
	struct llist_head entry;
	struct osmo_gsup_req *req;
	timestamp_t received_at;
};

/* Defer a GSUP message until we know a remote HLR to proxy to.
 * Where to send this GSUP message is indicated by its IMSI: as soon as an MS lookup has yielded the IMSI's home HLR,
 * that's where the message should go. */
static void proxy_deferred_gsup_req_add(struct proxy *proxy, struct osmo_gsup_req *req)
{
	struct proxy_pending_gsup_req *m;

	m = talloc_zero(proxy, struct proxy_pending_gsup_req);
	OSMO_ASSERT(m);
	m->req = req;
	timestamp_update(&m->received_at);
	llist_add_tail(&m->entry, &proxy->pending_gsup_reqs);
}

static void proxy_pending_req_remote_hlr_connect_result(struct osmo_gsup_req *req, struct remote_hlr *remote_hlr)
{
	if (!remote_hlr || !remote_hlr_is_up(remote_hlr)) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_ROAMING_NOTALLOWED, "Proxy: Failed to connect to home HLR");
		return;
	}

	remote_hlr_gsup_forward_to_remote_hlr(remote_hlr, req, NULL);
}

static bool proxy_deferred_gsup_req_waiting(struct proxy *proxy, const char *imsi)
{
	struct proxy_pending_gsup_req *p;
	OSMO_ASSERT(imsi);

	llist_for_each_entry(p, &proxy->pending_gsup_reqs, entry) {
		if (strcmp(p->req->gsup.imsi, imsi))
			continue;
		return true;
	}
	return false;
}

/* Result of looking for remote HLR. If it failed, pass remote_hlr as NULL. On failure, the remote_hlr may be passed
 * NULL. */
static void proxy_deferred_gsup_req_pop(struct proxy *proxy, const char *imsi, struct remote_hlr *remote_hlr)
{
	struct proxy_pending_gsup_req *p, *n;
	OSMO_ASSERT(imsi);

	llist_for_each_entry_safe(p, n, &proxy->pending_gsup_reqs, entry) {
		if (strcmp(p->req->gsup.imsi, imsi))
			continue;

		proxy_pending_req_remote_hlr_connect_result(p->req, remote_hlr);
		p->req = NULL;
		llist_del(&p->entry);
		talloc_free(p);
	}
}

static bool proxy_subscr_matches_imsi(const struct proxy_subscr *proxy_subscr, const char *imsi)
{
	if (!proxy_subscr || !imsi)
		return false;
	return strcmp(proxy_subscr->imsi, imsi) == 0;
}

static bool proxy_subscr_matches_msisdn(const struct proxy_subscr *proxy_subscr, const char *msisdn)
{
	if (!proxy_subscr || !msisdn)
		return false;
	return strcmp(proxy_subscr->msisdn, msisdn) == 0;
}

static struct proxy_subscr_listentry *_proxy_get_by_imsi(struct proxy *proxy, const char *imsi)
{
	struct proxy_subscr_listentry *e;
	if (!proxy)
		return NULL;
	llist_for_each_entry(e, &proxy->subscr_list, entry) {
		if (proxy_subscr_matches_imsi(&e->data, imsi))
			return e;
	}
	return NULL;
}

static struct proxy_subscr_listentry *_proxy_get_by_msisdn(struct proxy *proxy, const char *msisdn)
{
	struct proxy_subscr_listentry *e;
	if (!proxy)
		return NULL;
	llist_for_each_entry(e, &proxy->subscr_list, entry) {
		if (proxy_subscr_matches_msisdn(&e->data, msisdn))
			return e;
	}
	return NULL;
}

int proxy_subscr_get_by_imsi(struct proxy_subscr *dst, struct proxy *proxy, const char *imsi)
{
	struct proxy_subscr_listentry *e = _proxy_get_by_imsi(proxy, imsi);
	if (!e)
		return -ENOENT;
	*dst = e->data;
	return 0;
}

int proxy_subscr_get_by_msisdn(struct proxy_subscr *dst, struct proxy *proxy, const char *msisdn)
{
	struct proxy_subscr_listentry *e = _proxy_get_by_msisdn(proxy, msisdn);
	if (!e)
		return -ENOENT;
	*dst = e->data;
	return 0;
}

int proxy_subscr_create_or_update(struct proxy *proxy, const struct proxy_subscr *proxy_subscr)
{
	struct proxy_subscr_listentry *e = _proxy_get_by_imsi(proxy, proxy_subscr->imsi);
	if (!e) {
		/* Does not exist yet */
		e = talloc_zero(proxy, struct proxy_subscr_listentry);
		llist_add(&e->entry, &proxy->subscr_list);
	}
	e->data = *proxy_subscr;
	timestamp_update(&e->last_update);
	return 0;
}

int _proxy_subscr_del(struct proxy_subscr_listentry *e)
{
	llist_del(&e->entry);
	return 0;
}

int proxy_subscr_del(struct proxy *proxy, const char *imsi)
{
	struct proxy_subscr_listentry *e;
	proxy_deferred_gsup_req_pop(proxy, imsi, NULL);
	e = _proxy_get_by_imsi(proxy, imsi);
	if (!e)
		return -ENOENT;
	return _proxy_subscr_del(e);
}

/* Discard stale proxy entries. */
static void proxy_cleanup(void *proxy_v)
{
	struct proxy *proxy = proxy_v;
	struct proxy_subscr_listentry *e, *n;
	uint32_t age;
	llist_for_each_entry_safe(e, n, &proxy->subscr_list, entry) {
		if (!timestamp_age(&e->last_update, &age))
			LOGP(DDGSM, LOGL_ERROR, "Invalid timestamp, deleting proxy entry\n");
		else if (age <= proxy->fresh_time)
			continue;
		LOG_PROXY_SUBSCR(&e->data, LOGL_INFO, "proxy entry timed out, deleting\n");
		_proxy_subscr_del(e);
	}
	if (proxy->gc_period)
		osmo_timer_schedule(&proxy->gc_timer, proxy->gc_period, 0);
	else
		LOGP(DDGSM, LOGL_NOTICE, "Proxy cleanup is switched off (gc_period == 0)\n");
}

void proxy_set_gc_period(struct proxy *proxy, uint32_t gc_period)
{
	proxy->gc_period = gc_period;
	proxy_cleanup(proxy);
}

void proxy_init(struct osmo_gsup_server *gsup_server_to_vlr)
{
	OSMO_ASSERT(!gsup_server_to_vlr->proxy);
	struct proxy *proxy = talloc_zero(gsup_server_to_vlr, struct proxy);
	*proxy = (struct proxy){
		.gsup_server_to_vlr = gsup_server_to_vlr,
		.fresh_time = 60*60,
		.gc_period = 60,
	};
	INIT_LLIST_HEAD(&proxy->subscr_list);
	INIT_LLIST_HEAD(&proxy->pending_gsup_reqs);

	osmo_timer_setup(&proxy->gc_timer, proxy_cleanup, proxy);
	/* Invoke to trigger the first timer schedule */
	proxy_set_gc_period(proxy, proxy->gc_period);
	gsup_server_to_vlr->proxy = proxy;
}

void proxy_del(struct proxy *proxy)
{
	osmo_timer_del(&proxy->gc_timer);
	talloc_free(proxy);
}

/* All GSUP messages sent to the remote HLR pass through this function, to modify the subscriber state or disallow
 * sending the message. Return 0 to allow sending the message. */
static int proxy_acknowledge_gsup_to_remote_hlr(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
						const struct osmo_gsup_req *req)
{
	struct proxy_subscr proxy_subscr_new = *proxy_subscr;
	bool ps;
	bool cs;
	int rc;

	if (req->source_name.type != OSMO_GSUP_PEER_ID_IPA_NAME) {
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, &req->gsup, LOGL_ERROR,
				     "Unsupported GSUP peer id type: %s\n",
				     osmo_gsup_peer_id_type_name(req->source_name.type));
		return -ENOTSUP;
	}

	switch (req->gsup.message_type) {

	case OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		/* Store the CS and PS VLR name in vlr_name_preliminary to later update the right {cs,ps} LU timestamp
		 * when receiving an OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT. Store in vlr_name_preliminary so that in
		 * case the LU fails, we keep the vlr_name intact. */
		switch (req->gsup.cn_domain) {
		case OSMO_GSUP_CN_DOMAIN_CS:
			proxy_subscr_new.cs.vlr_name_preliminary = req->source_name.ipa_name;
			break;
		case OSMO_GSUP_CN_DOMAIN_PS:
			proxy_subscr_new.ps.vlr_name_preliminary = req->source_name.ipa_name;
			break;
		default:
			break;
		}

		ps = cs = false;
		if (osmo_ipa_name_cmp(&proxy_subscr_new.cs.vlr_name_preliminary, &proxy_subscr->cs.vlr_name_preliminary))
			cs = true;
		if (osmo_ipa_name_cmp(&proxy_subscr_new.ps.vlr_name_preliminary, &proxy_subscr->ps.vlr_name_preliminary))
			ps = true;

		if (!(cs || ps)) {
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, &req->gsup, LOGL_DEBUG, "VLR names remain unchanged\n");
			break;
		}

		rc = proxy_subscr_create_or_update(proxy, &proxy_subscr_new);
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, &req->gsup, rc ? LOGL_ERROR : LOGL_INFO,
				     "%s: preliminary VLR name for%s%s to %s\n",
				     rc ? "failed to update" : "updated",
				     cs ? " CS" : "", ps ? " PS" : "",
				     osmo_gsup_peer_id_to_str(&req->source_name));
		break;
	/* TODO: delete proxy entry in case of a Purge Request? */
	default:
		break;
	}
	return 0;
}

/* All GSUP messages received from the remote HLR to be sent to a local MSC pass through this function, to modify the
 * subscriber state or disallow sending the message. Return 0 to allow sending the message.
 * The local MSC shall be indicated by gsup.destination_name. */
static int proxy_acknowledge_gsup_from_remote_hlr(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
						  const struct osmo_gsup_message *gsup,
						  struct remote_hlr *from_remote_hlr,
						  const struct osmo_ipa_name *destination,
						  const struct osmo_ipa_name *via_peer)
{
	struct proxy_subscr proxy_subscr_new = *proxy_subscr;
	bool ps;
	bool cs;
	bool vlr_name_changed_cs = false;
	bool vlr_name_changed_ps = false;
	int rc;
	struct osmo_ipa_name via_proxy = {};
	if (osmo_ipa_name_cmp(via_peer, destination))
		via_proxy = *via_peer;

	switch (gsup->message_type) {
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		/* Remember the MSISDN of the subscriber. This does not need to be a preliminary record, because when
		 * the HLR tells us about subscriber data, it is definitive info and there is no ambiguity (like there
		 * would be with failed LU attempts from various sources). */
		if (!gsup->msisdn_enc_len)
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_DEBUG, "No MSISDN in this Insert Data Request\n");
		else if (gsm48_decode_bcd_number2(proxy_subscr_new.msisdn, sizeof(proxy_subscr_new.msisdn),
						  gsup->msisdn_enc, gsup->msisdn_enc_len, 0))
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR, "Failed to decode MSISDN\n");
		else if (!osmo_msisdn_str_valid(proxy_subscr_new.msisdn))
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR, "invalid MSISDN: %s\n",
					     osmo_quote_str_c(OTC_SELECT, proxy_subscr_new.msisdn, -1));
		else if (!strcmp(proxy_subscr->msisdn, proxy_subscr_new.msisdn))
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_DEBUG, "already have MSISDN = %s\n",
					     proxy_subscr_new.msisdn);
		else if (proxy_subscr_create_or_update(proxy, &proxy_subscr_new))
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR, "failed to update MSISDN to %s\n",
					     proxy_subscr_new.msisdn);
		else
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_INFO, "stored MSISDN=%s\n",
					     proxy_subscr_new.msisdn);
		break;

	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		/* Update the Location Updating timestamp */
		cs = ps = false;
		if (!osmo_ipa_name_cmp(destination, &proxy_subscr->cs.vlr_name_preliminary)) {
			timestamp_update(&proxy_subscr_new.cs.last_lu);
			proxy_subscr_new.cs.vlr_name_preliminary = (struct osmo_ipa_name){};
			vlr_name_changed_cs =
				osmo_ipa_name_cmp(&proxy_subscr->cs.vlr_name, destination)
				|| osmo_ipa_name_cmp(&proxy_subscr->cs.vlr_via_proxy, &via_proxy);
			proxy_subscr_new.cs.vlr_name = *destination;
			proxy_subscr_new.cs.vlr_via_proxy = via_proxy;
			cs = true;
		}
		if (!osmo_ipa_name_cmp(destination, &proxy_subscr->ps.vlr_name_preliminary)) {
			timestamp_update(&proxy_subscr_new.ps.last_lu);
			proxy_subscr_new.ps.vlr_name_preliminary = (struct osmo_ipa_name){};
			proxy_subscr_new.ps.vlr_name = *destination;
			vlr_name_changed_ps =
				osmo_ipa_name_cmp(&proxy_subscr->ps.vlr_name, destination)
				|| osmo_ipa_name_cmp(&proxy_subscr->ps.vlr_via_proxy, &via_proxy);
			proxy_subscr_new.ps.vlr_via_proxy = via_proxy;
			ps = true;
		}
		if (!(cs || ps)) {
			LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR,
					     "destination is neither CS nor PS VLR: %s\n",
					     osmo_ipa_name_to_str(destination));
			return GMM_CAUSE_PROTO_ERR_UNSPEC;
		}
		rc = proxy_subscr_create_or_update(proxy, &proxy_subscr_new);

		LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, rc ? LOGL_ERROR : LOGL_INFO,
				     "%s LU: timestamp for%s%s%s%s%s%s%s%s%s%s\n",
				     rc ? "failed to update" : "updated",
				     cs ? " CS" : "", ps ? " PS" : "",
				     vlr_name_changed_cs? ", CS VLR=" : "",
				     vlr_name_changed_cs? osmo_ipa_name_to_str(&proxy_subscr_new.cs.vlr_name) : "",
				     proxy_subscr_new.cs.vlr_via_proxy.len ? " via proxy " : "",
				     proxy_subscr_new.cs.vlr_via_proxy.len ?
					     osmo_ipa_name_to_str(&proxy_subscr_new.cs.vlr_via_proxy) : "",
				     vlr_name_changed_ps? ", PS VLR=" : "",
				     vlr_name_changed_ps? osmo_ipa_name_to_str(&proxy_subscr_new.ps.vlr_name) : "",
				     proxy_subscr_new.ps.vlr_via_proxy.len ? " via proxy " : "",
				     proxy_subscr_new.ps.vlr_via_proxy.len ?
					     osmo_ipa_name_to_str(&proxy_subscr_new.ps.vlr_via_proxy) : ""
				    );
		break;

	default:
		break;
	}

	return 0;
}

static void proxy_remote_hlr_connect_result_cb(const struct osmo_sockaddr_str *addr, struct remote_hlr *remote_hlr,
					       void *data)
{
	struct proxy *proxy = data;
	struct proxy_subscr_listentry *e;
	if (!proxy)
		return;
	llist_for_each_entry(e, &proxy->subscr_list, entry) {
		if (!osmo_sockaddr_str_cmp(addr, &e->data.remote_hlr_addr)) {
			proxy_deferred_gsup_req_pop(proxy, e->data.imsi, remote_hlr);
		}
	}
}

/* Store the remote HLR's GSUP address for this proxy subscriber.
 * This can be set before the remote_hlr is connected, or after.
 * And, this can be set before the gsup_req has been queued for this HLR, or after.
 */
void proxy_subscr_remote_hlr_resolved(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
				      const struct osmo_sockaddr_str *remote_hlr_addr)
{
	struct proxy_subscr proxy_subscr_new;

	if (osmo_sockaddr_str_is_nonzero(&proxy_subscr->remote_hlr_addr)) {
		if (!osmo_sockaddr_str_cmp(remote_hlr_addr, &proxy_subscr->remote_hlr_addr)) {
			/* Already have this remote address */
			return;
		} else {
			LOG_PROXY_SUBSCR(proxy_subscr, LOGL_NOTICE,
					 "Remote HLR address changes to " OSMO_SOCKADDR_STR_FMT "\n",
					 OSMO_SOCKADDR_STR_FMT_ARGS(remote_hlr_addr));
		}
	}

	/* Store the address. Make a copy to modify. */
	proxy_subscr_new = *proxy_subscr;
	proxy_subscr = &proxy_subscr_new;
	proxy_subscr_new.remote_hlr_addr = *remote_hlr_addr;

	if (proxy_subscr_create_or_update(proxy, proxy_subscr)) {
		LOG_PROXY_SUBSCR(proxy_subscr, LOGL_ERROR, "Failed to store proxy entry for remote HLR\n");
		/* If no remote HLR is known for the IMSI, the proxy entry is pointless. */
		proxy_subscr_del(proxy, proxy_subscr->imsi);
		return;
	}
	LOG_PROXY_SUBSCR(proxy_subscr, LOGL_DEBUG, "Remote HLR resolved, stored address\n");

	/* If any messages for this HLR are already spooled, connect now. Otherwise wait for
	 * proxy_subscr_forward_to_remote_hlr() to connect then. */
	if (proxy_deferred_gsup_req_waiting(proxy, proxy_subscr->imsi))
		remote_hlr_get_or_connect(&proxy_subscr->remote_hlr_addr, true,
					  proxy_remote_hlr_connect_result_cb, proxy);
}

int proxy_subscr_forward_to_remote_hlr(struct proxy *proxy, const struct proxy_subscr *proxy_subscr, struct osmo_gsup_req *req)
{
	struct remote_hlr *remote_hlr;
	int rc;

	rc = proxy_acknowledge_gsup_to_remote_hlr(proxy, proxy_subscr, req);
	if (rc) {
		osmo_gsup_req_respond_err(req, GMM_CAUSE_PROTO_ERR_UNSPEC, "Proxy does not allow this message");
		return rc;
	}

	if (!osmo_sockaddr_str_is_nonzero(&proxy_subscr->remote_hlr_addr)) {
		/* We don't know the remote target yet. Still waiting for an MS lookup response, which will end up
		 * calling proxy_subscr_remote_hlr_resolved(). See dgsm.c. */
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, &req->gsup, LOGL_DEBUG, "deferring until remote HLR is known\n");
		proxy_deferred_gsup_req_add(proxy, req);
		return 0;
	}

	if (!osmo_gsup_peer_id_is_empty(&req->via_proxy)) {
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, &req->gsup, LOGL_INFO, "VLR->HLR: forwarding from %s via proxy %s\n",
				     osmo_gsup_peer_id_to_str(&req->source_name),
				     osmo_gsup_peer_id_to_str(&req->via_proxy));
	} else {
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, &req->gsup, LOGL_INFO, "VLR->HLR: forwarding from %s\n",
				     osmo_gsup_peer_id_to_str(&req->source_name));
	}

	/* We could always store in the defer queue and empty the queue if the connection is already up.
	 * Slight optimisation: if the remote_hlr is already up and running, skip the defer queue.
	 * First ask for an existing remote_hlr. */
	remote_hlr = remote_hlr_get_or_connect(&proxy_subscr->remote_hlr_addr, false, NULL, NULL);
	if (remote_hlr && remote_hlr_is_up(remote_hlr)) {
		proxy_pending_req_remote_hlr_connect_result(req, remote_hlr);
		return 0;
	}

	/* Not existing or not up. Defer req and ask to be notified when it is up.
	 * If the remote_hlr exists but is not connected yet, there should actually already be a pending
	 * proxy_remote_hlr_connect_result_cb queued, but it doesn't hurt to do that more often. */
	proxy_deferred_gsup_req_add(proxy, req);
	remote_hlr_get_or_connect(&proxy_subscr->remote_hlr_addr, true,
				  proxy_remote_hlr_connect_result_cb, proxy);
	return 0;
}

int proxy_subscr_forward_to_vlr(struct proxy *proxy, const struct proxy_subscr *proxy_subscr,
				const struct osmo_gsup_message *gsup, struct remote_hlr *from_remote_hlr)
{
	struct osmo_ipa_name destination;
	struct osmo_gsup_conn *vlr_conn;
	struct msgb *msg;

	if (osmo_ipa_name_set(&destination, gsup->destination_name, gsup->destination_name_len)) {
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR,
				     "no valid Destination Name IE, cannot route to VLR.\n");
		return GMM_CAUSE_INV_MAND_INFO;
	}

	/* Route to MSC/SGSN that we're proxying for */
	vlr_conn = gsup_route_find_by_ipa_name(proxy->gsup_server_to_vlr, &destination);
	if (!vlr_conn) {
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR,
				     "Destination VLR unreachable: %s\n", osmo_ipa_name_to_str(&destination));
		return GMM_CAUSE_MSC_TEMP_NOTREACH;
	}

	if (proxy_acknowledge_gsup_from_remote_hlr(proxy, proxy_subscr, gsup, from_remote_hlr, &destination,
						   &vlr_conn->peer_name)) {
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR,
				     "Proxy does not allow forwarding this message\n");
		return GMM_CAUSE_PROTO_ERR_UNSPEC;
	}

	msg = osmo_gsup_msgb_alloc("GSUP proxy to VLR");
	if (osmo_gsup_encode(msg, gsup)) {
		LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_ERROR,
				     "Failed to re-encode GSUP message, cannot forward\n");
		return GMM_CAUSE_INV_MAND_INFO;
	}

	LOG_PROXY_SUBSCR_MSG(proxy_subscr, gsup, LOGL_INFO, "VLR<-HLR: forwarding to %s%s%s\n",
			     osmo_ipa_name_to_str(&destination),
			     osmo_ipa_name_cmp(&destination, &vlr_conn->peer_name) ? " via " : "",
			     osmo_ipa_name_cmp(&destination, &vlr_conn->peer_name) ?
						       osmo_ipa_name_to_str(&vlr_conn->peer_name) : "");
	return osmo_gsup_conn_send(vlr_conn, msg);
}
