#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/hlr/hlr.h>
#include <osmocom/hlr/proxy_mm.h>
#include <osmocom/hlr/proxy_db.h>

enum proxy_mm_fsm_state {
	PROXY_MM_ST_READY,
	PROXY_MM_ST_WAIT_SUBSCR_DATA,
	PROXY_MM_ST_WAIT_GSUP_ISD_RESULT,
	PROXY_MM_ST_WAIT_AUTH_TUPLES,
};

static const struct value_string proxy_mm_fsm_event_names[] = {
	OSMO_VALUE_STRING(PROXY_MM_EV_SUBSCR_INVALID),
	OSMO_VALUE_STRING(PROXY_MM_EV_RX_GSUP_LU),
	OSMO_VALUE_STRING(PROXY_MM_EV_RX_GSUP_SAI),
	OSMO_VALUE_STRING(PROXY_MM_EV_RX_SUBSCR_DATA),
	OSMO_VALUE_STRING(PROXY_MM_EV_RX_GSUP_ISD_RESULT),
	OSMO_VALUE_STRING(PROXY_MM_EV_RX_AUTH_TUPLES),
	{}
};

static struct osmo_fsm proxy_mm_fsm;
static struct osmo_fsm proxy_to_home_fsm;

struct osmo_tdef proxy_mm_tdefs[] = {
// FIXME
	{ .T=-1, .default_val=5, .desc="proxy_mm ready timeout" },
	{ .T=-2, .default_val=5, .desc="proxy_mm wait_subscr_data timeout" },
	{ .T=-3, .default_val=5, .desc="proxy_mm wait_gsup_isd_result timeout" },
	{ .T=-4, .default_val=5, .desc="proxy_mm wait_auth_tuples timeout" },
	{}
};

static const struct osmo_tdef_state_timeout proxy_mm_fsm_timeouts[32] = {
// FIXME
	[PROXY_MM_ST_READY] = { .T=-1 },
	[PROXY_MM_ST_WAIT_SUBSCR_DATA] = { .T=-2 },
	[PROXY_MM_ST_WAIT_GSUP_ISD_RESULT] = { .T=-3 },
	[PROXY_MM_ST_WAIT_AUTH_TUPLES] = { .T=-4 },
};

#define proxy_mm_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(mm_fi, state, \
				     proxy_mm_fsm_timeouts, \
				     proxy_mm_tdefs, \
				     5)

LLIST_HEAD(proxy_mm_list);

struct proxy_mm *proxy_mm_alloc(const struct osmo_gsup_peer_id *vlr_name,
				bool is_ps,
				const char *imsi)
{
	struct proxy_mm *proxy_mm;

	struct osmo_fsm_inst *mm_fi = osmo_fsm_inst_alloc(&proxy_mm_fsm, g_hlr, NULL, LOGL_DEBUG, imsi);
	OSMO_ASSERT(mm_fi);

	proxy_mm = talloc(mm_fi, struct proxy_mm);
	OSMO_ASSERT(proxy_mm);
	mm_fi->priv = proxy_mm;
	*proxy_mm = (struct proxy_mm){
		.mm_fi = mm_fi,
		.is_ps = is_ps,
	};
	OSMO_STRLCPY_ARRAY(proxy_mm->imsi, imsi);
	INIT_LLIST_HEAD(&proxy_mm->auth_cache);

	llist_add(&proxy_mm->entry, &proxy_mm_list);

	proxy_mm->to_home_fi = osmo_fsm_inst_alloc_child(&proxy_to_home_fsm, mm_fi, PROXY_MM_EV_SUBSCR_INVALID);
	proxy_mm->to_home_fi->priv = proxy_mm;

	/* Do a state change to activate timeout */
	proxy_mm_fsm_state_chg(PROXY_MM_ST_READY);

	return proxy_mm;
}

void proxy_mm_add_auth_vectors(struct proxy_mm *proxy_mm,
			       const struct osmo_auth_vector *auth_vectors, size_t num_auth_vectors)
{
	struct proxy_mm_auth_cache *ac = talloc_zero(proxy_mm, struct proxy_mm_auth_cache);
	int i;
	OSMO_ASSERT(ac);
	ac->num_auth_vectors = num_auth_vectors;
	for (i = 0; i < num_auth_vectors; i++)
		ac->auth_vectors[i] = auth_vectors[i];
	if (proxy_db_add_auth_vectors(&proxy_mm->vlr_name, ac)) {
		talloc_free(ac);
		return;
	}
	llist_add(&ac->entry, &proxy_mm->auth_cache);
}

struct proxy_mm_auth_cache *proxy_mm_get_auth_vectors(struct proxy_mm *proxy_mm)
{
	struct proxy_mm_auth_cache *i;
	struct proxy_mm_auth_cache *ac = NULL;

	llist_for_each_entry(i, &proxy_mm->auth_cache, entry) {
		if (!ac || i->sent_to_vlr_count < ac->sent_to_vlr_count) {
			ac = i;
		}
	}

	/* ac now points to (one of) the least used auth cache entries (or NULL if none). */
	return ac;
}

void proxy_mm_discard_auth_vectors(struct proxy_mm *proxy_mm, struct proxy_mm_auth_cache *ac)
{
	proxy_db_drop_auth_vectors(ac->db_id);
	llist_del(&ac->entry);
	talloc_free(ac);
}

/* Mark given auth cache entries as sent to the VLR and clean up if necessary. */
void proxy_mm_use_auth_vectors(struct proxy_mm *proxy_mm, struct proxy_mm_auth_cache *ac)
{
	struct proxy_mm_auth_cache *i, *i_next;
	bool found_fresh_ac = false;

	/* The aim is to keep at least one set of already used auth tuples in the cache. If there are still fresh ones,
	 * all used auth vectors can be discarded. If there are no fresh ones left, keep only this last set. */

	llist_for_each_entry_safe(i, i_next, &proxy_mm->auth_cache, entry) {
		if (i == ac)
			continue;
		if (i->sent_to_vlr_count) {
			/* An auth entry other than this freshly used one, which has been used before.
			 * No need to keep it. */
			proxy_mm_discard_auth_vectors(proxy_mm, i);
			continue;
		}
		if (!i->sent_to_vlr_count)
			found_fresh_ac = true;
	}

	if (found_fresh_ac) {
		/* There are still other, fresh auth vectors. */
		proxy_mm_discard_auth_vectors(proxy_mm, ac);
	} else {
		/* else, only this ac remains in the list */
		ac->sent_to_vlr_count++;
		proxy_db_auth_vectors_update_sent_count(ac);
	}
}

static void proxy_mm_ready_action(struct osmo_fsm_inst *mm_fi, uint32_t event, void *data)
{
	struct proxy *proxy = g_hlr->gs->proxy;
	struct proxy_mm *proxy_mm = mm_fi->priv;

	switch (event) {

	case PROXY_MM_EV_SUBSCR_INVALID:
		/* Home HLR has responded and rejected a Location Updating, or no home HLR could be found. The
		 * subscriber is invalid, remove it from the cache. */
		proxy_subscr_del(proxy, proxy_mm->imsi);
		osmo_fsm_inst_term(mm_fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;

	case PROXY_MM_EV_RX_GSUP_LU:
		/* The MSC asks for a LU. If we don't know details about this subscriber, then we'll have to wait for the
		 * home HLR to respond. If we already know details about the subscriber, we respond immediately (with
		 * Insert Subscriber Data and accept the LU), but also ask the home HLR to confirm the LU later. */
		osmo_fsm_inst_dispatch(proxy_mm->to_home_fi, PROXY_TO_HOME_EV_CONFIRM_LU, NULL);

		if (proxy_mm_subscriber_data_known(proxy_mm))
			proxy_mm_fsm_state_chg(PROXY_MM_ST_WAIT_GSUP_ISD_RESULT);
		else
			proxy_mm_fsm_state_chg(PROXY_MM_ST_WAIT_SUBSCR_DATA);
		break;

	case PROXY_MM_EV_RX_GSUP_SAI:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_mm_ready_timeout(struct osmo_fsm_inst *mm_fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

void proxy_mm_wait_subscr_data_onenter(struct osmo_fsm_inst *mm_fi, uint32_t prev_state)
{
	//struct proxy_mm *proxy_mm = mm_fi->priv;
	// FIXME
}

static void proxy_mm_wait_subscr_data_action(struct osmo_fsm_inst *mm_fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = mm_fi->priv;

	switch (event) {

	case PROXY_MM_EV_RX_SUBSCR_DATA:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_mm_wait_subscr_data_timeout(struct osmo_fsm_inst *mm_fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

static void proxy_mm_lu_error(struct osmo_fsm_inst *mm_fi)
{
	osmo_gsup_req_respond_err(req, GMM_CAUSE_ROAMING_NOTALLOWED,
				  "LU does not accept GSUP rx");

}

void proxy_mm_wait_gsup_isd_result_onenter(struct osmo_fsm_inst *mm_fi, uint32_t prev_state)
{
	struct proxy_mm *proxy_mm = mm_fi->priv;
	struct proxy_subscr proxy_subscr;
	struct osmo_gsup_message isd_req;

	uint8_t msisdn_enc[OSMO_GSUP_MAX_CALLED_PARTY_BCD_LEN];
	uint8_t apn[APN_MAXLEN];

	isd_req.message_type = OSMO_GSUP_MSGT_INSERT_DATA_REQUEST;

	if (proxy_subscr_get_by_imsi(&proxy_subscr, g_hlr->gs->proxy, proxy_mm->imsi)) {
		LOGPFSML(mm_fi, LOGL_ERROR,
			 "Proxy: trying to send cached Subscriber Data, but there is no proxy entry\n");
		proxy_mm_lu_error(mm_fi);
		return;
	}

	if (proxy_subscr.msisdn[0] == '\0') {
		LOGPFSML(mm_fi, LOGL_ERROR,
			 "Proxy: trying to send cached Subscriber Data, but subscriber has no MSISDN in proxy cache\n");
		proxy_mm_lu_error(mm_fi);
		return;
	}

	if (osmo_gsup_create_insert_subscriber_data_msg(&isd_req, proxy_mm->imsi,
							proxy_subscr->msisdn, msisdn_enc, sizeof(msisdn_enc),
							apn, sizeof(apn),
							proxy_mm->is_ps? OSMO_GSUP_CN_DOMAIN_PS : OSMO_GSUP_CN_DOMAIN_CS)) {
		LOGPFSML(mm_fi, LOGL_ERROR, "Proxy: failed to send cached Subscriber Data\n");
		proxy_mm_lu_error(mm_fi);
		return;
	}
}

static void proxy_mm_wait_gsup_isd_result_action(struct osmo_fsm_inst *mm_fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = mm_fi->priv;

	switch (event) {

	case PROXY_MM_EV_RX_GSUP_ISD_RESULT:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_mm_wait_gsup_isd_result_timeout(struct osmo_fsm_inst *mm_fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

void proxy_mm_wait_auth_tuples_onenter(struct osmo_fsm_inst *mm_fi, uint32_t prev_state)
{
	//struct proxy_mm *proxy_mm = mm_fi->priv;
	// FIXME
}

static void proxy_mm_wait_auth_tuples_action(struct osmo_fsm_inst *mm_fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = mm_fi->priv;

	switch (event) {

	case PROXY_MM_EV_RX_AUTH_TUPLES:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_mm_wait_auth_tuples_timeout(struct osmo_fsm_inst *mm_fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

#define S(x)    (1 << (x))

static const struct osmo_fsm_state proxy_mm_fsm_states[] = {
	[PROXY_MM_ST_READY] = {
		.name = "ready",
		.in_event_mask = 0
			| S(PROXY_MM_EV_SUBSCR_INVALID)
			| S(PROXY_MM_EV_RX_GSUP_LU)
			| S(PROXY_MM_EV_RX_GSUP_SAI)
			,
		.out_state_mask = 0
			| S(PROXY_MM_ST_READY)
			| S(PROXY_MM_ST_WAIT_SUBSCR_DATA)
			| S(PROXY_MM_ST_WAIT_GSUP_ISD_RESULT)
			| S(PROXY_MM_ST_WAIT_AUTH_TUPLES)
			,
		.action = proxy_mm_ready_action,
	},
	[PROXY_MM_ST_WAIT_SUBSCR_DATA] = {
		.name = "wait_subscr_data",
		.in_event_mask = 0
			| S(PROXY_MM_EV_RX_SUBSCR_DATA)
			,
		.out_state_mask = 0
			| S(PROXY_MM_ST_WAIT_GSUP_ISD_RESULT)
			| S(PROXY_MM_ST_READY)
			,
		.onenter = proxy_mm_wait_subscr_data_onenter,
		.action = proxy_mm_wait_subscr_data_action,
	},
	[PROXY_MM_ST_WAIT_GSUP_ISD_RESULT] = {
		.name = "wait_gsup_isd_result",
		.in_event_mask = 0
			| S(PROXY_MM_EV_RX_GSUP_ISD_RESULT)
			,
		.out_state_mask = 0
			| S(PROXY_MM_ST_READY)
			,
		.onenter = proxy_mm_wait_gsup_isd_result_onenter,
		.action = proxy_mm_wait_gsup_isd_result_action,
	},
	[PROXY_MM_ST_WAIT_AUTH_TUPLES] = {
		.name = "wait_auth_tuples",
		.in_event_mask = 0
			| S(PROXY_MM_EV_RX_AUTH_TUPLES)
			,
		.out_state_mask = 0
			| S(PROXY_MM_ST_READY)
			,
		.onenter = proxy_mm_wait_auth_tuples_onenter,
		.action = proxy_mm_wait_auth_tuples_action,
	},
};

static int proxy_mm_fsm_timer_cb(struct osmo_fsm_inst *mm_fi)
{
	//struct proxy_mm *proxy_mm = mm_fi->priv;
	switch (mm_fi->state) {

	case PROXY_MM_ST_READY:
		return proxy_mm_ready_timeout(mm_fi);

	case PROXY_MM_ST_WAIT_SUBSCR_DATA:
		return proxy_mm_wait_subscr_data_timeout(mm_fi);

	case PROXY_MM_ST_WAIT_GSUP_ISD_RESULT:
		return proxy_mm_wait_gsup_isd_result_timeout(mm_fi);

	case PROXY_MM_ST_WAIT_AUTH_TUPLES:
		return proxy_mm_wait_auth_tuples_timeout(mm_fi);

	default:
		/* Return 1 to terminate FSM instance, 0 to keep running */
		return 1;
	}
}

void proxy_mm_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct proxy_mm *proxy_mm = fi->priv;
	llist_del(&proxy_mm->entry);
}

static struct osmo_fsm proxy_mm_fsm = {
	.name = "proxy_mm",
	.states = proxy_mm_fsm_states,
	.num_states = ARRAY_SIZE(proxy_mm_fsm_states),
	.log_subsys = DLGLOBAL, // FIXME
	.event_names = proxy_mm_fsm_event_names,
	.timer_cb = proxy_mm_fsm_timer_cb,
	.cleanup = proxy_mm_fsm_cleanup,
};

static __attribute__((constructor)) void proxy_mm_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&proxy_mm_fsm) == 0);
}

bool proxy_mm_subscriber_data_known(const struct proxy_mm *proxy_mm)
{
	struct proxy_subscr proxy_subscr;
	if (proxy_subscr_get_by_imsi(&proxy_subscr, g_hlr->gs->proxy, proxy_mm->imsi))
		return false;
	return proxy_subscr.msisdn[0] != '\0';
}
