
#include <osmocom/hlr/proxy_mm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

enum proxy_to_home_fsm_state {
	PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED,
	PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT,
	PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT,
	PROXY_TO_HOME_ST_IDLE,
	PROXY_TO_HOME_ST_CLEAR,
};

static const struct value_string proxy_to_home_fsm_event_names[] = {
	OSMO_VALUE_STRING(PROXY_TO_HOME_EV_HOME_HLR_RESOLVED),
	OSMO_VALUE_STRING(PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ),
	OSMO_VALUE_STRING(PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT),
	OSMO_VALUE_STRING(PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT),
	OSMO_VALUE_STRING(PROXY_TO_HOME_EV_CHECK_TUPLES),
	OSMO_VALUE_STRING(PROXY_TO_HOME_EV_CONFIRM_LU),
	{}
};

static struct osmo_fsm proxy_to_home_fsm;

struct osmo_tdef proxy_to_home_tdefs[] = {
// FIXME
	{ .T=-1, .default_val=5, .desc="proxy_to_home wait_home_hlr_resolved timeout" },
	{ .T=-2, .default_val=5, .desc="proxy_to_home wait_update_location_result timeout" },
	{ .T=-3, .default_val=5, .desc="proxy_to_home wait_send_auth_info_result timeout" },
	{ .T=-4, .default_val=5, .desc="proxy_to_home idle timeout" },
	{ .T=-5, .default_val=5, .desc="proxy_to_home clear timeout" },
	{}
};

#if 0
static const struct osmo_tdef_state_timeout proxy_to_home_fsm_timeouts[32] = {
// FIXME
	[PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED] = { .T=-1 },
	[PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT] = { .T=-2 },
	[PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT] = { .T=-3 },
	[PROXY_TO_HOME_ST_IDLE] = { .T=-4 },
	[PROXY_TO_HOME_ST_CLEAR] = { .T=-5 },
};
#endif

#define proxy_to_home_fsm_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     proxy_to_home_fsm_timeouts, \
				     proxy_to_home_tdefs, \
				     5)

void proxy_to_home_wait_home_hlr_resolved_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	//struct proxy_mm *proxy_mm = fi->priv;
	// FIXME
}

static void proxy_to_home_wait_home_hlr_resolved_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = fi->priv;

	switch (event) {

	case PROXY_TO_HOME_EV_HOME_HLR_RESOLVED:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CHECK_TUPLES:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CONFIRM_LU:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_to_home_wait_home_hlr_resolved_timeout(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

void proxy_to_home_wait_update_location_result_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	//struct proxy_mm *proxy_mm = fi->priv;
	// FIXME
}

static void proxy_to_home_wait_update_location_result_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = fi->priv;

	switch (event) {

	case PROXY_TO_HOME_EV_HOME_HLR_RESOLVED:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CHECK_TUPLES:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CONFIRM_LU:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_to_home_wait_update_location_result_timeout(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

void proxy_to_home_wait_send_auth_info_result_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	//struct proxy_mm *proxy_mm = fi->priv;
	// FIXME
}

static void proxy_to_home_wait_send_auth_info_result_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = fi->priv;

	switch (event) {

	case PROXY_TO_HOME_EV_HOME_HLR_RESOLVED:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CHECK_TUPLES:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CONFIRM_LU:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_to_home_wait_send_auth_info_result_timeout(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

void proxy_to_home_idle_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	//struct proxy_mm *proxy_mm = fi->priv;
	// FIXME
}

static void proxy_to_home_idle_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = fi->priv;

	switch (event) {

	case PROXY_TO_HOME_EV_HOME_HLR_RESOLVED:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CHECK_TUPLES:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CONFIRM_LU:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_to_home_idle_timeout(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

void proxy_to_home_clear_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	//struct proxy_mm *proxy_mm = fi->priv;
	// FIXME
}

static void proxy_to_home_clear_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	//struct proxy_mm *proxy_mm = fi->priv;

	switch (event) {

	case PROXY_TO_HOME_EV_HOME_HLR_RESOLVED:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CHECK_TUPLES:
		// FIXME
		break;

	case PROXY_TO_HOME_EV_CONFIRM_LU:
		// FIXME
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static int proxy_to_home_clear_timeout(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	return 1;
}

#define S(x)    (1 << (x))

static const struct osmo_fsm_state proxy_to_home_fsm_states[] = {
	[PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED] = {
		.name = "wait_home_hlr_resolved",
		.in_event_mask = 0
			| S(PROXY_TO_HOME_EV_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ)
			| S(PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_EV_CHECK_TUPLES)
			| S(PROXY_TO_HOME_EV_CONFIRM_LU)
			,
		.out_state_mask = 0
			| S(PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_ST_IDLE)
			| S(PROXY_TO_HOME_ST_CLEAR)
			,
		.onenter = proxy_to_home_wait_home_hlr_resolved_onenter,
		.action = proxy_to_home_wait_home_hlr_resolved_action,
	},
	[PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT] = {
		.name = "wait_update_location_result",
		.in_event_mask = 0
			| S(PROXY_TO_HOME_EV_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ)
			| S(PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_EV_CHECK_TUPLES)
			| S(PROXY_TO_HOME_EV_CONFIRM_LU)
			,
		.out_state_mask = 0
			| S(PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_ST_IDLE)
			| S(PROXY_TO_HOME_ST_CLEAR)
			,
		.onenter = proxy_to_home_wait_update_location_result_onenter,
		.action = proxy_to_home_wait_update_location_result_action,
	},
	[PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT] = {
		.name = "wait_send_auth_info_result",
		.in_event_mask = 0
			| S(PROXY_TO_HOME_EV_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ)
			| S(PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_EV_CHECK_TUPLES)
			| S(PROXY_TO_HOME_EV_CONFIRM_LU)
			,
		.out_state_mask = 0
			| S(PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_ST_IDLE)
			| S(PROXY_TO_HOME_ST_CLEAR)
			,
		.onenter = proxy_to_home_wait_send_auth_info_result_onenter,
		.action = proxy_to_home_wait_send_auth_info_result_action,
	},
	[PROXY_TO_HOME_ST_IDLE] = {
		.name = "idle",
		.in_event_mask = 0
			| S(PROXY_TO_HOME_EV_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ)
			| S(PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_EV_CHECK_TUPLES)
			| S(PROXY_TO_HOME_EV_CONFIRM_LU)
			,
		.out_state_mask = 0
			| S(PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_ST_IDLE)
			| S(PROXY_TO_HOME_ST_CLEAR)
			,
		.onenter = proxy_to_home_idle_onenter,
		.action = proxy_to_home_idle_action,
	},
	[PROXY_TO_HOME_ST_CLEAR] = {
		.name = "clear",
		.in_event_mask = 0
			| S(PROXY_TO_HOME_EV_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ)
			| S(PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_EV_CHECK_TUPLES)
			| S(PROXY_TO_HOME_EV_CONFIRM_LU)
			,
		.out_state_mask = 0
			| S(PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED)
			| S(PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT)
			| S(PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT)
			| S(PROXY_TO_HOME_ST_IDLE)
			| S(PROXY_TO_HOME_ST_CLEAR)
			,
		.onenter = proxy_to_home_clear_onenter,
		.action = proxy_to_home_clear_action,
	},
};

static int proxy_to_home_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	//struct proxy_mm *proxy_mm = fi->priv;
	switch (fi->state) {

	case PROXY_TO_HOME_ST_WAIT_HOME_HLR_RESOLVED:
		return proxy_to_home_wait_home_hlr_resolved_timeout(fi);

	case PROXY_TO_HOME_ST_WAIT_UPDATE_LOCATION_RESULT:
		return proxy_to_home_wait_update_location_result_timeout(fi);

	case PROXY_TO_HOME_ST_WAIT_SEND_AUTH_INFO_RESULT:
		return proxy_to_home_wait_send_auth_info_result_timeout(fi);

	case PROXY_TO_HOME_ST_IDLE:
		return proxy_to_home_idle_timeout(fi);

	case PROXY_TO_HOME_ST_CLEAR:
		return proxy_to_home_clear_timeout(fi);

	default:
		/* Return 1 to terminate FSM instance, 0 to keep running */
		return 1;
	}
}

void proxy_to_home_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	//struct proxy_mm *proxy_mm = fi->priv;
	// FIXME
}

static struct osmo_fsm proxy_to_home_fsm = {
	.name = "proxy_to_home",
	.states = proxy_to_home_fsm_states,
	.num_states = ARRAY_SIZE(proxy_to_home_fsm_states),
	.log_subsys = DLGLOBAL, // FIXME
	.event_names = proxy_to_home_fsm_event_names,
	.timer_cb = proxy_to_home_fsm_timer_cb,
	.cleanup = proxy_to_home_fsm_cleanup,
};

static __attribute__((constructor)) void proxy_to_home_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&proxy_to_home_fsm) == 0);
}
