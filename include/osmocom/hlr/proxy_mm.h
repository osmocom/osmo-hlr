#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/hlr/proxy.h>

enum proxy_mm_fsm_event {
	PROXY_MM_EV_SUBSCR_INVALID,
	PROXY_MM_EV_RX_GSUP_LU,
	PROXY_MM_EV_RX_GSUP_SAI,
	PROXY_MM_EV_RX_SUBSCR_DATA,
	PROXY_MM_EV_RX_GSUP_ISD_RESULT,
	PROXY_MM_EV_RX_AUTH_TUPLES,
};

enum proxy_to_home_fsm_event {
	PROXY_TO_HOME_EV_HOME_HLR_RESOLVED,
	PROXY_TO_HOME_EV_RX_INSERT_SUBSCRIBER_DATA_REQ,
	PROXY_TO_HOME_EV_RX_UPDATE_LOCATION_RESULT,
	PROXY_TO_HOME_EV_RX_SEND_AUTH_INFO_RESULT,
	PROXY_TO_HOME_EV_CHECK_TUPLES,
	PROXY_TO_HOME_EV_CONFIRM_LU,
};

extern struct llist_head proxy_mm_list;

struct proxy_mm_auth_cache {
	struct llist_head entry;
	uint64_t db_id;
	struct osmo_auth_vector	auth_vectors[OSMO_GSUP_MAX_NUM_AUTH_INFO];
	size_t num_auth_vectors;
	unsigned int sent_to_vlr_count;
};

struct proxy_mm {
	struct llist_head entry;
	struct osmo_gsup_peer_id vlr_name;
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	bool is_ps;
	struct osmo_fsm_inst *mm_fi;
	struct osmo_fsm_inst *to_home_fi;
	struct llist_head auth_cache;
};

struct proxy_mm *proxy_mm_alloc(const struct osmo_gsup_peer_id *vlr_name,
				bool is_ps,
				const char *imsi);

void proxy_mm_add_auth_vectors(struct proxy_mm *proxy_mm,
			       const struct osmo_auth_vector *auth_vectors, size_t num_auth_vectors);
struct proxy_mm_auth_cache *proxy_mm_get_auth_vectors(struct proxy_mm *proxy_mm);
void proxy_mm_use_auth_vectors(struct proxy_mm *proxy_mm, struct proxy_mm_auth_cache *ac);
void proxy_mm_discard_auth_vectors(struct proxy_mm *proxy_mm, struct proxy_mm_auth_cache *ac);

bool proxy_mm_subscriber_data_known(const struct proxy_mm *proxy_mm);
