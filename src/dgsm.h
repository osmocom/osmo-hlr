#pragma once

#include <osmocom/mslookup/mslookup.h>
#include "gsup_server.h"

extern void *dgsm_ctx;

struct dgsm_service_addr {
	struct llist_head entry;
	char service[OSMO_MSLOOKUP_SERVICE_MAXLEN+1];
	struct osmo_sockaddr_str addr_v4;
	struct osmo_sockaddr_str addr_v6;
};

struct dgsm_msc_config {
	struct llist_head entry;
	uint8_t *unit_name;
	size_t unit_name_len;
	struct llist_head service_addrs;
};

struct dgsm_config {
	struct {
		/* Whether to listen for incoming MS Lookup requests */
		bool enable;

		struct {
			bool enable;
			struct osmo_sockaddr_str multicast_bind_addr;
		} dns;

		struct llist_head msc_configs;
	} server;

	struct {
		/* Whether to ask remote HLRs via MS Lookup if an IMSI is not known locally. */
		bool enable;

		struct {
			/* Whether to use mDNS for IMSI MS Lookup */
			bool enable;
			struct osmo_sockaddr_str multicast_query_addr;
		} dns;
	} client;
};

extern struct dgsm_config dgsm_config;
void dgsm_dns_server_config_apply();
void dgsm_dns_client_config_apply();

struct dgsm_service_addr *dgsm_config_service_get(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
						  const char *service);
int dgsm_config_service_set(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
			    const char *service, const struct osmo_sockaddr_str *addr);
int dgsm_config_service_del(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
			    const char *service, const struct osmo_sockaddr_str *addr);

struct dgsm_msc_config *dgsm_config_msc_get(const uint8_t *ipa_unit_name, size_t ipa_unit_name_len,
					    bool create);

void dgsm_init(void *ctx);
bool dgsm_check_forward_gsup_msg(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup);

void dgsm_vty_init();
void dgsm_vty_go_parent_action(struct vty *vty);
