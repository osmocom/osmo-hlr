#pragma once

#include <osmocom/mslookup/mslookup.h>
#include "gsup_server.h"
#include "global_title.h"

struct vty;

extern void *dgsm_ctx;

struct dgsm_service_host {
	struct llist_head entry;
	char service[OSMO_MSLOOKUP_SERVICE_MAXLEN+1];
	struct osmo_sockaddr_str host_v4;
	struct osmo_sockaddr_str host_v6;
};

struct dgsm_msc_config {
	struct llist_head entry;
	struct global_title name;
	struct llist_head service_hosts;
};

/* "Sketch pad" where the VTY can store config items without yet applying. The changes will be applied by e.g.
 * dgsm_mdns_server_config_apply() and dgsm_mdns_client_config_apply(). */
struct dgsm_config {
	struct {
		/* Whether to listen for incoming MS Lookup requests */
		bool enable;

		struct {
			bool enable;
			struct osmo_sockaddr_str bind_addr;
		} mdns;

		struct llist_head msc_configs;
	} server;

	struct {
		/* Whether to ask remote HLRs via MS Lookup if an IMSI is not known locally. */
		bool enable;
		struct timeval timeout;

		struct {
			/* Whether to use mDNS for IMSI MS Lookup */
			bool enable;
			struct osmo_sockaddr_str query_addr;
		} mdns;
	} client;
};

void dgsm_config_apply();

struct dgsm_service_host *dgsm_config_service_get(const struct global_title *msc_name, const char *service);
int dgsm_config_service_set(const struct global_title *msc_name, const char *service, const struct osmo_sockaddr_str *addr);
int dgsm_config_service_del(const struct global_title *msc_name, const char *service, const struct osmo_sockaddr_str *addr);

struct dgsm_service_host *dgsm_config_msc_service_get(struct dgsm_msc_config *msc, const char *service, bool create);
int dgsm_config_msc_service_set(struct dgsm_msc_config *msc, const char *service, const struct osmo_sockaddr_str *addr);
int dgsm_config_msc_service_del(struct dgsm_msc_config *msc, const char *service, const struct osmo_sockaddr_str *addr);

extern const struct global_title dgsm_config_msc_wildcard;
struct dgsm_msc_config *dgsm_config_msc_get(const struct global_title *msc_name, bool create);

void dgsm_init(void *ctx);
void dgsm_start(void *ctx);
bool dgsm_check_forward_gsup_msg(struct osmo_gsup_conn *conn, const struct osmo_gsup_message *gsup);

void dgsm_vty_init();
void dgsm_vty_go_parent_action(struct vty *vty);
