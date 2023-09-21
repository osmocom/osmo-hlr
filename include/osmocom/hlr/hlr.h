/* OsmoHLR generic header */

/* (C) 2017 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Max Suraev <msuraev@sysmocom.de>
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

#pragma once

#include <stdbool.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/hlr/dgsm.h>

#define HLR_DEFAULT_DB_FILE_PATH "hlr.db"

struct hlr_euse;
struct osmo_gsup_conn;
enum osmo_gsup_message_type;

extern struct osmo_tdef g_hlr_tdefs[];

struct hlr {
	/* GSUP server pointer */
	struct osmo_gsup_server *gs;

	/* DB context */
	char *db_file_path;
	struct db_context *dbc;

	/* Control Interface */
	struct ctrl_handle *ctrl;

	/* Local bind addr */
	char *gsup_bind_addr;
	struct ipaccess_unit gsup_unit_name;

	struct llist_head euse_list;
	struct hlr_euse *euse_default;
	enum gsm48_gmm_cause reject_cause;
	enum gsm48_gmm_cause no_proxy_reject_cause;
	/* PS: APN default configuration used by Subscription Data on ISR */
	struct {
		struct {
			bool enabled;
			struct osmo_gsup_pdp_info pdp_infos[OSMO_GSUP_MAX_NUM_PDP_INFO];
			size_t num_pdp_infos;
		} pdp_profile;
	} ps;

	/* NCSS (call independent) session guard timeout value */
	int ncss_guard_timeout;

	struct llist_head ussd_routes;

	struct llist_head ss_sessions;

	struct llist_head smsc_list;
	struct llist_head smsc_routes;
	struct hlr_smsc *smsc_default;

	bool store_imei;

	bool subscr_create_on_demand;
	/* Bitmask of DB_SUBSCR_FLAG_* */
	uint8_t subscr_create_on_demand_flags;
	unsigned int subscr_create_on_demand_rand_msisdn_len;

	struct {
		bool allow_startup;
		struct {
			/* Whether the mslookup server should be active in general (all lookup methods) */
			bool enable;
			uint32_t local_attach_max_age;
			struct llist_head local_site_services;
			struct {
				/* Whether the mDNS method of the mslookup server should be active. */
				bool enable;
				/* The mDNS bind address and domain suffix as set by the VTY, not necessarily in use. */
				struct osmo_sockaddr_str bind_addr;
				char *domain_suffix;
				struct osmo_mslookup_server_mdns *running;
			} mdns;
		} server;

		/* The mslookup client in osmo-hlr is used to find out which remote HLRs service a locally unknown IMSI.
		 * (It may also be used to resolve recipients for SMS-over-GSUP in the future.) */
		struct {
			/* Whether to proxy/forward to remote HLRs */
			bool enable;

			/* If this is set, all GSUP for unknown IMSIs is forwarded directly to this GSUP address,
			 * unconditionally. */
			struct osmo_sockaddr_str gsup_gateway_proxy;

			/* mslookup client request handling */
			unsigned int result_timeout_milliseconds;

			struct osmo_mslookup_client *client;
			struct {
				/* Whether to use mDNS for IMSI MS Lookup */
				bool enable;
				struct osmo_sockaddr_str query_addr;
				char *domain_suffix;
				struct osmo_mslookup_client_method *running;
			} mdns;
		} client;
	} mslookup;
};

extern struct hlr *g_hlr;

struct hlr_subscriber;

void osmo_hlr_subscriber_update_notify(struct hlr_subscriber *subscr);
int hlr_subscr_nam(struct hlr *hlr, struct hlr_subscriber *subscr, bool nam_val, bool is_ps);
