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

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>
#include <osmocom/mslookup/mdns.h>
#include <osmocom/hlr/hlr_vty.h>
#include <osmocom/hlr/proxy.h>
#include <osmocom/hlr/mslookup_server.h>
#include <osmocom/hlr/mslookup_server_mdns.h>
#include <osmocom/gsupclient/cni_peer_id.h>
#include <osmocom/gsm/gsm23003.h>

struct cmd_node mslookup_node = {
	MSLOOKUP_NODE,
	"%s(config-mslookup)# ",
	1,
};

DEFUN(cfg_mslookup,
      cfg_mslookup_cmd,
      "mslookup",
      "Configure Distributed GSM mslookup")
{
	vty->node = MSLOOKUP_NODE;
	return CMD_SUCCESS;
}

static int mslookup_server_mdns_bind(struct vty *vty, int argc, const char **argv)
{
	const char *ip_str = argc > 0? argv[0] : g_hlr->mslookup.server.mdns.bind_addr.ip;
	const char *port_str = argc > 1? argv[1] : NULL;
	uint16_t port_nr = port_str ? atoi(port_str) : g_hlr->mslookup.server.mdns.bind_addr.port;
	struct osmo_sockaddr_str addr;
	if (osmo_sockaddr_str_from_str(&addr, ip_str, port_nr)
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% mslookup server: Invalid mDNS bind address: %s %u%s",
			ip_str, port_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hlr->mslookup.server.mdns.bind_addr = addr;
	g_hlr->mslookup.server.mdns.enable = true;
	g_hlr->mslookup.server.enable = true;
	mslookup_server_mdns_config_apply();
	return CMD_SUCCESS;
}

static int mslookup_client_mdns_to(struct vty *vty, int argc, const char **argv)
{
	const char *ip_str = argc > 0? argv[0] : g_hlr->mslookup.client.mdns.query_addr.ip;
	const char *port_str = argc > 1? argv[1] : NULL;
	uint16_t port_nr = port_str ? atoi(port_str) : g_hlr->mslookup.client.mdns.query_addr.port;
	struct osmo_sockaddr_str addr;
	if (osmo_sockaddr_str_from_str(&addr, ip_str, port_nr)
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% mslookup client: Invalid mDNS target address: %s %u%s",
			ip_str, port_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hlr->mslookup.client.mdns.query_addr = addr;
	g_hlr->mslookup.client.mdns.enable = true;
	g_hlr->mslookup.client.enable = true;
	dgsm_mdns_client_config_apply();
	return CMD_SUCCESS;
}

#define MDNS_STR "Multicast DNS related configuration\n"
#define MDNS_IP46_STR "multicast IPv4 address like " OSMO_MSLOOKUP_MDNS_IP4 \
			" or IPv6 address like " OSMO_MSLOOKUP_MDNS_IP6 "\n"
#define MDNS_PORT_STR "mDNS UDP Port number\n"
#define MDNS_DOMAIN_SUFFIX_STR "mDNS domain suffix (default: " OSMO_MDNS_DOMAIN_SUFFIX_DEFAULT "). This is appended" \
				 " and stripped from mDNS packets during encoding/decoding, so we don't collide with" \
				 " top-level domains administrated by IANA\n"
#define IP46_STR "IPv4 address like 1.2.3.4 or IPv6 address like a:b:c:d::1\n"
#define PORT_STR "Service-specific port number\n"

DEFUN(cfg_mslookup_mdns,
      cfg_mslookup_mdns_cmd,
      "mdns bind [IP] [<1-65535>]",
      MDNS_STR
      "Convenience shortcut: enable and configure both server and client for mDNS mslookup\n"
      MDNS_IP46_STR MDNS_PORT_STR)
{
	int rc1 = mslookup_server_mdns_bind(vty, argc, argv);
	int rc2 = mslookup_client_mdns_to(vty, argc, argv);
	if (rc1 != CMD_SUCCESS)
		return rc1;
	return rc2;
}

DEFUN(cfg_mslookup_mdns_domain_suffix,
      cfg_mslookup_mdns_domain_suffix_cmd,
      "mdns domain-suffix DOMAIN_SUFFIX",
      MDNS_STR MDNS_DOMAIN_SUFFIX_STR MDNS_DOMAIN_SUFFIX_STR)
{
	osmo_talloc_replace_string(g_hlr, &g_hlr->mslookup.server.mdns.domain_suffix, argv[0]);
	osmo_talloc_replace_string(g_hlr, &g_hlr->mslookup.client.mdns.domain_suffix, argv[0]);
	mslookup_server_mdns_config_apply();
	dgsm_mdns_client_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_mdns,
      cfg_mslookup_no_mdns_cmd,
      "no mdns bind",
      NO_STR "Disable both server and client for mDNS mslookup\n")
{
	g_hlr->mslookup.server.mdns.enable = false;
	g_hlr->mslookup.client.mdns.enable = false;
	mslookup_server_mdns_config_apply();
	dgsm_mdns_client_config_apply();
	return CMD_SUCCESS;
}

struct cmd_node mslookup_server_node = {
	MSLOOKUP_SERVER_NODE,
	"%s(config-mslookup-server)# ",
	1,
};

DEFUN(cfg_mslookup_server,
      cfg_mslookup_server_cmd,
      "server",
      "Enable and configure Distributed GSM mslookup server")
{
	vty->node = MSLOOKUP_SERVER_NODE;
	g_hlr->mslookup.server.enable = true;
	mslookup_server_mdns_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_server,
      cfg_mslookup_no_server_cmd,
      "no server",
      NO_STR "Disable Distributed GSM mslookup server")
{
	g_hlr->mslookup.server.enable = false;
	mslookup_server_mdns_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_server_mdns_bind,
      cfg_mslookup_server_mdns_bind_cmd,
      "mdns bind [IP] [<1-65535>]",
      MDNS_STR
      "Configure where the mDNS server listens for mslookup requests\n"
      MDNS_IP46_STR MDNS_PORT_STR)
{
	return mslookup_server_mdns_bind(vty, argc, argv);
}

DEFUN(cfg_mslookup_server_mdns_domain_suffix,
      cfg_mslookup_server_mdns_domain_suffix_cmd,
      "mdns domain-suffix DOMAIN_SUFFIX",
      MDNS_STR
      MDNS_DOMAIN_SUFFIX_STR
      MDNS_DOMAIN_SUFFIX_STR)
{
	osmo_talloc_replace_string(g_hlr, &g_hlr->mslookup.server.mdns.domain_suffix, argv[0]);
	mslookup_server_mdns_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_server_no_mdns_bind,
      cfg_mslookup_server_no_mdns_bind_cmd,
      "no mdns bind",
      NO_STR "Disable server for mDNS mslookup (do not answer remote requests)\n")
{
	g_hlr->mslookup.server.mdns.enable = false;
	mslookup_server_mdns_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_server_max_age,
      cfg_mslookup_server_max_age_cmd,
      "max-age <1-21600>",
      "How old can the Last Location Update be for the mslookup server to respond\n"
      "max age in seconds\n")
{
	uint32_t val = atol(argv[0]);
	g_hlr->mslookup.server.local_attach_max_age = val;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_auth_imsi_only,
      cfg_mslookup_auth_imsi_only_cmd,
      "authorized-imsi-only",
      "On local GSUP, use mslookup ignoring local HLR + don't answer queries for IMSIs without PS or CS network access mode")
{
	g_hlr->mslookup.auth_imsi_only = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_auth_imsi_only,
      cfg_mslookup_no_auth_imsi_only_cmd,
      "no authorized-imsi-only",
      NO_STR "Answer Local GSUP/mDNS queries for any IMSI in the local HLR database")
{
	g_hlr->mslookup.auth_imsi_only = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_cod,
      cfg_mslookup_cod_cmd,
      "ignore-created-on-demand",
      "Ignore IMSIs that were created-on-demand")
{
	g_hlr->mslookup.ignore_created_on_demand = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_cod,
      cfg_mslookup_no_cod_cmd,
      "no ignore-created-on-demand",
      NO_STR "Answer mslookup and local GSUP for created on demand IMSIs")
{
	g_hlr->mslookup.ignore_created_on_demand = false;
	return CMD_SUCCESS;
}

struct cmd_node mslookup_server_msc_node = {
	MSLOOKUP_SERVER_MSC_NODE,
	"%s(config-mslookup-server-msc)# ",
	1,
};

DEFUN(cfg_mslookup_server_msc,
      cfg_mslookup_server_msc_cmd,
      "msc ipa-name .IPA_NAME",
      "Configure services for individual local MSCs\n"
      "Identify locally connected MSC by IPA Unit Name\n"
      "IPA Unit Name of the local MSC to configure\n")
{
	struct osmo_ipa_name msc_name;
	struct mslookup_server_msc_cfg *msc;
	osmo_ipa_name_set_str(&msc_name, argv_concat(argv, argc, 0));

	msc = mslookup_server_msc_get(&msc_name, true);
	if (!msc) {
		vty_out(vty, "%% Error creating MSC %s%s", osmo_ipa_name_to_str(&msc_name), VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty->node = MSLOOKUP_SERVER_MSC_NODE;
	vty->index = msc;
	return CMD_SUCCESS;
}

#define SERVICE_NAME_STR \
	"mslookup service name, e.g. sip.voice or smpp.sms\n"

static struct mslookup_server_msc_cfg *msc_from_node(struct vty *vty)
{
	switch (vty->node) {
	case MSLOOKUP_SERVER_NODE:
		/* On the mslookup.server node, set services on the wildcard msc, without a particular name. */
		return mslookup_server_msc_get(&mslookup_server_msc_wildcard, true);
	case MSLOOKUP_SERVER_MSC_NODE:
		return vty->index;
	default:
		return NULL;
	}
}

DEFUN(cfg_mslookup_server_msc_service,
      cfg_mslookup_server_msc_service_cmd,
      "service NAME at IP <1-65535>",
      "Configure addresses of local services, as sent in replies to remote mslookup requests.\n"
      SERVICE_NAME_STR "at\n" IP46_STR PORT_STR)
{
	/* If this command is run on the 'server' node, it produces an empty unit name and serves as wildcard for all
	 * MSCs. If on a 'server' / 'msc' node, set services only for that MSC Unit Name. */
	struct mslookup_server_msc_cfg *msc = msc_from_node(vty);
	const char *service = argv[0];
	const char *ip_str = argv[1];
	const char *port_str = argv[2];
	struct osmo_sockaddr_str addr;

	if (!msc) {
		vty_out(vty, "%% Error: no MSC object on this node%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&addr, ip_str, atoi(port_str))
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% mslookup server: Invalid address for service %s: %s %s%s",
			service, ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mslookup_server_msc_service_set(msc, service, &addr)) {
		vty_out(vty, "%% mslookup server: Error setting service %s to %s %s%s",
			service, ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

#define NO_SERVICE_AND_NAME_STR NO_STR "Remove one or more service address entries\n" SERVICE_NAME_STR

DEFUN(cfg_mslookup_server_msc_no_service,
      cfg_mslookup_server_msc_no_service_cmd,
      "no service NAME",
      NO_SERVICE_AND_NAME_STR)
{
	/* If this command is run on the 'server' node, it produces an empty unit name and serves as wildcard for all
	 * MSCs. If on a 'server' / 'msc' node, set services only for that MSC Unit Name. */
	struct mslookup_server_msc_cfg *msc = msc_from_node(vty);
	const char *service = argv[0];

	if (!msc) {
		vty_out(vty, "%% Error: no MSC object on this node%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mslookup_server_msc_service_del(msc, service, NULL) < 1) {
		vty_out(vty, "%% mslookup server: cannot remove service '%s'%s",
			service, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_server_msc_no_service_addr,
      cfg_mslookup_server_msc_no_service_addr_cmd,
      "no service NAME at IP <1-65535>",
      NO_SERVICE_AND_NAME_STR "at\n" IP46_STR PORT_STR)
{
	/* If this command is run on the 'server' node, it produces an empty unit name and serves as wildcard for all
	 * MSCs. If on a 'server' / 'msc' node, set services only for that MSC Unit Name. */
	struct mslookup_server_msc_cfg *msc = msc_from_node(vty);
	const char *service = argv[0];
	const char *ip_str = argv[1];
	const char *port_str = argv[2];
	struct osmo_sockaddr_str addr;

	if (!msc) {
		vty_out(vty, "%% Error: no MSC object on this node%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&addr, ip_str, atoi(port_str))
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% mslookup server: Invalid address for 'no service' %s: %s %s%s",
			service, ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mslookup_server_msc_service_del(msc, service, &addr) < 1) {
		vty_out(vty, "%% mslookup server: cannot remove service '%s' to %s %s%s",
			service, ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

struct cmd_node mslookup_client_node = {
	MSLOOKUP_CLIENT_NODE,
	"%s(config-mslookup-client)# ",
	1,
};

DEFUN(cfg_mslookup_client,
      cfg_mslookup_client_cmd,
      "client",
      "Enable and configure Distributed GSM mslookup client")
{
	vty->node = MSLOOKUP_CLIENT_NODE;
	g_hlr->mslookup.client.enable = true;
	dgsm_mdns_client_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_client,
      cfg_mslookup_no_client_cmd,
      "no client",
      NO_STR "Disable Distributed GSM mslookup client")
{
	g_hlr->mslookup.client.enable = false;
	dgsm_mdns_client_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_client_subscr_cod_fallback,
      cfg_mslookup_client_subscr_cod_fallback_cmd,
      "create-on-demand-fallback",
      "If the msclient does not get a response from mDNS, proceed according to this HLR subscriber-create-on-demand config")
{
	g_hlr->mslookup.client.subscr_create_on_demand_fallback = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_client_no_subscr_cod_fallback,
      cfg_mslookup_client_no_subscr_cod_fallback_cmd,
      "no create-on-demand-fallback",
      NO_STR "Return IMSI UNKNOWN if the mslookup client does not receive a response from mDNS")
{
	g_hlr->mslookup.client.subscr_create_on_demand_fallback = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_client_timeout,
      cfg_mslookup_client_timeout_cmd,
      "timeout <1-100000>",
      "How long should the mslookup client wait for remote responses before evaluating received results\n"
      "timeout in milliseconds\n")
{
	uint32_t val = atol(argv[0]);
	g_hlr->mslookup.client.result_timeout_milliseconds = val;
	return CMD_SUCCESS;
}

#define EXIT_HINT() \
	if (vty->type != VTY_FILE) \
		vty_out(vty, "%% 'exit' this node to apply changes%s", VTY_NEWLINE)


DEFUN(cfg_mslookup_client_mdns_bind,
      cfg_mslookup_client_mdns_bind_cmd,
      "mdns bind [IP] [<1-65535>]",
      MDNS_STR
      "Enable mDNS client, and configure multicast address to send mDNS mslookup requests to\n"
      MDNS_IP46_STR MDNS_PORT_STR)
{
	return mslookup_client_mdns_to(vty, argc, argv);
}

DEFUN(cfg_mslookup_client_mdns_domain_suffix,
      cfg_mslookup_client_mdns_domain_suffix_cmd,
      "mdns domain-suffix DOMAIN_SUFFIX",
      MDNS_STR
      MDNS_DOMAIN_SUFFIX_STR
      MDNS_DOMAIN_SUFFIX_STR)
{
	osmo_talloc_replace_string(g_hlr, &g_hlr->mslookup.client.mdns.domain_suffix, argv[0]);
	dgsm_mdns_client_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_client_no_mdns_bind,
      cfg_mslookup_client_no_mdns_bind_cmd,
      "no mdns bind",
      NO_STR "Disable mDNS client, do not query remote services by mDNS\n")
{
	g_hlr->mslookup.client.mdns.enable = false;
	dgsm_mdns_client_config_apply();
	return CMD_SUCCESS;
}

void config_write_msc_services(struct vty *vty, const char *indent, struct mslookup_server_msc_cfg *msc)
{
	struct mslookup_service_host *e;

	llist_for_each_entry(e, &msc->service_hosts, entry) {
		if (osmo_sockaddr_str_is_nonzero(&e->host_v4))
			vty_out(vty, "%sservice %s at %s %u%s", indent, e->service, e->host_v4.ip, e->host_v4.port,
				VTY_NEWLINE);
		if (osmo_sockaddr_str_is_nonzero(&e->host_v6))
			vty_out(vty, "%sservice %s at %s %u%s", indent, e->service, e->host_v6.ip, e->host_v6.port,
				VTY_NEWLINE);
	}
}

int config_write_mslookup(struct vty *vty)
{
	if (!g_hlr->mslookup.server.enable
	    && llist_empty(&g_hlr->mslookup.server.local_site_services)
	    && !g_hlr->mslookup.client.enable)
		return CMD_SUCCESS;

	vty_out(vty, "mslookup%s", VTY_NEWLINE);

	if (g_hlr->mslookup.auth_imsi_only)
			vty_out(vty, " authorized-imsi-only%s", VTY_NEWLINE);
	if (g_hlr->mslookup.ignore_created_on_demand)
			vty_out(vty, " ignore-created-on-demand%s", VTY_NEWLINE);

	if (g_hlr->mslookup.server.enable || !llist_empty(&g_hlr->mslookup.server.local_site_services)) {
		struct mslookup_server_msc_cfg *msc;

		vty_out(vty, " server%s", VTY_NEWLINE);

		if (g_hlr->mslookup.server.mdns.enable) {
			vty_out(vty, "  mdns bind");
			if (osmo_sockaddr_str_is_nonzero(&g_hlr->mslookup.server.mdns.bind_addr)) {
				vty_out(vty, " %s %u",
					g_hlr->mslookup.server.mdns.bind_addr.ip,
					g_hlr->mslookup.server.mdns.bind_addr.port);
			}
			vty_out(vty, "%s", VTY_NEWLINE);
		}
		if (strcmp(g_hlr->mslookup.server.mdns.domain_suffix, OSMO_MDNS_DOMAIN_SUFFIX_DEFAULT))
			vty_out(vty, "  mdns domain-suffix %s%s",
				g_hlr->mslookup.server.mdns.domain_suffix,
				VTY_NEWLINE);

		msc = mslookup_server_msc_get(&mslookup_server_msc_wildcard, false);
		if (msc)
			config_write_msc_services(vty, "  ", msc);

		llist_for_each_entry(msc, &g_hlr->mslookup.server.local_site_services, entry) {
			if (!osmo_ipa_name_cmp(&mslookup_server_msc_wildcard, &msc->name))
				continue;
			vty_out(vty, "  msc ipa-name %s%s", osmo_ipa_name_to_str(&msc->name), VTY_NEWLINE);
			config_write_msc_services(vty, "   ", msc);
		}
		if (g_hlr->mslookup.server.local_attach_max_age != OSMO_DGSM_DEFAULT_LOCAL_ATTACH_MAX_AGE)
			vty_out(vty, "  max-age %u%s",
				g_hlr->mslookup.server.local_attach_max_age, VTY_NEWLINE);

		/* If the server is disabled, still output the above to not lose the service config. */
		if (!g_hlr->mslookup.server.enable)
			vty_out(vty, " no server%s", VTY_NEWLINE);
	}

	if (g_hlr->mslookup.client.enable) {
		vty_out(vty, " client%s", VTY_NEWLINE);

		if (osmo_sockaddr_str_is_nonzero(&g_hlr->mslookup.client.gsup_gateway_proxy))
			vty_out(vty, "  gateway-proxy %s %u%s",
				g_hlr->mslookup.client.gsup_gateway_proxy.ip,
				g_hlr->mslookup.client.gsup_gateway_proxy.port,
				VTY_NEWLINE);

		if (g_hlr->mslookup.client.mdns.enable
		    && osmo_sockaddr_str_is_nonzero(&g_hlr->mslookup.client.mdns.query_addr))
			vty_out(vty, "  mdns bind %s %u%s",
				g_hlr->mslookup.client.mdns.query_addr.ip,
				g_hlr->mslookup.client.mdns.query_addr.port,
				VTY_NEWLINE);
		if (strcmp(g_hlr->mslookup.client.mdns.domain_suffix, OSMO_MDNS_DOMAIN_SUFFIX_DEFAULT))
			vty_out(vty, "  mdns domain-suffix %s%s",
				g_hlr->mslookup.client.mdns.domain_suffix,
				VTY_NEWLINE);
		if (g_hlr->mslookup.client.result_timeout_milliseconds != OSMO_DGSM_DEFAULT_RESULT_TIMEOUT_MS)
			vty_out(vty, "  timeout %u%s",
				g_hlr->mslookup.client.result_timeout_milliseconds,
				VTY_NEWLINE);
		if (g_hlr->mslookup.client.subscr_create_on_demand_fallback)
			vty_out(vty, "  create-on-demand-fallback%s", VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_client_gateway_proxy,
      cfg_mslookup_client_gateway_proxy_cmd,
      "gateway-proxy IP [<1-65535>]",
      "Configure a fixed IP address to send all GSUP requests for unknown IMSIs to, without invoking a lookup for IMSI\n"
      "IP address of the remote HLR\n" "GSUP port number (omit for default " OSMO_STRINGIFY_VAL(OSMO_GSUP_PORT) ")\n")
{
	const char *ip_str = argv[0];
	const char *port_str = argc > 1 ? argv[1] : NULL;
	struct osmo_sockaddr_str addr;

	if (osmo_sockaddr_str_from_str(&addr, ip_str, port_str ? atoi(port_str) : OSMO_GSUP_PORT)
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% mslookup client: Invalid address for gateway-proxy: %s %s%s",
			ip_str, port_str ? : "", VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hlr->mslookup.client.gsup_gateway_proxy = addr;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_client_no_gateway_proxy,
      cfg_mslookup_client_no_gateway_proxy_cmd,
      "no gateway-proxy",
      NO_STR "Disable gateway proxy for GSUP with unknown IMSIs\n")
{
	g_hlr->mslookup.client.gsup_gateway_proxy = (struct osmo_sockaddr_str){};
	return CMD_SUCCESS;
}

DEFUN(do_mslookup_show_services,
      do_mslookup_show_services_cmd,
      "show mslookup services",
      SHOW_STR "Distributed GSM / mslookup related information\n"
      "List configured service addresses as sent to remote mslookup requests\n")
{
	struct mslookup_server_msc_cfg *msc;
	const struct mslookup_service_host *local_hlr = mslookup_server_get_local_gsup_addr();

	vty_out(vty, "Local GSUP HLR address returned in mslookup responses for local IMSIs:");
	if (osmo_sockaddr_str_is_nonzero(&local_hlr->host_v4))
		vty_out(vty, " " OSMO_SOCKADDR_STR_FMT,
			OSMO_SOCKADDR_STR_FMT_ARGS(&local_hlr->host_v4));
	if (osmo_sockaddr_str_is_nonzero(&local_hlr->host_v6))
		vty_out(vty, " " OSMO_SOCKADDR_STR_FMT,
			OSMO_SOCKADDR_STR_FMT_ARGS(&local_hlr->host_v6));
	vty_out(vty, "%s", VTY_NEWLINE);

	msc = mslookup_server_msc_get(&mslookup_server_msc_wildcard, false);
	if (msc)
		config_write_msc_services(vty, "", msc);

	llist_for_each_entry(msc, &g_hlr->mslookup.server.local_site_services, entry) {
		if (!osmo_ipa_name_cmp(&mslookup_server_msc_wildcard, &msc->name))
			continue;
		vty_out(vty, "msc ipa-name %s%s", osmo_ipa_name_to_str(&msc->name), VTY_NEWLINE);
		config_write_msc_services(vty, " ", msc);
	}
	return CMD_SUCCESS;
}

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

static void write_one_proxy(struct vty *vty, struct proxy_subscr_listentry *e)
{
	struct proxy_subscr p = e->data;
	uint32_t age;

	vty_out(vty, "%-12s  %-16s  %-12s:%-4u     ",
		strlen(p.msisdn) == 0 ? "Unknown" : p.msisdn,
		strlen(p.imsi) == 0 ? "Unknown" : p.imsi,
		p.remote_hlr_addr.ip ? p.remote_hlr_addr.ip : "Unknown",
		p.remote_hlr_addr.port);

	if (!timestamp_age(&e->last_update, &age)) {
		vty_out(vty, "Invalid%s", VTY_NEWLINE);
		return;
	}

#define UNIT_AGO(UNITNAME, UNITVAL) \
		if (age >= (UNITVAL)) { \
			vty_out(vty, "%u%s", age / (UNITVAL), UNITNAME); \
			age = age % (UNITVAL); \
		}
		UNIT_AGO("d", 60*60*24);
		UNIT_AGO("h", 60*60);
		UNIT_AGO("m", 60);
		UNIT_AGO("s", 1);
		vty_out(vty, "%s", VTY_NEWLINE);
#undef UNIT_AGO
}

static void write_one_proxy_request(struct vty *vty, struct osmo_gsup_req *r)
{
	vty_out(vty, "IMSI: %s TYPE: %s%s",
		r->gsup.imsi,
		osmo_gsup_message_type_name(r->gsup.message_type),
		VTY_NEWLINE);
}

DEFUN(do_proxy_del_sub,
      do_proxy_del_sub_cmd,
      "proxy subscriber-delete [IMSI]",
      "Subscriber Proxy \n"
      "Delete by IMSI\n"
      "IMSI of subscriber to delete from the Proxy"
      )
{
	const char *imsi = argv[0];
	if (!osmo_imsi_str_valid(imsi)) {
		vty_out(vty, "%% Not a valid IMSI: %s%s", imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (proxy_subscr_del(g_hlr->gs->proxy, imsi) == 0)
		return CMD_SUCCESS;
	vty_out(vty, "%% Unable to delete a Proxy for: %s%s", imsi, VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(do_proxy_show,
      do_proxy_show_cmd,
      "show proxy",
      SHOW_STR "Proxy Entries\n")
{
	struct proxy_subscr_listentry *e;
	struct proxy_pending_gsup_req *p;
	unsigned int count = 0;

	vty_out(vty, "MSISDN        IMSI              HLR                   AGE%s", VTY_NEWLINE);
	vty_out(vty, "------------  ----------------  --------------------  ------%s", VTY_NEWLINE);
	llist_for_each_entry(e, &g_hlr->gs->proxy->subscr_list, entry) {
		count++;
		write_one_proxy(vty, e);
	}

	vty_out(vty, "%s%s",
		(count == 0) ? "% No proxy subscribers" : "", VTY_NEWLINE);
	if (!llist_count(&g_hlr->gs->proxy->pending_gsup_reqs))
		return CMD_SUCCESS;
	vty_out(vty, "In-flight Proxy Subscribers Requests:%s", VTY_NEWLINE);
	llist_for_each_entry(p, &g_hlr->gs->proxy->pending_gsup_reqs, entry) {
		write_one_proxy_request(vty, p->req);
	}
	return CMD_SUCCESS;
}

void dgsm_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_mslookup_cmd);

	install_node(&mslookup_node, config_write_mslookup);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_auth_imsi_only_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_auth_imsi_only_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_cod_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_cod_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_mdns_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_mdns_domain_suffix_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_mdns_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_server_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_server_cmd);

	install_node(&mslookup_server_node, NULL);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_mdns_bind_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_mdns_domain_suffix_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_no_mdns_bind_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_service_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_no_service_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_no_service_addr_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_max_age_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_cmd);

	install_node(&mslookup_server_msc_node, NULL);
	install_element(MSLOOKUP_SERVER_MSC_NODE, &cfg_mslookup_server_msc_service_cmd);
	install_element(MSLOOKUP_SERVER_MSC_NODE, &cfg_mslookup_server_msc_no_service_cmd);
	install_element(MSLOOKUP_SERVER_MSC_NODE, &cfg_mslookup_server_msc_no_service_addr_cmd);

	install_element(MSLOOKUP_NODE, &cfg_mslookup_client_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_client_cmd);
	install_node(&mslookup_client_node, NULL);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_subscr_cod_fallback_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_no_subscr_cod_fallback_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_timeout_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_mdns_bind_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_mdns_domain_suffix_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_no_mdns_bind_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_gateway_proxy_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_no_gateway_proxy_cmd);

	install_element_ve(&do_mslookup_show_services_cmd);
	install_element_ve(&do_proxy_show_cmd);
	install_element_ve(&do_proxy_del_sub_cmd);
}
