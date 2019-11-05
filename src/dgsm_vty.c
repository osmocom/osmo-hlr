#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include "hlr_vty.h"
#include "dgsm.h"

struct cmd_node mslookup_node = {
	MSLOOKUP_NODE,
	"%s(config-mslookup)# ",
	1,
};

DEFUN(cfg_mslookup,
      cfg_mslookup_cmd,
      "mslookup",
      "Configure Distributed GSM / multicast MS Lookup")
{
	vty->node = MSLOOKUP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_mdns,
      cfg_mslookup_mdns_cmd,
      "mdns",
      "Convenience shortcut: enable both server and client for DNS/mDNS MS Lookup with default config\n")
{
	g_hlr->mslookup.vty.server.enable = true;
	g_hlr->mslookup.vty.server.mdns.enable = true;
	g_hlr->mslookup.vty.client.enable = true;
	g_hlr->mslookup.vty.client.mdns.enable = true;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_mdns,
      cfg_mslookup_no_mdns_cmd,
      "no mdns",
      NO_STR "Disable both server and client for DNS/mDNS MS Lookup\n")
{
	g_hlr->mslookup.vty.server.mdns.enable = false;
	g_hlr->mslookup.vty.client.mdns.enable = false;
	dgsm_config_apply();
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
      "Enable and configure Distributed GSM / multicast MS Lookup server")
{
	vty->node = MSLOOKUP_SERVER_NODE;
	g_hlr->mslookup.vty.server.enable = true;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_server,
      cfg_mslookup_no_server_cmd,
      "no server",
      NO_STR "Disable Distributed GSM / multicast MS Lookup server")
{
	g_hlr->mslookup.vty.server.enable = false;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

#define MDNS_STR "Configure mslookup by multicast DNS\n"
#define MDNS_BIND_STR MDNS_STR "Configure where the mDNS server listens for MS Lookup requests\n"
#define IP46_STR "IPv4 address like 1.2.3.4 or IPv6 address like a:b:c:d::1\n"
#define PORT_STR "Port number\n"

DEFUN(cfg_mslookup_server_mdns_bind,
      cfg_mslookup_server_mdns_bind_cmd,
      "mdns [bind] [IP] [<1-65535>]",
      MDNS_BIND_STR IP46_STR PORT_STR)
{
	const char *ip_str = argc > 1? argv[1] : g_hlr->mslookup.vty.server.mdns.bind_addr.ip;
	const char *port_str = argc > 2? argv[2] : NULL;
	uint16_t port_nr = port_str ? atoi(port_str) : g_hlr->mslookup.vty.server.mdns.bind_addr.port;
	struct osmo_sockaddr_str addr;
	if (osmo_sockaddr_str_from_str(&addr, ip_str, port_nr)
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% MS Lookup server: Invalid mDNS bind address: %s %u%s",
			ip_str, port_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hlr->mslookup.vty.server.mdns.bind_addr = addr;
	g_hlr->mslookup.vty.server.mdns.enable = true;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_server_no_mdns,
      cfg_mslookup_server_no_mdns_cmd,
      "no mdns",
      NO_STR "Disable server for DNS/mDNS MS Lookup (do not answer remote requests)\n")
{
	g_hlr->mslookup.vty.server.mdns.enable = false;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

struct cmd_node mslookup_server_msc_node = {
	MSLOOKUP_SERVER_MSC_NODE,
	"%s(config-mslookup-server-msc)# ",
	1,
};

DEFUN(cfg_mslookup_server_msc,
      cfg_mslookup_server_msc_cmd,
      "msc .UNIT_NAME",
      "Configure services for individual local MSCs\n"
      "IPA Unit Name of the local MSC to configure\n")
{
	struct global_title msc_name;
	struct dgsm_msc_config *msc;
	global_title_set_str(&msc_name, argv_concat(argv, argc, 0));

	msc = dgsm_config_msc_get(&msc_name, true);
	if (!msc) {
		vty_out(vty, "%% Error creating MSC %s%s", global_title_name(&msc_name), VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty->node = MSLOOKUP_SERVER_MSC_NODE;
	vty->index = msc;
	return CMD_SUCCESS;
}

#define SERVICE_NAME_STR \
	"MS Lookup service name, e.g. " OSMO_MSLOOKUP_SERVICE_SIP " or " OSMO_MSLOOKUP_SERVICE_SMPP "\n"

#define SERVICE_AND_NAME_STR \
	"Configure addresses of local services, as sent in replies to remote MS Lookup requests.\n" \
	SERVICE_NAME_STR


DEFUN(cfg_mslookup_server_msc_service,
      cfg_mslookup_server_msc_service_cmd,
      "service NAME at IP <1-65535>",
      SERVICE_AND_NAME_STR "at\n" IP46_STR PORT_STR)
{
	/* If this command is run on the 'server' node, it produces an empty unit name and serves as wildcard for all
	 * MSCs. If on a 'server' / 'msc' node, set services only for that MSC Unit Name. */
	struct dgsm_msc_config *msc = (vty->node == MSLOOKUP_SERVER_MSC_NODE) ? vty->index : NULL;
	const char *service = argv[0];
	const char *ip_str = argv[1];
	const char *port_str = argv[2];
	struct osmo_sockaddr_str addr;

	/* On the mslookup.server node, set services on the wildcard msc, without a particular name. */
	if (vty->node == MSLOOKUP_SERVER_NODE)
		msc = dgsm_config_msc_get(&dgsm_config_msc_wildcard, true);

	if (!msc) {
		vty_out(vty, "%% Error: no MSC object on this node%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (osmo_sockaddr_str_from_str(&addr, ip_str, atoi(port_str))
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% MS Lookup server: Invalid address for service %s: %s %s%s",
			service, ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dgsm_config_msc_service_set(msc, service, &addr)) {
		vty_out(vty, "%% MS Lookup server: Error setting service %s to %s %s%s",
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
	struct dgsm_msc_config *msc = (vty->node == MSLOOKUP_SERVER_MSC_NODE) ? vty->index : NULL;
	const char *service = argv[0];

	if (dgsm_config_msc_service_del(msc, service, NULL)) {
		vty_out(vty, "%% MS Lookup server: Error removing service %s%s",
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
	struct dgsm_msc_config *msc = (vty->node == MSLOOKUP_SERVER_MSC_NODE) ? vty->index : NULL;
	const char *service = argv[0];
	const char *ip_str = argv[1];
	const char *port_str = argv[2];
	struct osmo_sockaddr_str addr;

	if (osmo_sockaddr_str_from_str(&addr, ip_str, atoi(port_str))
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% MS Lookup server: Invalid address for 'no service' %s: %s %s%s",
			service, ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dgsm_config_service_del(&msc->name, service, &addr)) {
		vty_out(vty, "%% MS Lookup server: Error removing service %s to %s %s%s",
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
      "Enable and configure Distributed GSM / multicast MS Lookup client")
{
	vty->node = MSLOOKUP_CLIENT_NODE;
	g_hlr->mslookup.vty.client.enable = true;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_client,
      cfg_mslookup_no_client_cmd,
      "no client",
      NO_STR "Disable Distributed GSM / multicast MS Lookup client")
{
	g_hlr->mslookup.vty.client.enable = false;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

#define MDNS_TO_STR MDNS_STR "Configure to which multicast address mDNS MS Lookup requests are sent\n"

DEFUN(cfg_mslookup_client_timeout,
      cfg_mslookup_client_timeout_cmd,
      "timeout <1-100000>",
      "How long should the mslookup client wait for remote responses before evaluating received results\n"
      "timeout in milliseconds\n")
{
	uint32_t val = atol(argv[0]);
	g_hlr->mslookup.vty.client.timeout.tv_sec = val / 1000;
	g_hlr->mslookup.vty.client.timeout.tv_usec = (val % 1000) * 1000;
	return CMD_SUCCESS;
}

#define EXIT_HINT() \
	if (vty->type != VTY_FILE) \
		vty_out(vty, "%% 'exit' this node to apply changes%s", VTY_NEWLINE)

DEFUN(cfg_mslookup_client_mdns,
      cfg_mslookup_client_mdns_cmd,
      "mdns [to] [IP] [<1-65535>]",
      MDNS_STR "Configure multicast address to send mDNS mslookup requests to\n" IP46_STR PORT_STR)
{
	const char *ip_str = argc > 1? argv[1] : g_hlr->mslookup.vty.client.mdns.query_addr.ip;
	const char *port_str = argc > 2? argv[2] : NULL;
	uint16_t port_nr = port_str ? atoi(port_str) : g_hlr->mslookup.vty.client.mdns.query_addr.port;
	struct osmo_sockaddr_str addr;
	if (osmo_sockaddr_str_from_str(&addr, ip_str, port_nr)
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% MS Lookup client: Invalid mDNS target address: %s %u%s",
			ip_str, port_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_hlr->mslookup.vty.client.mdns.query_addr = addr;
	g_hlr->mslookup.vty.client.mdns.enable = true;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_client_no_mdns,
      cfg_mslookup_client_no_mdns_cmd,
      "no mdns",
      NO_STR "Disable mDNS client, do not query remote services by mDNS\n")
{
	g_hlr->mslookup.vty.client.mdns.enable = false;
	dgsm_config_apply();
	return CMD_SUCCESS;
}

int config_write_mslookup(struct vty *vty)
{
	return CMD_SUCCESS;
}

int config_write_mslookup_server(struct vty *vty)
{
	return CMD_SUCCESS;
}

int config_write_mslookup_server_msc(struct vty *vty)
{
	return CMD_SUCCESS;
}

int config_write_mslookup_client(struct vty *vty)
{
	return CMD_SUCCESS;
}

void dgsm_vty_init()
{
	install_element(CONFIG_NODE, &cfg_mslookup_cmd);

	install_node(&mslookup_node, config_write_mslookup);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_mdns_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_mdns_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_server_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_server_cmd);

	install_node(&mslookup_server_node, config_write_mslookup_server);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_mdns_bind_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_no_mdns_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_service_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_no_service_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_no_service_addr_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_msc_cmd);

	install_node(&mslookup_server_msc_node, config_write_mslookup_server_msc);
	install_element(MSLOOKUP_SERVER_MSC_NODE, &cfg_mslookup_server_msc_service_cmd);
	install_element(MSLOOKUP_SERVER_MSC_NODE, &cfg_mslookup_server_msc_no_service_cmd);
	install_element(MSLOOKUP_SERVER_MSC_NODE, &cfg_mslookup_server_msc_no_service_addr_cmd);

	install_element(MSLOOKUP_NODE, &cfg_mslookup_client_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_client_cmd);
	install_node(&mslookup_client_node, config_write_mslookup_client);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_timeout_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_mdns_cmd);
	install_element(MSLOOKUP_CLIENT_NODE, &cfg_mslookup_client_no_mdns_cmd);

}

void dgsm_vty_go_parent_action(struct vty *vty)
{
}
