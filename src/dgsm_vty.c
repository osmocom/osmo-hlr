#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include "hlr_vty.h"
#include "dgsm.h"

static struct dgsm_config dgsm_config_vty = {};

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
	printf("%s vty->node = %d\n", __func__, vty->node);
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_dns,
      cfg_mslookup_dns_cmd,
      "dns",
      "Convenience shortcut: enable both server and client for DNS/mDNS MS Lookup with default config\n")
{
	dgsm_config_vty.server.enable = true;
	dgsm_config_vty.server.dns.enable = true;
	dgsm_config_vty.client.enable = true;
	dgsm_config_vty.client.dns.enable = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_dns,
      cfg_mslookup_no_dns_cmd,
      "no dns",
      NO_STR "Disable both server and client for DNS/mDNS MS Lookup\n")
{
	dgsm_config_vty.server.dns.enable = false;
	dgsm_config_vty.client.dns.enable = false;
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
	dgsm_config_vty.server.enable = true;
	printf("%s vty->node = %d\n", __func__, vty->node);
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_server,
      cfg_mslookup_no_server_cmd,
      "no server",
      NO_STR "Disable Distributed GSM / multicast MS Lookup server")
{
	dgsm_config_vty.server.enable = false;
	return CMD_SUCCESS;
}

#define DNS_STR "Configure DNS/mDNS MS Lookup\n"
#define DNS_BIND_STR DNS_STR "Configure where the DNS/mDNS server listens for MS Lookup requests\n"
#define IP46_STR "IPv4 address like 1.2.3.4 or IPv6 address like a:b:c:d::1\n"
#define PORT_STR "Port number\n"

DEFUN(cfg_mslookup_server_dns_bind_multicast,
      cfg_mslookup_server_dns_bind_multicast_cmd,
      "dns bind multicast IP <1-65535>",
      DNS_BIND_STR "Configure mDNS multicast listen address\n" IP46_STR PORT_STR)
{
	const char *ip_str = argv[1];
	const char *port_str = argv[2];
	struct osmo_sockaddr_str addr;
	if (osmo_sockaddr_str_from_str(&addr, ip_str, atoi(port_str))
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% MS Lookup server: Invalid mDNS bind address: %s %s%s",
			ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}

	dgsm_config_vty.server.dns.multicast_bind_addr = addr;
	dgsm_config_vty.server.dns.enable = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_server_no_dns,
      cfg_mslookup_server_no_dns_cmd,
      "no dns",
      NO_STR "Disable server for DNS/mDNS MS Lookup (do not answer remote requests)\n")
{
	dgsm_config_vty.server.dns.enable = false;
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
	const char *unit_name = argv_concat(argv, argc, 0);
	struct dgsm_msc_config *msc = dgsm_config_msc_get((uint8_t*)unit_name, strlen(unit_name),
							  true);
	if (!msc) {
		vty_out(vty, "%% Error creating MSC %s%s",
			osmo_quote_str(unit_name, -1), VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty->node = MSLOOKUP_SERVER_MSC_NODE;
	vty->index = msc;
	printf("%s vty->node = %d\n", __func__, vty->node);
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
	uint8_t *unit_name = msc ? msc->unit_name : NULL;
	size_t unit_name_len = msc ? msc->unit_name_len : 0;
	const char *service = argv[0];
	const char *ip_str = argv[1];
	const char *port_str = argv[2];
	struct osmo_sockaddr_str addr;

	if (osmo_sockaddr_str_from_str(&addr, ip_str, atoi(port_str))
	    || !osmo_sockaddr_str_is_nonzero(&addr)) {
		vty_out(vty, "%% MS Lookup server: Invalid address for service %s: %s %s%s",
			service, ip_str, port_str, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dgsm_config_service_set(unit_name, unit_name_len, service, &addr)) {
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
	uint8_t *unit_name = msc ? msc->unit_name : NULL;
	size_t unit_name_len = msc ? msc->unit_name_len : 0;
	const char *service = argv[0];

	if (dgsm_config_service_del(unit_name, unit_name_len, service, NULL)) {
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
	uint8_t *unit_name = msc ? msc->unit_name : NULL;
	size_t unit_name_len = msc ? msc->unit_name_len : 0;
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

	if (dgsm_config_service_del(unit_name, unit_name_len, service, &addr)) {
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
	dgsm_config.client.enable = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_mslookup_no_client,
      cfg_mslookup_no_client_cmd,
      "no client",
      NO_STR "Disable Distributed GSM / multicast MS Lookup client")
{
	dgsm_config.client.enable = false;
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
	install_element(MSLOOKUP_NODE, &cfg_mslookup_dns_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_dns_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_server_cmd);
	install_element(MSLOOKUP_NODE, &cfg_mslookup_no_server_cmd);

	install_node(&mslookup_server_node, config_write_mslookup_server);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_dns_bind_multicast_cmd);
	install_element(MSLOOKUP_SERVER_NODE, &cfg_mslookup_server_no_dns_cmd);
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

}

void dgsm_vty_go_parent_action(struct vty *vty)
{
	/* Exiting 'mslookup' VTY node, apply new config. */
	switch (vty->node) {
	case MSLOOKUP_SERVER_NODE:
		dgsm_dns_server_config_apply();
		break;
	case MSLOOKUP_CLIENT_NODE:
		dgsm_dns_client_config_apply();
		break;
	}
}
