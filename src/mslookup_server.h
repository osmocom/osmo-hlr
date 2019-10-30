#pragma once

struct osmo_mslookup_server_dns {
	bool running;
	struct osmo_sockaddr_str multicast_bind_addr;
};

struct osmo_mslookup_server_dns *osmo_mslookup_server_dns_start(const struct osmo_sockaddr_str *multicast_bind_addr);
void osmo_mslookup_server_dns_stop(struct osmo_mslookup_server_dns *server);
