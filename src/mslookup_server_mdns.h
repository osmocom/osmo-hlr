#pragma once

#include <stdbool.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mslookup/mdns_sock.h>

struct osmo_mslookup_server_mdns {
	struct osmo_mslookup_server *mslookup;
	struct osmo_sockaddr_str bind_addr;
	struct osmo_mdns_sock *sock;
};

struct osmo_mslookup_server_mdns *osmo_mslookup_server_mdns_start(void *ctx, const struct osmo_sockaddr_str *bind_addr);
void osmo_mslookup_server_mdns_stop(struct osmo_mslookup_server_mdns *server);
