#pragma once

struct osmo_mslookup_query;
struct osmo_mslookup_result;

void osmo_mslookup_server_rx(const struct osmo_mslookup_query *query,
			     struct osmo_mslookup_result *result);
