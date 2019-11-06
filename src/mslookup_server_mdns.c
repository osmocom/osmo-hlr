#include <stdlib.h>
#include <unistd.h>

#include <osmocom/mslookup/mslookup.h>
#include <osmocom/mslookup/mdns.h>
#include "logging.h"
#include "mslookup_server.h"
#include "mslookup_server_mdns.h"

static void osmo_mslookup_server_mdns_tx(struct osmo_mslookup_server_mdns *server,
					 const struct osmo_mdns_request *req,
					 const struct osmo_mslookup_query *query,
					 const struct osmo_mslookup_result *result)
{
	const char *errmsg = NULL;
	struct msgb *msg;
	struct osmo_mdns_answer ans;
	struct osmo_mdns_record *rec_age;
	struct osmo_mdns_record rec_ip_v4 = {};
	struct osmo_mdns_record *rec_ip_v4_port;
	struct osmo_mdns_record rec_ip_v6 = {};
	struct osmo_mdns_record *rec_ip_v6_port;
	uint32_t ip_v4;
	struct in6_addr ip_v6;

	void *ctx = talloc_named_const(server, 0, __func__);

	LOGP(DDGSM, LOGL_DEBUG, "%s: sending mDNS response\n",
	     osmo_mslookup_result_name_c(OTC_SELECT, query, result));

	osmo_mdns_answer_init(&ans);
	ans.id = req->id;
	ans.domain = req->domain;

	rec_age = osmo_mdns_encode_txt_record(ctx, "age", "%u", result->age);
	llist_add_tail(&rec_age->list, &ans.records);

	if (osmo_sockaddr_str_is_nonzero(&result->host_v4)) {
		if (osmo_sockaddr_str_to_32(&result->host_v4, &ip_v4)) {
			errmsg = "Error encoding IPv4 address";
			goto clean_and_exit;
		}
		rec_ip_v4.type = OSMO_MSLOOKUP_MDNS_RECORD_TYPE_A;
		rec_ip_v4.data = (void*)&ip_v4;
		rec_ip_v4.length = sizeof(ip_v4);
		llist_add_tail(&rec_ip_v4.list, &ans.records);

		rec_ip_v4_port = osmo_mdns_encode_txt_record(ctx, "port", "%u", result->host_v4.port);
		if (!rec_ip_v4_port) {
			errmsg = "Error encoding IPv4 port";
			goto clean_and_exit;
		}
		llist_add_tail(&rec_ip_v4_port->list, &ans.records);
	}

	if (osmo_sockaddr_str_is_nonzero(&result->host_v6)) {
		if (osmo_sockaddr_str_to_in6_addr(&result->host_v6, &ip_v6)) {
			errmsg = "Error encoding IPv6 address";
			goto clean_and_exit;
		}

		rec_ip_v6.type = OSMO_MSLOOKUP_MDNS_RECORD_TYPE_AAAA;
		rec_ip_v6.data = (void*)&ip_v6;
		rec_ip_v6.length = sizeof(ip_v6);
		llist_add_tail(&rec_ip_v6.list, &ans.records);

		rec_ip_v6_port = osmo_mdns_encode_txt_record(ctx, "port", "%u", result->host_v6.port);
		if (!rec_ip_v6_port) {
			errmsg = "Error encoding IPv6 port";
			goto clean_and_exit;
		}
		llist_add_tail(&rec_ip_v6_port->list, &ans.records);
	}

	msg = msgb_alloc(1024, __func__);
	if (dns_encode_answer(ctx, msg, &ans)) {
		errmsg = "Error encoding DNS answer packet";
		goto clean_and_exit;
	}

	if (osmo_mdns_sock_send(server->sock, msg))
		errmsg = "Error sending DNS answer";

clean_and_exit:
	if (errmsg)
		LOGP(DDGSM, LOGL_ERROR, "%s: DNS: %s\n", osmo_mslookup_result_name_c(ctx, query, result), errmsg);
	talloc_free(ctx);
}

static void osmo_mslookup_server_mdns_handle_request(struct osmo_mslookup_server_mdns *server,
						     const struct osmo_mdns_request *req)
{
	struct osmo_mslookup_query query;
	struct osmo_mslookup_result result;

	if (osmo_mslookup_query_from_domain_str(&query, req->domain)) {
		LOGP(DDGSM, LOGL_ERROR, "mDNS mslookup server: unable to parse request domain string: %s\n",
		     osmo_quote_str_c(OTC_SELECT, req->domain, -1));
		return;
	}

	osmo_mslookup_server_rx(&query, &result);
	/* Error logging already happens in osmo_mslookup_server_rx() */
	if (result.rc != OSMO_MSLOOKUP_RC_OK)
		return;

	osmo_mslookup_server_mdns_tx(server, req, &query, &result);
}

static int osmo_mslookup_server_mdns_rx(struct osmo_fd *osmo_fd, unsigned int what)
{
	struct osmo_mslookup_server_mdns *server = osmo_fd->data;
	struct osmo_mdns_request *req;
	int n;
	uint8_t buffer[1024];
	void *ctx;

	/* Parse the message and print it */
	n = read(osmo_fd->fd, buffer, sizeof(buffer));
	if (n < 0)
		return n;

	ctx = talloc_named_const(server, 0, __func__);
	req = dns_decode_request(ctx, buffer, n);
	if (!req) {
		LOGP(DDGSM, LOGL_DEBUG, "mDNS rx: ignoring: not a request\n");
		talloc_free(ctx);
		return -1;
	}

	LOGP(DDGSM, LOGL_DEBUG, "mDNS rx request: %s\n", osmo_quote_str_c(OTC_SELECT, req->domain, -1));
	osmo_mslookup_server_mdns_handle_request(server, req);
	talloc_free(ctx);
	return n;
}

struct osmo_mslookup_server_mdns *osmo_mslookup_server_mdns_start(void *ctx, const struct osmo_sockaddr_str *bind_addr)
{
	struct osmo_mslookup_server_mdns *server = talloc_zero(ctx, struct osmo_mslookup_server_mdns);
	OSMO_ASSERT(server);
	*server = (struct osmo_mslookup_server_mdns){
		.bind_addr = *bind_addr,
	};

	server->sock = osmo_mdns_sock_init(server,
					   bind_addr->ip, bind_addr->port, true,
					   osmo_mslookup_server_mdns_rx,
					   server, 0);
	if (!server->sock) {
		LOGP(DDGSM, LOGL_ERROR,
		     "mslookup mDNS server: error initializing multicast bind on " OSMO_SOCKADDR_STR_FMT "\n",
		     OSMO_SOCKADDR_STR_FMT_ARGS(bind_addr));
		talloc_free(server);
		return NULL;
	}

	return server;
}

void osmo_mslookup_server_mdns_stop(struct osmo_mslookup_server_mdns *server)
{
	if (!server)
		return;
	osmo_mdns_sock_cleanup(server->sock);
	talloc_free(server);
}
