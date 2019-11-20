/*! \file osmo-mslookup-client.c
 * Distributed GSM: find the location of subscribers, for example by multicast DNS,
 * to obtain HLR, SIP or SMPP server addresses (or arbitrary service names).
 */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2019 by Neels Hofmeyr <neels@hofmeyr.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <talloc.h>
#include <sys/un.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>
#include <osmocom/mslookup/mdns_sock.h>
#include <osmocom/mslookup/mdns.h>

#define CSV_HEADERS "query\tresult\tlast\tage\tv4_ip\tv4_port\tv6_ip\tv6_port"

static void print_version(void)
{
	printf("osmo-mslookup-client version %s\n", PACKAGE_VERSION);
	printf("\n"
	"Copyright (C) 2019 by sysmocom - s.f.m.c. GmbH\n"
	"Copyright (C) 2019 by Neels Hofmeyr <neels@hofmeyr.de>\n"
	"This program is free software; you can redistribute it and/or modify\n"
	"it under the terms of the GNU General Public License as published by\n"
	"the Free Software Foundation; either version 2 of the License, or\n"
	"(at your option) any later version.\n"
	"\n");
}

static void print_help()
{
	print_version();
	printf(
"Standalone mslookup client for Distributed GSM\n"
"\n"
"Receiving mslookup results means listening for responses on a socket. Often,\n"
"integration (e.g. FreeSwitch dialplan.py) makes it hard to select() on a socket\n"
"to read responses, because that interferes with the main program (e.g.\n"
"FreeSwitch's dialplan.py seems to be integrated with an own select() main loop\n"
"that interferes with osmo_select_main(), or an smpp.py uses\n"
"smpplib.client.listen() as main loop, etc.).\n"
"\n"
"This program provides a trivial solution, by outsourcing the mslookup main loop\n"
"to a separate process. Communication is done via cmdline arg and stdout pipe or\n"
"a (blocking) unix domain socket, results are returned in CSV or JSON format.\n"
"\n"
"This can be done one-shot, i.e. exit as soon as the response has been\n"
"determined, or in daemon form, i.e. continuously listen for requests and return\n"
"responses.\n"
"\n"
"About running a local daemon: it is unintuitive to connect to a socket to solve\n"
"a problem of reading from a socket -- it seems like just more of the same\n"
"problem. The reasons why the daemon is in fact useful are:\n"
"- The osmo-mslookup-client daemon will return only those results matching\n"
"  requests issued on that socket connection.\n"
"- A program can simply blockingly recv() from the osmo-mslookup-client socket\n"
"  instead of needing to run osmo_select_main() so that libosmo-mslookup is able\n"
"  to asynchronously receive responses from remote servers.\n"
"- Only one long-lived multicast socket needs to be opened instead of a new\n"
"  socket for each request.\n"
"\n"
"Output is in CSV or json, see --format. The default is tab-separated CSV\n"
"with these columns:\n"
CSV_HEADERS "\n"
"\n"
"One-shot operation example:\n"
"$ osmo-mslookup-client 1000-@sip.voice.12345.msisdn -f json\n"
"{\"query\": \"sip.voice.12345.msisdn\", \"result\": \"result\", \"last\": true, \"age\": 5, \"v4\": [\"1.2.3.7\", \"23\"]}\n"
"$\n"
"\n"
"Daemon operation example:\n"
"$ osmo-mslookup-client -s /tmp/mslookup -d\n"
"(and a client program then connects to /tmp/mslookup, find an implementation\n"
"example below)\n"
"\n"
"Integrating with calling programs can be done by:\n"
"- call osmo-mslookup-client with the query string as argument.\n"
"  It will open a multicast DNS socket, send out a query and wait for the\n"
"  matching response. It will print the result on stdout and exit.\n"
"  This method launches a new process for every mslookup query,\n"
"  and creates a short-lived multicast listener for each invocation.\n"
"  This is fine for low activity, but does not scale well.\n"
"\n"
"- invoke osmo-mslookup-client --socket /tmp/mslookup -d.\n"
"  Individual queries can be sent by connecting to that unix domain socket,\n"
"  blockingly reading the response when it arrives and disconnecting.\n"
"  This way only one process keeps one multicast listener open.\n"
"  Callers can connect to this socket without spawning processes.\n"
"  This is recommended for scale.\n"
"\n"
"Python example clients for {CSV,JSON}x{cmdline,socket} can be found here:\n"
"http://git.osmocom.org/osmo-hlr/tree/contrib/dgsm/osmo-mslookup-pipe.py\n"
"http://git.osmocom.org/osmo-hlr/tree/contrib/dgsm/osmo-mslookup-socket.py\n"
"\n"
"\n"
"Options:\n"
"\n"
"[[delay-][timeout]@]service.number.id\n"
"	A service query string with optional individual timeout.\n"
"	The same format is also used on a daemon socket, if any.\n"
"	The timeout consists of the min-delay and the timeout numbers,\n"
"	corresponding to the --min-delay and --timeout options, in milliseconds.\n"
"	These options apply if a query string lacks own numbers.\n"
"	Examples:\n"
"		gsup.hlr.1234567.imsi		Use cmdline timeout settings\n"
"		5000@gsup.hlr.1234567.imsi	Return N results for 5 seconds\n"
"		1000-5000@sip.voice.123.msisdn	Same, but silent for first second\n"
"		10000-@smpp.sms.567.msisdn	Return 1 result after 10 seconds\n"
"\n"
"--format -f csv (default)\n"
"	Format result lines in CSV format.\n"
"--no-csv-headers -H\n"
"	If the format is 'csv', by default, the first output line prints the\n"
"	CSV headers used for CSV output format. This option disables these CSV\n"
"	headers.\n"
"\n"
"--format -f json\n"
"	Format result lines in json instead of semicolon separated, like:\n"
"	{\"query\": \"sip.voice.12345.msisdn\", \"result\": \"ok\", \"v4\": [\"10.9.8.7\", \"5060\"]}\n"
"\n"
"--daemon -d\n"
"	Keep running after a request has been serviced\n"
"\n"
"--mdns-ip -m " OSMO_MSLOOKUP_MDNS_IP4 " -m " OSMO_MSLOOKUP_MDNS_IP6 "\n"
"--mdns-port -M " OSMO_STRINGIFY_VAL(OSMO_MSLOOKUP_MDNS_PORT) "\n"
"	Set multicast IP address / port to send mDNS requests and listen for\n"
"	mDNS reponses\n"
"\n"
"--min-delay -t 1000 (in milliseconds)\n"
"	Set minimum delay to wait before returning any results.\n"
"	When this timeout has elapsed, the best current result is returned,\n"
"	if any is available.\n"
"	Responses arriving after the min-delay has elapsed which have a younger\n"
"	age than previous results are returned immediately.\n"
"	Note: When a response with age of zero comes in, the result is returned\n"
"	immediately and the request is discarded: non-daemon mode exits, daemon\n"
"	mode ignores later results.\n"
"\n"
"--timeout -T 1000 (in milliseconds)\n"
"	Set timeout after which to stop listening for responses.\n"
"	If this is smaller than -t, the value from -t will be used for -T as well.\n"
"	Note: When a response with age of zero comes in, the result is returned\n"
"	immediately and the request is discarded: non-daemon mode exits, daemon\n"
"	mode ignores later results.\n"
"\n"
"--socket -s /path/to/unix-domain-socket\n"
"	Listen to requests from and write responses to a UNIX domain socket.\n"
"\n"
"--send -S <query> <age> <ip1> <port1> <ip2> <port2>\n"
"	Do not query, but send an mslookup result. This is useful only for\n"
"	testing. Examples:\n"
"	--send foo.123.msisdn 300 23.42.17.11 1234\n"
"	--send foo.123.msisdn 300 2323:4242:1717:1111::42 1234\n"
"	--send foo.123.msisdn 300 23.42.17.11 1234 2323:4242:1717:1111::42 1234\n"
"\n"
"--quiet -q\n"
"	Do not print errors to stderr, do not log to stderr.\n"
"\n"
"--help -h\n"
"	This help\n"
);
}

enum result_format {
	FORMAT_CSV = 0,
	FORMAT_JSON,
};

static struct {
	bool daemon;
	struct osmo_sockaddr_str mdns_addr;
	uint32_t min_delay;
	uint32_t timeout;
	const char *socket_path;
	const char *format_str;
	bool csv_headers;
	bool send;
	bool quiet;
} cmdline_opts = {
	.mdns_addr = { .af=AF_INET, .ip=OSMO_MSLOOKUP_MDNS_IP4, .port=OSMO_MSLOOKUP_MDNS_PORT },
	.min_delay = 1000,
	.timeout = 1000,
	.csv_headers = true,
};

#define print_error(fmt, args...) do { \
		if (!cmdline_opts.quiet) \
			fprintf(stderr, fmt, ##args); \
	} while (0)

char g_buf[1024];

long long int parse_int(long long int minval, long long int maxval, const char *arg, int *rc)
{
	long long int val;
	char *endptr;
	if (rc)
		*rc = -1;
	if (!arg)
		return -1;
	errno = 0;
	val = strtoll(arg, &endptr, 10);
	if (errno || val < minval || val > maxval || *endptr)
		return -1;
	if (rc)
		*rc = 0;
	return val;
}

int cb_doing_nothing(struct osmo_fd *fd, unsigned int what)
{
	return 0;
}

/* --send: Just send a response, for manual testing. */
int do_send(int argc, char ** argv)
{
	/* parse args <query> <age> <v4-ip> <v4-port> <v6-ip> <v6-port> */
#define ARG(NR) ((argc > NR)? argv[NR] : NULL)
	const char *query_str = ARG(0);
	const char *age_str = ARG(1);
	const char *ip_strs[2][2] = {
		{ ARG(2), ARG(3) },
		{ ARG(4), ARG(5) },
	};
	struct osmo_mslookup_query q = {};
	struct osmo_mslookup_result r = { .rc = OSMO_MSLOOKUP_RC_RESULT };
	int i;
	int rc;
	void *ctx = talloc_named_const(NULL, 0, __func__);
	struct osmo_mdns_sock *sock;

	if (!query_str) {
		print_error("--send needs a query string like foo.123456.imsi\n");
		return 1;
	}
	if (osmo_mslookup_query_init_from_domain_str(&q, query_str)) {
		print_error("Invalid query string '%s', need a query string like foo.123456.imsi\n",
			    query_str);
		return 1;
	}

	if (!age_str) {
		print_error("--send needs an age\n");
		return 1;
	}
	r.age = parse_int(0, UINT32_MAX, age_str, &rc);
	if (rc) {
		print_error("invalid age\n");
		return 1;
	}

	for (i = 0; i < 2; i++) {
		struct osmo_sockaddr_str addr;
		uint16_t port;
		if (!ip_strs[i][0])
			continue;
		port = parse_int(1, 65535, ip_strs[i][1] ? : "2342", &rc);
		if (rc) {
			print_error("invalid port: %s\n", ip_strs[i][1] ? : "NULL");
			return 1;
		}
		if (osmo_sockaddr_str_from_str(&addr, ip_strs[i][0], port)) {
			print_error("invalid IP addr: %s\n", ip_strs[i][0]);
			return 1;
		}
		if (addr.af == AF_INET)
			r.host_v4 = addr;
		else
			r.host_v6 = addr;
	}

	printf("Sending mDNS to " OSMO_SOCKADDR_STR_FMT ": %s\n", OSMO_SOCKADDR_STR_FMT_ARGS(&cmdline_opts.mdns_addr),
	       osmo_mslookup_result_name_c(ctx, &q, &r));

	rc = 1;
	sock = osmo_mdns_sock_init(ctx, cmdline_opts.mdns_addr.ip, cmdline_opts.mdns_addr.port,
				   cb_doing_nothing, NULL, 0);
	if (!sock) {
		print_error("unable to open mDNS socket\n");
		goto exit_cleanup;
	}

	struct msgb *msg = osmo_mdns_result_encode(ctx, 0, &q, &r);
	if (!msg) {
		print_error("unable to encode mDNS response\n");
		goto exit_cleanup;
	}

	if (osmo_mdns_sock_send(sock, msg)) {
		print_error("unable to send mDNS message\n");
		goto exit_cleanup;
	}

	rc = 0;
exit_cleanup:
	osmo_mdns_sock_cleanup(sock);
	talloc_free(ctx);
	return rc;
}

static struct {
	void *ctx;
	unsigned int requests_handled;
	struct osmo_fd socket_ofd;
	struct osmo_mslookup_client *mslookup_client;
	struct llist_head queries;
	struct llist_head socket_clients;
	enum result_format format;
} globals = {
	.queries = LLIST_HEAD_INIT(globals.queries),
	.socket_clients = LLIST_HEAD_INIT(globals.socket_clients),
};

typedef void (*formatter_t)(char *buf, size_t buflen, const char *query_str, const struct osmo_mslookup_result *r);

void formatter_csv(char *buf, size_t buflen, const char *query_str, const struct osmo_mslookup_result *r)
{
	struct osmo_strbuf sb = { .buf=buf, .len=buflen };
	OSMO_STRBUF_PRINTF(sb, "%s", query_str);

	if (!r)
		OSMO_STRBUF_PRINTF(sb, "\tERROR\t\t\t\t\t\t");
	else {
		OSMO_STRBUF_PRINTF(sb, "\t%s", osmo_mslookup_result_code_name(r->rc));
		OSMO_STRBUF_PRINTF(sb, "\t%s", r->last ? "last" : "not-last");
		OSMO_STRBUF_PRINTF(sb, "\t%u", r->age);
		switch (r->rc) {
		case OSMO_MSLOOKUP_RC_RESULT:
			if (osmo_sockaddr_str_is_nonzero(&r->host_v4))
				OSMO_STRBUF_PRINTF(sb, "\t%s\t%u", r->host_v4.ip, r->host_v4.port);
			else
				OSMO_STRBUF_PRINTF(sb, "\t\t");
			if (osmo_sockaddr_str_is_nonzero(&r->host_v6))
				OSMO_STRBUF_PRINTF(sb, "\t%s\t%u", r->host_v6.ip, r->host_v6.port);
			else
				OSMO_STRBUF_PRINTF(sb, "\t\t");
			break;
		default:
			OSMO_STRBUF_PRINTF(sb, "\t\t\t\t\t");
			break;
		}
	}
}

void formatter_json(char *buf, size_t buflen, const char *query_str, const struct osmo_mslookup_result *r)
{
	struct osmo_strbuf sb = { .buf=buf, .len=buflen };
	OSMO_STRBUF_PRINTF(sb, "{\"query\": \"%s\"", query_str);

	if (!r)
		OSMO_STRBUF_PRINTF(sb, ", \"result\": \"ERROR\"");
	else {
		OSMO_STRBUF_PRINTF(sb, ", \"result\": \"%s\"", osmo_mslookup_result_code_name(r->rc));
		OSMO_STRBUF_PRINTF(sb, ", \"last\": %s", r->last ? "true" : "false");
		OSMO_STRBUF_PRINTF(sb, ", \"age\": %u", r->age);
		if (r->rc == OSMO_MSLOOKUP_RC_RESULT) {
			if (osmo_sockaddr_str_is_nonzero(&r->host_v4))
				OSMO_STRBUF_PRINTF(sb, ", \"v4\": [\"%s\", \"%u\"]", r->host_v4.ip, r->host_v4.port);
			if (osmo_sockaddr_str_is_nonzero(&r->host_v6))
				OSMO_STRBUF_PRINTF(sb, ", \"v6\": [\"%s\", \"%u\"]", r->host_v6.ip, r->host_v6.port);
		}
	}
	OSMO_STRBUF_PRINTF(sb, "}");
}

formatter_t formatters[] = {
	[FORMAT_CSV] = formatter_csv,
	[FORMAT_JSON] = formatter_json,
};

void respond_str_stdout(const char *str) {
	fprintf(stdout, "%s\n", str);
	fflush(stdout);
}

void start_query_str(const char *query_str);
void start_query_strs(char **query_strs, size_t query_strs_len);

struct socket_client {
	struct llist_head entry;
	struct osmo_fd ofd;
	char query_str[1024];
};

static void socket_client_close(struct socket_client *c)
{
	struct osmo_fd *ofd = &c->ofd;

	close(ofd->fd);
	ofd->fd = -1;
	osmo_fd_unregister(ofd);

	llist_del(&c->entry);
	talloc_free(c);
}

void socket_client_respond_result(struct socket_client *c, const char *response)
{
	write(c->ofd.fd, response, strlen(response));
}

static int socket_read_cb(struct osmo_fd *ofd)
{
	struct socket_client *c = ofd->data;
	int rc;
	char rxbuf[1024];
	char *query_with_timeout;
	char *query_str;
	char *at;

	rc = recv(ofd->fd, rxbuf, sizeof(rxbuf), 0);
	if (rc == 0)
		goto close;

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		goto close;
	}

	if (rc >= sizeof(c->query_str))
		goto close;

	rxbuf[rc] = '\0';
	query_with_timeout = strtok(rxbuf, "\r\n");
	at = strchr(query_with_timeout, '@');
	query_str = at ? at + 1 : query_with_timeout;

	if (c->query_str[0]) {
		print_error("ERROR: Only one query per client connect is allowed;"
			    " received '%s' and '%s' on the same connection\n",
			    c->query_str, query_str);
		formatters[globals.format](g_buf, sizeof(g_buf), query_str, NULL);
		socket_client_respond_result(c, g_buf);
		return 0;
	}

	OSMO_STRLCPY_ARRAY(c->query_str, query_str);
	start_query_str(query_with_timeout);
	printf("query: %s\n", query_with_timeout);
	return rc;

close:
	socket_client_close(c);
	return -1;
}

static int socket_cb(struct osmo_fd *ofd, unsigned int flags)
{
	int rc = 0;

	if (flags & BSC_FD_READ)
		rc = socket_read_cb(ofd);
	if (rc < 0)
		return rc;

	return rc;
}

int socket_accept(struct osmo_fd *ofd, unsigned int flags)
{
	struct socket_client *c;
	struct sockaddr_un un_addr;
	socklen_t len;
	int rc;

	len = sizeof(un_addr);
	rc = accept(ofd->fd, (struct sockaddr*)&un_addr, &len);
	if (rc < 0) {
		print_error("Failed to accept a new connection\n");
		return -1;
	}

	c = talloc_zero(globals.ctx, struct socket_client);
	OSMO_ASSERT(c);
	c->ofd.fd = rc;
	c->ofd.when = BSC_FD_READ;
	c->ofd.cb = socket_cb;
	c->ofd.data = c;

	if (osmo_fd_register(&c->ofd) != 0) {
		print_error("Failed to register new connection fd\n");
		close(c->ofd.fd);
		c->ofd.fd = -1;
		talloc_free(c);
		return -1;
	}

	llist_add(&c->entry, &globals.socket_clients);

	if (globals.format == FORMAT_CSV && cmdline_opts.csv_headers)
		write(c->ofd.fd, CSV_HEADERS, strlen(CSV_HEADERS));

	return 0;
}

int socket_init(const char *sock_path)
{
	struct osmo_fd *ofd = &globals.socket_ofd;
	int rc;

	ofd->fd = osmo_sock_unix_init(SOCK_SEQPACKET, 0, sock_path, OSMO_SOCK_F_BIND);
	if (ofd->fd < 0) {
		print_error("Could not create unix socket: %s: %s\n", sock_path, strerror(errno));
		return -1;
	}

	ofd->when = BSC_FD_READ;
	ofd->cb = socket_accept;

	rc = osmo_fd_register(ofd);
	if (rc < 0) {
		print_error("Could not register listen fd: %d\n", rc);
		close(ofd->fd);
		return rc;
	}
	return 0;
}

void socket_close()
{
	struct socket_client *c, *n;
	llist_for_each_entry_safe(c, n, &globals.socket_clients, entry)
		socket_client_close(c);
	if (osmo_fd_is_registered(&globals.socket_ofd)) {
		close(globals.socket_ofd.fd);
		globals.socket_ofd.fd = -1;
		osmo_fd_unregister(&globals.socket_ofd);
	}
}

struct query {
	struct llist_head entry;

	char query_str[128];
	struct osmo_mslookup_query query;
	uint32_t handle;
};

void respond_result(const char *query_str, const struct osmo_mslookup_result *r)
{
	struct socket_client *c, *n;
	formatters[globals.format](g_buf, sizeof(g_buf), query_str, r);
	respond_str_stdout(g_buf);

	llist_for_each_entry_safe(c, n, &globals.socket_clients, entry) {
		if (!strcmp(query_str, c->query_str)) {
			socket_client_respond_result(c, g_buf);
			if (r->last)
				socket_client_close(c);
		}
	}
	if (r->last)
		globals.requests_handled++;
}

void respond_err(const char *query_str)
{
	respond_result(query_str, NULL);
}

struct query *query_by_handle(uint32_t request_handle)
{
	struct query *q;
	llist_for_each_entry(q, &globals.queries, entry) {
		if (request_handle == q->handle)
			return q;
	}
	return NULL;
}

void mslookup_result_cb(struct osmo_mslookup_client *client,
			uint32_t request_handle,
			const struct osmo_mslookup_query *query,
			const struct osmo_mslookup_result *result)
{
	struct query *q = query_by_handle(request_handle);
	if (!q)
		return;
	respond_result(q->query_str, result);
	if (result->last) {
		llist_del(&q->entry);
		talloc_free(q);
	}
}

void start_query_str(const char *query_str)
{
	struct query *q;
	const char *domain_str = query_str;
	char *at;
	struct osmo_mslookup_query_handling h = {
		.min_wait_milliseconds = cmdline_opts.min_delay,
		.result_timeout_milliseconds = cmdline_opts.timeout,
		.result_cb = mslookup_result_cb,
	};

	at = strchr(query_str, '@');
	if (at) {
		int rc;
		char timeouts[16];
		char *dash;
		char *timeout;

		domain_str = at + 1;

		h.min_wait_milliseconds = h.result_timeout_milliseconds = 0;

		if (osmo_print_n(timeouts, sizeof(timeouts), query_str, at - query_str) >= sizeof(timeouts)) {
			print_error("ERROR: timeouts part too long in query string\n");
			respond_err(domain_str);
			return;
		}

		dash = strchr(timeouts, '-');
		if (dash) {
			char min_delay[16];
			osmo_print_n(min_delay, sizeof(min_delay), timeouts, dash - timeouts);
			h.min_wait_milliseconds = parse_int(0, UINT32_MAX, min_delay, &rc);
			if (rc) {
				print_error("ERROR: invalid min-delay number: %s\n", min_delay);
				respond_err(domain_str);
				return;
			}
			timeout = dash + 1;
		} else {
			timeout = timeouts;
		}
		if (*timeout) {
			h.result_timeout_milliseconds = parse_int(0, UINT32_MAX, timeout, &rc);
			if (rc) {
				print_error("ERROR: invalid timeout number: %s\n", timeout);
				respond_err(domain_str);
				return;
			}
		}
	}

	if (strlen(domain_str) >= sizeof(q->query_str)) {
		print_error("ERROR: query string is too long: '%s'\n", domain_str);
		respond_err(domain_str);
		return;
	}

	q = talloc_zero(globals.ctx, struct query);
	OSMO_ASSERT(q);
	OSMO_STRLCPY_ARRAY(q->query_str, domain_str);

	if (osmo_mslookup_query_init_from_domain_str(&q->query, q->query_str)) {
		print_error("ERROR: cannot parse query string: '%s'\n", domain_str);
		respond_err(domain_str);
		talloc_free(q);
		return;
	}

	q->handle = osmo_mslookup_client_request(globals.mslookup_client, &q->query, &h);
	if (!q->handle) {
		print_error("ERROR: cannot send query: '%s'\n", domain_str);
		respond_err(domain_str);
		talloc_free(q);
		return;
	}

	llist_add(&q->entry, &globals.queries);
}

void start_query_strs(char **query_strs, size_t query_strs_len)
{
	int i;
	for (i = 0; i < query_strs_len; i++)
		start_query_str(query_strs[i]);
}

int main(int argc, char **argv)
{
	int rc = EXIT_FAILURE;
	globals.ctx = talloc_named_const(NULL, 0, "osmo-mslookup-client");

	osmo_init_logging2(globals.ctx, NULL);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_BASENAME);
	log_set_print_filename_pos(osmo_stderr_target, LOG_FILENAME_POS_LINE_END);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_extended_timestamp(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	while (1) {
		int c;
		long long int val;
		char *endptr;
		int option_index = 0;

		static struct option long_options[] = {
			{ "format", 1, 0, 'f' },
			{ "no-csv-headers", 0, 0, 'H' },
			{ "daemon", 0, 0, 'd' },
			{ "mdns-ip", 1, 0, 'm' },
			{ "mdns-port", 1, 0, 'M' },
			{ "timeout", 1, 0, 'T' },
			{ "min-delay", 1, 0, 't' },
			{ "socket", 1, 0, 's' },
			{ "send", 0, 0, 'S' },
			{ "quiet", 0, 0, 'q' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'V' },
			{}
		};

#define PARSE_INT(TARGET, MINVAL, MAXVAL) do { \
		int _rc; \
		TARGET = parse_int(MINVAL, MAXVAL, optarg, &_rc); \
		if (_rc) { \
			print_error("Invalid " #TARGET ": %s\n", optarg); \
			goto program_exit; \
		} \
	} while (0)

		c = getopt_long(argc, argv, "f:Hdm:M:t:T:s:SqhV", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'f':
			cmdline_opts.format_str = optarg;
			break;
		case 'H':
			cmdline_opts.csv_headers = false;
			break;
		case 'd':
			cmdline_opts.daemon = true;
			break;
		case 'm':
			if (osmo_sockaddr_str_from_str(&cmdline_opts.mdns_addr, optarg, cmdline_opts.mdns_addr.port)
			    || !osmo_sockaddr_str_is_nonzero(&cmdline_opts.mdns_addr)) {
				print_error("Invalid mDNS IP address: %s\n", optarg);
				goto program_exit;
			}
			break;
		case 'M':
			PARSE_INT(cmdline_opts.mdns_addr.port, 1, 65535);
			break;
		case 't':
			PARSE_INT(cmdline_opts.min_delay, 0, UINT32_MAX);
			break;
		case 'T':
			PARSE_INT(cmdline_opts.timeout, 0, UINT32_MAX);
			break;
		case 's':
			cmdline_opts.socket_path = optarg;
			break;
		case 'S':
			cmdline_opts.send = true;
			break;
		case 'q':
			cmdline_opts.quiet = true;
			break;

		case 'h':
			print_help();
			rc = 0;
			goto program_exit;
		case 'V':
			print_version();
			rc = 0;
			goto program_exit;

		default:
			/* catch unknown options *as well as* missing arguments. */
			print_error("Error in command line options. Exiting.\n");
			goto program_exit;
		}
	}

	if (cmdline_opts.send) {
		if (cmdline_opts.daemon || cmdline_opts.format_str || cmdline_opts.socket_path) {
			print_error("--send option cannot have any listening related args.");
		}
		rc = do_send(argc - optind, argv + optind);
		goto program_exit;
	}

	if (!cmdline_opts.daemon && !(argc - optind)) {
		print_help();
		goto program_exit;
	}

	if (cmdline_opts.daemon && !cmdline_opts.timeout) {
		print_error("In daemon mode, --timeout must not be zero.\n");
		goto program_exit;
	}

	if (cmdline_opts.quiet)
		log_target_destroy(osmo_stderr_target);

	if (cmdline_opts.format_str) {
		if (osmo_str_startswith("json", cmdline_opts.format_str))
			globals.format = FORMAT_JSON;
		else if (osmo_str_startswith("csv", cmdline_opts.format_str))
			globals.format = FORMAT_CSV;
		else {
			print_error("Invalid format: %s\n", cmdline_opts.format_str);
			goto program_exit;
		}
	}

	if (globals.format == FORMAT_CSV && cmdline_opts.csv_headers)
		respond_str_stdout(CSV_HEADERS);

	globals.mslookup_client = osmo_mslookup_client_new(globals.ctx);
	if (!globals.mslookup_client
	    || !osmo_mslookup_client_add_mdns(globals.mslookup_client,
					      cmdline_opts.mdns_addr.ip, cmdline_opts.mdns_addr.port,
					      -1)) {
		print_error("Failed to start mDNS client\n");
		goto program_exit;
	}

	if (cmdline_opts.socket_path) {
		if (socket_init(cmdline_opts.socket_path))
			goto program_exit;
	}

	start_query_strs(&argv[optind], argc - optind);

	while (1) {
		osmo_select_main_ctx(0);

		if (!cmdline_opts.daemon
		    && globals.requests_handled
		    && llist_empty(&globals.queries))
			break;
	}

	rc = 0;
program_exit:
	osmo_mslookup_client_free(globals.mslookup_client);
	socket_close();
	log_fini();
	talloc_free(globals.ctx);
	return rc;
}
