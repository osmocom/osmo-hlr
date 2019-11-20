/* Copyright 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#pragma once

#include <osmocom/gsm/gsup.h>
#include <osmocom/gsupclient/ipa_name.h>

struct osmo_gsup_req;

#define LOG_GSUP_REQ_CAT_SRC(req, subsys, level, file, line, fmt, args...) \
	LOGPSRC(subsys, level, file, line, "GSUP %u: %s: IMSI-%s %s: " fmt, \
		(req) ? (req)->nr : 0, \
		(req) ? osmo_ipa_name_to_str(&(req)->source_name) : "NULL", \
		(req) ? (req)->gsup.imsi : "NULL", \
		(req) ? osmo_gsup_message_type_name((req)->gsup.message_type) : "NULL", \
		##args)
#define LOG_GSUP_REQ_CAT(req, subsys, level, fmt, args...) \
	LOG_GSUP_REQ_CAT_SRC(req, subsys, level, __FILE__, __LINE__, fmt, ##args)

#define LOG_GSUP_REQ_SRC(req, level, file, line, fmt, args...) \
	LOG_GSUP_REQ_CAT_SRC(req, DLGSUP, level, file, line, fmt, ##args)

#define LOG_GSUP_REQ(req, level, fmt, args...) \
	LOG_GSUP_REQ_SRC(req, level, __FILE__, __LINE__, fmt, ##args)

typedef void (*osmo_gsup_req_send_response_t)(struct osmo_gsup_req *req, struct osmo_gsup_message *response);

/* Keep track of an incoming request, to route back a response when it is ready.
 * Particularly, a GSUP response to a request must contain various bits of information that need to be copied from the
 * request for proxy/routing to work and for session states to remain valid. That is the main reason why (almost) all
 * GSUP request/response should go through an osmo_gsup_req, even if it is handled synchronously.
 */
struct osmo_gsup_req {
	/* The incoming GSUP message in decoded form. */
	const struct osmo_gsup_message gsup;

	/* Decoding result code. If decoding failed, this will be != 0. */
	int decode_rc;

	/* The ultimate source of this message: the source_name form the GSUP message, or, if not present, then the
	 * immediate GSUP peer. GSUP messages going via a proxy reflect the initial source in the source_name.
	 * This source_name is implicitly added to the routes for the conn the message was received on. */
	struct osmo_ipa_name source_name;

	/* If the source_name is not an immediate GSUP peer, this is set to the closest intermediate peer between here
	 * and source_name. */
	struct osmo_ipa_name via_proxy;

	/* Identify this request by number, for logging. */
	unsigned int nr;

	/* osmo_gsup_req can be used by both gsup_server and gsup_client. The individual method of actually sending a
	 * GSUP message is provided by this callback. */
	osmo_gsup_req_send_response_t send_response_cb;

	/* User supplied data pointer, may be used to provide context to send_response_cb(). */
	void *cb_data;

	/* List entry that can be used to keep a list of osmo_gsup_req instances; not used directly by osmo_gsup_req.c,
	 * it is up to using implementations to keep a list. If this is non-NULL, osmo_gsup_req_free() calls
	 * llist_del() on this. */
	struct llist_head entry;

	/* A decoded GSUP message still points into the received msgb. For a decoded osmo_gsup_message to remain valid,
	 * we also need to keep the msgb. */
	struct msgb *msg;
};

struct osmo_gsup_req *osmo_gsup_req_new(void *ctx, const struct osmo_ipa_name *from_peer, struct msgb *msg,
					osmo_gsup_req_send_response_t send_response_cb, void *cb_data,
					struct llist_head *add_to_list);
void osmo_gsup_req_free(struct osmo_gsup_req *req);

/*! Call _osmo_gsup_req_respond() to convey the sender's source file and line in the logs. */
#define osmo_gsup_req_respond(REQ, RESPONSE, ERROR, FINAL_RESPONSE) \
	_osmo_gsup_req_respond(REQ, RESPONSE, ERROR, FINAL_RESPONSE, __FILE__, __LINE__)
int _osmo_gsup_req_respond(struct osmo_gsup_req *req, struct osmo_gsup_message *response,
			   bool error, bool final_response, const char *file, int line);

/*! Call _osmo_gsup_req_respond_msgt() to convey the sender's source file and line in the logs. */
#define osmo_gsup_req_respond_msgt(REQ, MESSAGE_TYPE, FINAL_RESPONSE) \
	_osmo_gsup_req_respond_msgt(REQ, MESSAGE_TYPE, FINAL_RESPONSE, __FILE__, __LINE__)
int _osmo_gsup_req_respond_msgt(struct osmo_gsup_req *req, enum osmo_gsup_message_type message_type,
				bool final_response, const char *file, int line);

/*! Log an error message, and call _osmo_gsup_req_respond() to convey the sender's source file and line in the logs. */
#define osmo_gsup_req_respond_err(REQ, CAUSE, FMT, args...) do { \
		LOG_GSUP_REQ(REQ, LOGL_ERROR, "%s: " FMT "\n", \
			     get_value_string(gsm48_gmm_cause_names, CAUSE), ##args); \
		_osmo_gsup_req_respond_err(REQ, CAUSE, __FILE__, __LINE__); \
	} while(0)
void _osmo_gsup_req_respond_err(struct osmo_gsup_req *req, enum gsm48_gmm_cause cause,
				const char *file, int line);

int osmo_gsup_make_response(struct osmo_gsup_message *reply,
			    const struct osmo_gsup_message *rx, bool error, bool final_response);

size_t osmo_gsup_message_to_str_buf(char *buf, size_t bufsize, const struct osmo_gsup_message *msg);
char *osmo_gsup_message_to_str_c(void *ctx, const struct osmo_gsup_message *msg);
