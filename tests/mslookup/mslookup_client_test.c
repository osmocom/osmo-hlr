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

#include <sys/time.h>
#include <string.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/mslookup/mslookup_client_fake.h>
#include <osmocom/mslookup/mslookup_client.h>

#define SERVICE_HLR_GSUP "gsup.hlr"
#define SERVICE_SIP "sip.voice"

void *ctx = NULL;

static struct osmo_mslookup_fake_response fake_lookup_responses[] = {
	{
		.time_to_reply = { .tv_sec = 1, },
		.for_id = {
			.type = OSMO_MSLOOKUP_ID_IMSI,
			.imsi = "1234567",
		},
		.for_service = SERVICE_HLR_GSUP,
		.result = {
			.rc = OSMO_MSLOOKUP_RC_RESULT,
			.host_v4 = {
				.af = AF_INET,
				.ip = "12.34.56.7",
				.port = 42,
			},
			.host_v6 = {
				.af = AF_INET6,
				.ip = "be:ef:ed:ca:fe:fa:ce::1",
				.port = 42,
			},
			.age = 0,
		},
	},
	{
		.time_to_reply = { .tv_usec = 600 * 1000, },
		.for_id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "112",
		},
		.for_service = SERVICE_SIP,
		.result = {
			.rc = OSMO_MSLOOKUP_RC_RESULT,
			.host_v4 = {
				.af = AF_INET,
				.ip = "66.66.66.66",
				.port = 666,
			},
			.host_v6 = {
				.af = AF_INET,
				.ip = "6666:6666:6666::6",
				.port = 666,
			},
			.age = 423,
		},
	},
	{
		.time_to_reply = { .tv_usec = 800 * 1000, },
		.for_id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "112",
		},
		.for_service = SERVICE_SIP,
		.result = {
			.rc = OSMO_MSLOOKUP_RC_RESULT,
			.host_v4 = {
				.af = AF_INET,
				.ip = "112.112.112.112",
				.port = 23,
			},
			.age = 235,
		},
	},
	{
		.time_to_reply = { .tv_sec = 1, .tv_usec = 200 * 1000, },
		.for_id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "112",
		},
		.for_service = SERVICE_SIP,
		.result = {
			.rc = OSMO_MSLOOKUP_RC_RESULT,
			.host_v4 = {
				.af = AF_INET,
				.ip = "99.99.99.99",
				.port = 999,
			},
			.host_v6 = {
				.af = AF_INET,
				.ip = "9999:9999:9999::9",
				.port = 999,
			},
			.age = 335,
		},
	},
	{
		.time_to_reply = { .tv_sec = 1, .tv_usec = 500 * 1000, },
		.for_id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "112",
		},
		.for_service = SERVICE_SIP,
		.result = {
			.rc = OSMO_MSLOOKUP_RC_RESULT,
			.host_v4 = {
				.af = AF_INET,
				.ip = "99.99.99.99",
				.port = 999,
			},
			.age = 999,
		},
	},
};

const struct timeval fake_time_start_time = { 0, 0 };

#define fake_time_passes(secs, usecs) do \
{ \
	struct timeval diff; \
	osmo_gettimeofday_override_add(secs, usecs); \
	osmo_clock_override_add(CLOCK_MONOTONIC, secs, usecs * 1000); \
	timersub(&osmo_gettimeofday_override_time, &fake_time_start_time, &diff); \
	LOGP(DMSLOOKUP, LOGL_DEBUG, "Total time passed: %d.%06d s\n", \
	       (int)diff.tv_sec, (int)diff.tv_usec); \
	osmo_timers_prepare(); \
	osmo_timers_update(); \
} while (0)

static void fake_time_start()
{
	struct timespec *clock_override;

	osmo_gettimeofday_override_time = fake_time_start_time;
	osmo_gettimeofday_override = true;
	clock_override = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	OSMO_ASSERT(clock_override);
	clock_override->tv_sec = fake_time_start_time.tv_sec;
	clock_override->tv_nsec = fake_time_start_time.tv_usec * 1000;
	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	fake_time_passes(0, 0);
}

static void result_cb_once(struct osmo_mslookup_client *client,
			   uint32_t request_handle,
			   const struct osmo_mslookup_query *query,
			   const struct osmo_mslookup_result *result)
{
	LOGP(DMSLOOKUP, LOGL_DEBUG, "result_cb(): %s\n", osmo_mslookup_result_name_c(ctx, query, result));
}

int main()
{
	ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_category_filter(osmo_stderr_target, DMSLOOKUP, true, LOGL_DEBUG);

	fake_time_start();

	struct osmo_mslookup_client *client = osmo_mslookup_client_new(ctx);
	osmo_mslookup_client_add_fake(client, fake_lookup_responses, ARRAY_SIZE(fake_lookup_responses));

	/* Place some requests to be replied upon asynchronously */

	struct osmo_mslookup_query_handling handling = {
		.result_timeout_milliseconds = 1, /* set some timeout < min_wait_milliseconds */
		.min_wait_milliseconds = 2000,
		.result_cb = result_cb_once,
	};

	struct osmo_mslookup_query q1 = {
		.service = SERVICE_HLR_GSUP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_IMSI,
			.imsi = "1234567",
		},
	};
	OSMO_ASSERT(osmo_mslookup_client_request(client, &q1, &handling));

	struct osmo_mslookup_query q2 = {
		.service = SERVICE_SIP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "112",
		},
	};
	handling.min_wait_milliseconds = 3000;
	OSMO_ASSERT(osmo_mslookup_client_request(client, &q2, &handling));

	struct osmo_mslookup_query q3 = {
		.service = "smpp.sms",
		.id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "00000",
		},
	};
	handling.min_wait_milliseconds = 5000;
	OSMO_ASSERT(osmo_mslookup_client_request(client, &q3, &handling));

	struct osmo_mslookup_query q4 = {
		.service = SERVICE_HLR_GSUP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "666",
		},
	};
	handling.min_wait_milliseconds = 10000;
	uint32_t q4_handle;
	OSMO_ASSERT((q4_handle = osmo_mslookup_client_request(client, &q4, &handling)));

	while (osmo_gettimeofday_override_time.tv_sec < 6) {
		log_reset_context();
		fake_time_passes(0, 1e6 / 5);
	}

	osmo_mslookup_client_request_cancel(client, q4_handle);

	return 0;
}
