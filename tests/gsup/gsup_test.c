/* (C) 2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <string.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>
#include <osmocom/gsupclient/gsup_req.h>

void *ctx = NULL;

static void test_gsup_make_response(void)
{
	char *source_name = "incoming-source-name";
	char *destination_name = "preset-destination-name";
	uint8_t sm_rp_mr = 23;
	uint8_t other_sm_rp_mr = 17;
	struct osmo_gsup_message rx = {
		.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST,
		.imsi = "1234567",
		.message_class = OSMO_GSUP_MESSAGE_CLASS_SUBSCRIBER_MANAGEMENT,
		.source_name = (uint8_t*)source_name,
		.source_name_len = strlen(source_name) + 1,
		.sm_rp_mr = &sm_rp_mr,
		.session_id = 42,
		.session_state = OSMO_GSUP_SESSION_STATE_BEGIN,
	};
	struct osmo_gsup_message nonempty = {
		.message_type = OSMO_GSUP_MSGT_ROUTING_ERROR,
		.imsi = "987654321",
		.message_class = OSMO_GSUP_MESSAGE_CLASS_INTER_MSC,
		.destination_name = (uint8_t*)destination_name,
		.destination_name_len = strlen(destination_name) + 1,
		.sm_rp_mr = &other_sm_rp_mr,
		.session_id = 11,
		.session_state = OSMO_GSUP_SESSION_STATE_END,
	};
	void *name_ctx = talloc_named_const(ctx, 0, __func__);
	int error;
	int final;
	char *nonempty_str;
	int rc;

	printf("\n%s()\n", __func__);
	printf("rx = %s\n", osmo_gsup_message_to_str_c(name_ctx, &rx));

	printf("\nwriting to an empty struct osmo_gsup_message should populate values as needed:\n");
	for (error = 0; error <= 1; error++) {
		for (final = 0; final <= 1; final++) {
			struct osmo_gsup_message target = {};
			printf("- args (error=%d, final=%d)\n", error, final);
			rc = osmo_gsup_make_response(&target, &rx, error, final);
			printf("  %s\n", osmo_gsup_message_to_str_c(name_ctx, &target));
			printf("  rc = %d\n", rc);
		}
	}

	printf("\nwriting to an already populated struct osmo_gsup_message, should have no effect:\n");
	nonempty_str = osmo_gsup_message_to_str_c(name_ctx, &nonempty);
	for (error = 0; error <= 1; error++) {
		for (final = 0; final <= 1; final++) {
			struct osmo_gsup_message target = nonempty;
			char *result;
			printf("- args (error=%d, final=%d)\n", error, final);
			rc = osmo_gsup_make_response(&target, &rx, error, final);
			result = osmo_gsup_message_to_str_c(name_ctx, &target);
			printf("  %s\n", result);
			if (strcmp(result, nonempty_str))
				printf("  ERROR: expected: %s\n", nonempty_str);
			printf("  rc = %d\n", rc);
		}
	}
}

const struct log_info_cat default_categories[] = {
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, "gsup_test");
	osmo_init_logging2(ctx, &info);
	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	test_gsup_make_response();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
