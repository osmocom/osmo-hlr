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
#include <osmocom/gsm/gsup.h>

#include "logging.h"
#include "luop.h"

struct osmo_gsup_server;

/* override osmo_gsup_addr_send() to not actually send anything. */
int osmo_gsup_addr_send(struct osmo_gsup_server *gs,
			const uint8_t *addr, size_t addrlen,
			struct msgb *msg)
{
	LOGP(DMAIN, LOGL_DEBUG, "%s\n", msgb_hexdump(msg));
	msgb_free(msg);
	return 0;
}

int db_subscr_get_by_imsi(struct db_context *dbc, const char *imsi,
			  struct hlr_subscriber *subscr)
{
	return 0;
}

/* Verify that the internally allocated msgb is large enough */
void test_gsup_tx_insert_subscr_data()
{
	struct lu_operation luop = {
		.state = LU_S_LU_RECEIVED,
		.subscr = {
			.imsi = "123456789012345",
			.msisdn = "987654321098765",
			.nam_cs = true,
			.nam_ps = true,
		},
		.is_ps = true,
	};

	lu_op_tx_insert_subscr_data(&luop);
}

const struct log_info_cat default_categories[] = {
	[DMAIN] = {
		.name = "DMAIN",
		.description = "Main Program",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "gsup_test");
	osmo_init_logging2(ctx, &info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	test_gsup_tx_insert_subscr_data();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
