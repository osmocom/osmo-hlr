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

#include <string.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/hlr/logging.h>
#include <osmocom/mslookup/mslookup_client.h>

void *ctx;

const char *domains[] = {
	"gsup.hlr.123456789012345.imsi",
	"gsup.hlr.1.imsi",
	"sip.voice.1.msisdn",
	"a.b.c.imsi",
	"",
	".",
	"...",
	".....",
	".....1.msisdn",
	"fofdndsf. d.ads ofdsf. ads.kj.1243455132.msisdn",
	"foo.12345678901234567890.imsi",
	"gsup.hlr.123456789012345.what",
	NULL,
	"blarg",
	"blarg.",
	"blarg.1.",
	"blarg.1.msisdn",
	"blarg.1.msisdn.",
	".1.msisdn",
	"1.msisdn",
	"qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmm.1.msisdn",
	"qwerty.1.qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmm",
};

void test_osmo_mslookup_query_init_from_domain_str()
{
	int i;
	for (i = 0; i < ARRAY_SIZE(domains); i++) {
		const char *d = domains[i];
		struct osmo_mslookup_query q;

		int rc = osmo_mslookup_query_init_from_domain_str(&q, d);
		if (rc)
			fprintf(stderr, "%s -> rc = %d\n", osmo_quote_str(d, -1), rc);
		else
			fprintf(stderr, "%s -> %s %s %s\n", osmo_quote_str(d, -1),
			       osmo_quote_str_c(ctx, q.service, -1),
			       osmo_quote_str_c(ctx, q.id.imsi, -1),
			       osmo_mslookup_id_type_name(q.id.type));
	}
}

int main()
{
	ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename2(osmo_stderr_target, LOG_FILENAME_NONE);
	log_set_print_level(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_category_filter(osmo_stderr_target, DMSLOOKUP, true, LOGL_DEBUG);

	test_osmo_mslookup_query_init_from_domain_str();

	talloc_free(ctx);

	return 0;
}
