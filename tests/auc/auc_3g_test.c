/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <string.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include "logging.h"

#define comment_start() fprintf(stderr, "===== %s\n", __func__);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

uint8_t fake_rand[16] = { 0 };

int rand_get(uint8_t *rand, unsigned int len)
{
	OSMO_ASSERT(len <= sizeof(fake_rand));
	memcpy(rand, fake_rand, len);
	return len;
}

static void test_gen_vectors_3g_only(void)
{
	comment_start();
	comment_end();
}

int main()
{
	printf("auc_3g_test.c\n");
	osmo_init_logging(&hlr_log_info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);

	test_gen_vectors_3g_only();

	printf("Done\n");
	return 0;
}
