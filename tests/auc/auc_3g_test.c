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
#include <inttypes.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>

#include <osmocom/crypt/auth.h>

#include "logging.h"
#include "auc.h"

#define comment_start() fprintf(stderr, "\n===== %s\n", __func__);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

#define VERBOSE_ASSERT(val, expect_op, fmt) \
	do { \
		fprintf(stderr, #val " == " fmt "\n", (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0);

char *vec_str(const struct osmo_auth_vector *vec)
{
	static char buf[1024];
	char *pos = buf;
	char *end = buf + sizeof(buf);

#define append(what) \
	if (pos >= end) \
		return buf; \
	pos += snprintf(pos, sizeof(buf) - (pos - buf), \
                        "  " #what ": %s\n", \
			osmo_hexdump_nospc((void*)&vec->what, sizeof(vec->what)))

	append(rand);
	append(autn);
	append(ck);
	append(ik);
	append(res);
	append(res_len);
	append(kc);
	append(sres);
	append(auth_types);
#undef append

	return buf;
}

#define VEC_IS(vec, expect) do { \
		char *_is = vec_str(vec); \
		fprintf(stderr, "auth vector ==\n%s\n", _is); \
	        if (strcmp(_is, expect)) { \
			fprintf(stderr, "MISMATCH! expected ==\n%s\n", \
				expect); \
			char *a = _is; \
			char *b = expect; \
			for (; *a && *b; a++, b++) { \
				if (*a != *b) { \
					while (a > _is && *(a-1) != '\n') a--; \
					fprintf(stderr, "mismatch at %d:\n" \
						"%s", (int)(a - _is), a); \
					break; \
				} \
			} \
			OSMO_ASSERT(false); \
		} \
	} while (0)

uint8_t fake_rand[16] = { 0 };

int rand_get(uint8_t *rand, unsigned int len)
{
	OSMO_ASSERT(len <= sizeof(fake_rand));
	memcpy(rand, fake_rand, len);
	return len;
}

static void test_gen_vectors_2g_only(void)
{
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct osmo_auth_vector vec;
	int rc;

	comment_start();

	aud2g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_COMP128v1,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud2g.u.gsm.ki, sizeof(aud2g.u.gsm.ki));

	aud3g = (struct osmo_sub_auth_data){ 0 };

	osmo_hexparse("39fa2f4e3d523d8619a73b4f65c3e14d",
		      fake_rand, sizeof(fake_rand));

	vec = (struct osmo_auth_vector){ {0} };
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 00000000000000000000000000000000\n"
	       "  ck: 00000000000000000000000000000000\n"
	       "  ik: 00000000000000000000000000000000\n"
	       "  res: 00000000000000000000000000000000\n"
	       "  res_len: 00\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 01000000\n"
	      );

	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);

	/* even though vec is not zero-initialized, it should produce the same
	 * result (regardless of the umts sequence nr) */
	aud3g.u.umts.sqn = 123;
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 00000000000000000000000000000000\n"
	       "  ck: 00000000000000000000000000000000\n"
	       "  ik: 00000000000000000000000000000000\n"
	       "  res: 00000000000000000000000000000000\n"
	       "  res_len: 00\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 01000000\n"
	      );

	comment_end();
}

static void test_gen_vectors_2g_plus_3g(void)
{
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct osmo_auth_vector vec;
	int rc;

	comment_start();

	aud2g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_GSM,
		.algo = OSMO_AUTH_ALG_COMP128v1,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud2g.u.gsm.ki, sizeof(aud2g.u.gsm.ki));

	aud3g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_MILENAGE,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud3g.u.umts.k, sizeof(aud3g.u.umts.k));
	osmo_hexparse("FB2A3D1B360F599ABAB99DB8669F8308",
		      aud3g.u.umts.opc, sizeof(aud3g.u.umts.opc));

	osmo_hexparse("39fa2f4e3d523d8619a73b4f65c3e14d",
		      fake_rand, sizeof(fake_rand));

	vec = (struct osmo_auth_vector){ {0} };
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55f30000d2ee44b22c8ea919\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 03000000\n"
	      );

	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 1, "%"PRIu64);

	/* even though vec is not zero-initialized, it should produce the same
	 * result with the same sequence nr */
	aud3g.u.umts.sqn = 0;
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 1, "%"PRIu64);

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55f30000d2ee44b22c8ea919\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 241a5b16aeb8e400\n"
	       "  sres: 429d5b27\n"
	       "  auth_types: 03000000\n"
	      );

	comment_end();
}

static void test_gen_vectors_3g_only(void)
{
	struct osmo_sub_auth_data aud2g;
	struct osmo_sub_auth_data aud3g;
	struct osmo_auth_vector vec;
	int rc;

	comment_start();

	aud2g = (struct osmo_sub_auth_data){ 0 };

	aud3g = (struct osmo_sub_auth_data){
		.type = OSMO_AUTH_TYPE_UMTS,
		.algo = OSMO_AUTH_ALG_MILENAGE,
	};

	osmo_hexparse("EB215756028D60E3275E613320AEC880",
		      aud3g.u.umts.k, sizeof(aud3g.u.umts.k));
	osmo_hexparse("FB2A3D1B360F599ABAB99DB8669F8308",
		      aud3g.u.umts.opc, sizeof(aud3g.u.umts.opc));

	osmo_hexparse("39fa2f4e3d523d8619a73b4f65c3e14d",
		      fake_rand, sizeof(fake_rand));

	vec = (struct osmo_auth_vector){ {0} };
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55f30000d2ee44b22c8ea919\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 059a4f668f6fbe39\n"
	       "  sres: 9b36efdf\n"
	       "  auth_types: 03000000\n"
	      );

	/* Note: 3GPP TS 33.102 6.8.1.2: c3 function to get GSM auth is
	 * KC[0..7] == CK[0..7] ^ CK[8..15] ^ IK[0..7] ^ IK[8..15]
	 * In [16]: hex(  0xf64735036e587131
	 *              ^ 0x9c679f4742a75ea1
	 *              ^ 0x27497388b6cb0446
	 *              ^ 0x48f396aa155b95ef)
	 * Out[16]: '0x59a4f668f6fbe39L'
	 * hence expecting kc: 059a4f668f6fbe39
	 */

	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 1, "%"PRIu64);

	/* even though vec is not zero-initialized, it should produce the same
	 * result with the same sequence nr */
	aud3g.u.umts.sqn = 0;
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 0, "%"PRIu64);
	rc = auc_compute_vectors(&vec, 1, &aud2g, &aud3g, NULL, NULL);
	VERBOSE_ASSERT(rc, == 1, "%d");
	VERBOSE_ASSERT(aud3g.u.umts.sqn, == 1, "%"PRIu64);

	VEC_IS(&vec,
	       "  rand: 39fa2f4e3d523d8619a73b4f65c3e14d\n"
	       "  autn: 8704f5ba55f30000d2ee44b22c8ea919\n"
	       "  ck: f64735036e5871319c679f4742a75ea1\n"
	       "  ik: 27497388b6cb044648f396aa155b95ef\n"
	       "  res: e229c19e791f2e410000000000000000\n"
	       "  res_len: 08\n"
	       "  kc: 059a4f668f6fbe39\n"
	       "  sres: 9b36efdf\n"
	       "  auth_types: 03000000\n"
	      );

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

	test_gen_vectors_2g_only();
	test_gen_vectors_2g_plus_3g();
	test_gen_vectors_3g_only();

	printf("Done\n");
	return 0;
}
