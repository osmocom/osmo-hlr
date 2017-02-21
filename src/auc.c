/* (C) 2015 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/crypt/auth.h>

#include "logging.h"
#include "rand.h"

/* compute given number of vectors using either aud2g or aud2g or a combination
 * of both.  Handles re-synchronization if rand_auts and auts are set */
int auc_compute_vectors(struct osmo_auth_vector *vec, unsigned int num_vec,
			struct osmo_sub_auth_data *aud2g,
			struct osmo_sub_auth_data *aud3g,
			const uint8_t *rand_auts, const uint8_t *auts)
{
	unsigned int i;
	uint8_t rand[16];
	int rc;

	if (aud2g && (aud2g->algo == OSMO_AUTH_ALG_NONE
		      || aud2g->type == OSMO_AUTH_TYPE_NONE))
		aud2g = NULL;
	if (aud3g && (aud3g->algo == OSMO_AUTH_ALG_NONE
		      || aud3g->type == OSMO_AUTH_TYPE_NONE))
		aud3g = NULL;

	if (!aud2g && !aud3g) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() called"
		     " with neither 2G nor 3G auth data available\n");
		return -1;
	}

	if (aud2g && aud2g->type != OSMO_AUTH_TYPE_GSM) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() called"
		     " with non-2G auth data passed for aud2g arg\n");
		return -1;
	}

	if (aud3g && aud3g->type != OSMO_AUTH_TYPE_UMTS) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() called"
		     " with non-3G auth data passed for aud3g arg\n");
		return -1;
	}

	if ((rand_auts != NULL) != (auts != NULL)) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() with only one"
		     " of AUTS and AUTS_RAND given, need both or neither\n");
		return -1;
	}

	if (auts && !aud3g) {
		LOGP(DAUC, LOGL_ERROR, "auc_compute_vectors() with AUTS called"
		     " but no 3G auth data passed\n");
		return -1;
	}

	/* compute quintuples */
	for (i = 0; i < num_vec; i++) {
		rc = rand_get(rand, sizeof(rand));
		DEBUGP(DAUC, "rand %s\n", osmo_hexdump_nospc(rand, sizeof(rand)));
		if (rc != sizeof(rand)) {
			LOGP(DAUC, LOGL_ERROR, "Unable to read %zu random "
			     "bytes: rc=%d\n", sizeof(rand), rc);
			goto out;
		}

		if (aud2g && !aud3g) {
			/* 2G only case: output directly to vec */
			DEBUGP(DAUC, "compute vector [%u]/%u: 2G only\n",
			       i, num_vec);
			rc = osmo_auth_gen_vec(vec+i, aud2g, rand);
			if (rc < 0) {
				LOGP(DAUC, LOGL_ERROR, "Error in 2G vector "
				     "generation: %d\n", rc);
				goto out;
			}
		} else if (aud3g) {
			/* 3G or 3G + 2G case */
			if (!aud2g)
				DEBUGP(DAUC, "compute vector [%u]/%u: 3G only\n",
				       i, num_vec);
			if (rand_auts && auts)
				rc = osmo_auth_gen_vec_auts(vec+i, aud3g,
							    auts, rand_auts,
							    rand);
			else
				rc = osmo_auth_gen_vec(vec+i, aud3g, rand);
			if (rc < 0) {
				LOGP(DAUC, LOGL_ERROR, "Error in 3G vector "
				     "generation: %d\n", rc);
				goto out;
			}
		}
		if (aud2g && aud3g) {
			/* separate 2G + 3G case: patch 2G into 3G */
			struct osmo_auth_vector vtmp;
			DEBUGP(DAUC, "compute vector [%u]/%u:"
			       " separate 2G + 3G\n", i, num_vec);
			rc = osmo_auth_gen_vec(&vtmp, aud2g, rand);
			if (rc < 0) {
				LOGP(DAUC, LOGL_ERROR, "Error in 2G vector "
				     "generation: %d\n", rc);
				goto out;
			}
			memcpy(&vec[i].kc, vtmp.kc, sizeof(vec[i].kc));
			memcpy(&vec[i].sres, vtmp.sres, sizeof(vec[i].sres));
			vec[i].auth_types |= OSMO_AUTH_TYPE_GSM;
		}
	}
out:
	return i;
}
