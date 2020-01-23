/* Copyright 2020 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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

/* If a subscriber from a remote site has successfully attached at this local site, and the link to the subscriber's
 * home HLR has succeeded, this will try to bridge the time of temporary link failure to that home HLR.
 * Tasks to take over from the unreachable home HLR:
 * - Resend known auth tuples on OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST.
 * - ...?
 *
 *
 */

/* Data stored per subscriber */
struct proxy_broken_link_cache {
	struct osmo_auth_vector auth_vectors[OSMO_GSUP_MAX_NUM_AUTH_INFO];
	size_t num_auth_vectors;

	timestamp_t last_update;
};
