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

#include <osmocom/core/timer.h>
#include <osmocom/hlr/timestamp.h>

/* Central implementation to set a timestamp to the current time, in case we want to modify this in the future. */
void timestamp_update(timestamp_t *timestamp)
{
	struct timeval tv;
	time_t raw;
	struct tm utc;
	/* The simpler way would be just time(&raw), but by using osmo_gettimeofday() we can also use
	 * osmo_gettimeofday_override for unit tests independent from real time. */
	osmo_gettimeofday(&tv, NULL);
	raw = tv.tv_sec;
	gmtime_r(&raw, &utc);
	*timestamp = mktime(&utc);
}

/* Calculate seconds since a given timestamp was taken. Return true for a valid age returned in age_p, return false if
 * the timestamp is either in the future or the age surpasses uint32_t range. When false is returned, *age_p is set to
 * UINT32_MAX. */
bool timestamp_age(const timestamp_t *timestamp, uint32_t *age_p)
{
	int64_t age64;
	timestamp_t now;
	timestamp_update(&now);
	age64 = (int64_t)now - (int64_t)(*timestamp);
	if (age64 < 0 || age64 > UINT32_MAX) {
		*age_p = UINT32_MAX;
		return false;
	}
	*age_p = (uint32_t)age64;
	return true;
}

