/* OsmoHLR VTY implementation */

/* (C) 2016 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include <osmocom/core/logging.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/hlr/hlr.h>

enum hlr_vty_node {
	HLR_NODE = _LAST_OSMOVTY_NODE + 1,
	GSUP_NODE,
	EUSE_NODE,
	MSLOOKUP_NODE,
	MSLOOKUP_SERVER_NODE,
	MSLOOKUP_SERVER_MSC_NODE,
	MSLOOKUP_CLIENT_NODE,
};


#define A38_XOR_MIN_KEY_LEN	12
#define A38_XOR_MAX_KEY_LEN	16
#define A38_COMP128_KEY_LEN	16
#define MILENAGE_KEY_LEN	16

int hlr_vty_is_config_node(struct vty *vty, int node);
int hlr_vty_go_parent(struct vty *vty);
void hlr_vty_init(void);
void dgsm_vty_init(void);
