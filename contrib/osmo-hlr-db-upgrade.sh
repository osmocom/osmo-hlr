#!/bin/sh -e
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2021 sysmocom s.f.m.c GmbH <info@sysmocom.de>
#
# This script gets called in ExecStartPre= of osmo-hlr.service, so it can
# safely upgrade the database scheme if required.

DB="/var/lib/osmocom/hlr.db"

msg() {
	echo "osmo-hlr-db-upgrade: $@"
}

err() {
	msg "ERROR: $@"
}

open_db() {
	# Attempt to open the database with osmo-hlr-db-tool, it will fail if
	# upgrading the schema is required
	osmo-hlr-db-tool -s -l "$DB" create
}

check_upgrade_required() {
	if ! [ -e "$DB" ]; then
		msg "nothing to do (no existing database)"
		exit 0
	fi

	if open_db 2>/dev/null; then
		msg "nothing to do (database version is up to date)"
		exit 0
	fi

	msg "database upgrade is required"
}

create_backup() {
	backup="$DB.$(date +%Y%m%d%H%M%S).bak"
	msg "creating backup: $backup"
	if [ -e "$backup" ]; then
		err "backup already exists: $backup"
		exit 1
	fi
	cp "$DB" "$backup"
}

upgrade() {
	msg "performing database upgrade"
	osmo-hlr-db-tool -s -U -l "$DB" create

	if ! open_db 2>/dev/null; then
		err "failed to open the database after upgrade"
		err "osmo-hlr-db-tool output:"
		open_db
		# exit because of "set -e"
	fi

	msg "database upgrade successful"
}

check_upgrade_required
create_backup
upgrade
