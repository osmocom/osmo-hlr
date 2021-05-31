#!/bin/sh -e
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2021 sysmocom s.f.m.c GmbH <info@sysmocom.de>
#
# Packagers are supposed to call this script in post-upgrade, so it can safely
# upgrade the database scheme if required.

DB="/var/lib/osmocom/hlr.db"
IS_ACTIVE=0

msg() {
	echo "osmo-hlr-post-upgrade: $@"
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

stop_service() {
	if systemctl is-active -q osmo-hlr; then
		IS_ACTIVE=1
		msg "stopping osmo-hlr service"
		systemctl stop osmo-hlr

		# Verify that it stopped
		for i in $(seq 1 100); do
			if ! systemctl is-active -q osmo-hlr; then
				return
			fi
			sleep 0.1
		done

		err "failed to stop osmo-hlr service"
		exit 1
	else
		msg "osmo-hlr service is not running"
	fi
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

start_service() {
	if [ "$IS_ACTIVE" = "1" ]; then
		msg "starting osmo-hlr service"
		systemctl start osmo-hlr
	fi
}

check_upgrade_required
stop_service
create_backup
upgrade
start_service
