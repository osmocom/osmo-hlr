#!/bin/sh
srcdir="${1:-.}"
builddir="${2:-.}"
do_equivalence_test="$3"

set -e

db="$builddir/test.db"
osmo_hlr="$builddir/../../src/osmo-hlr"
cfg="$srcdir/osmo-hlr.cfg"

dump_sorted_schema(){
	db_file="$1"
	tables="$(sqlite3 "$db_file" "SELECT name FROM sqlite_master WHERE type = 'table' order by name")"
	for table in $tables; do
		echo
		echo "Table: $table"
		sqlite3 -header "$db_file" "SELECT name,type,\"notnull\",dflt_value,pk FROM PRAGMA_TABLE_INFO('$table') order by name;"
		echo
		echo "Table $table contents:"
		columns="$(sqlite3 "$db_file" "SELECT name FROM PRAGMA_TABLE_INFO('$table') order by name;")"
		sqlite3 -header "$db_file" "SELECT $(echo $columns | sed 's/ /,/g') from $table;"
	done
}

rm -f "$db"
echo "Creating db in schema version 0"
sqlite3 "$db" < "$srcdir/hlr_db_v0.sql"

echo
echo "Version 0 db:"
dump_sorted_schema "$db"

set +e

echo
echo "Launching osmo-hlr to upgrade db:"
echo osmo-hlr --database '$db' --db-upgrade --db-check --config-file '$srcdir/osmo-hlr.cfg'
"$osmo_hlr" --database "$db" --db-upgrade --db-check --config-file "$cfg" >log 2>&1
echo "rc = $?"
cat log | sed 's@[^ "]*/@<PATH>@g'

echo
echo "Resulting db:"
dump_sorted_schema "$db"

echo
echo "Verify that osmo-hlr can open it:"
echo osmo-hlr --database '$db' --db-check --config-file '$srcdir/osmo-hlr.cfg'
"$osmo_hlr" --database "$db" --db-check --config-file "$cfg" >log 2>&1
echo "rc = $?"
cat log | sed 's@[^ "]*/@<PATH>@g'

if [ -n "$do_equivalence_test" ]; then
	# this part requires osmo_interact_vty.py, so this test is not part of the normal run
	set -e -x
	mint_db="$builddir/mint.db"
	rm -f "$mint_db"

	osmo_verify_transcript_vty.py -v \
		-n OsmoHLR -p 4258 \
		-r "$osmo_hlr -c $cfg -l $mint_db" \
		"$srcdir/create_subscribers.vty"
	sqlite3 "$mint_db" < "$srcdir/create_subscribers_step2.sql"

	set +x
	test_dump="$builddir/test.dump"
	mint_dump="$builddir/mint.dump"

	dump_sorted_schema "$db" > "$test_dump"
	dump_sorted_schema "$mint_db" > "$mint_dump"

	echo
	echo "Newly created sorted schema is:"
	cat "$mint_dump"
	echo
	echo "Diff to upgraded schema:"
	diff -u "$mint_dump" "$test_dump"
	echo "rc=$?"
fi

rm -f log
rm -f "$db"
