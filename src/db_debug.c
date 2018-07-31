/*
 * libtalloc based memory allocator for SQLite3.
 *
 * (C) 2019 by Vadim Yanitskiy <axilirator@gmail.com>
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

#include <sqlite3.h>
#include <talloc.h>
#include <errno.h>

/* Dedicated talloc context for SQLite */
static void *db_sqlite_ctx = NULL;

static void *tall_xMalloc(int size)
{
	return talloc_size(db_sqlite_ctx, size);
}

static void tall_xFree(void *ptr)
{
	talloc_free(ptr);
}

static void *tall_xRealloc(void *ptr, int size)
{
	return talloc_realloc_fn(db_sqlite_ctx, ptr, size);
}

static int tall_xSize(void *ptr)
{
	return talloc_total_size(ptr);
}

/* DUMMY: talloc doesn't round up the allocation size */
static int tall_xRoundup(int size) { return size; }

/* DUMMY: nothing to initialize */
static int tall_xInit(void *data) { return 0; }

/* DUMMY: nothing to deinitialize */
static void tall_xShutdown(void *data) {  }

/* Interface between SQLite and talloc memory allocator */
static const struct sqlite3_mem_methods tall_sqlite_if = {
	/* Memory allocation function */
	.xMalloc = &tall_xMalloc,
	/* Free a prior allocation */
	.xFree = &tall_xFree,
	/* Resize an allocation */
	.xRealloc = &tall_xRealloc,
	/* Return the size of an allocation */
	.xSize = &tall_xSize,
	/* Round up request size to allocation size */
	.xRoundup = &tall_xRoundup,
	/* Initialize the memory allocator */
	.xInit = &tall_xInit,
	/* Deinitialize the memory allocator */
	.xShutdown = &tall_xShutdown,
	/* Argument to xInit() and xShutdown() */
	.pAppData = NULL,
};

int db_sqlite3_use_talloc(void *ctx)
{
	if (db_sqlite_ctx != NULL)
		return -EEXIST;

	db_sqlite_ctx = talloc_named_const(ctx, 0, "SQLite3");
	return sqlite3_config(SQLITE_CONFIG_MALLOC, &tall_sqlite_if);
}
