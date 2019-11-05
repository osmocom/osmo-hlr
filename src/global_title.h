#pragma once
#include <unistd.h>
#include <stdint.h>

/* Arbitrary length blob, not necessarily zero-terminated.
 * In osmo-hlr, struct hlr_subscriber is mostly used as static reference and cannot serve as talloc context, which is
 * why this is also implemented as a fixed-maximum-size buffer instead of a talloc'd arbitrary sized buffer.
 */
struct global_title {
	size_t len;
	uint8_t val[128];
};

int global_title_set(struct global_title *gt, const uint8_t *val, size_t len);
int global_title_cmp(const struct global_title *a, const struct global_title *b);
const char *global_title_name(const struct global_title *gt);
