#include <errno.h>
#include <string.h>
#include <osmocom/core/utils.h>
#include "global_title.h"

int global_title_set(struct global_title *gt, const uint8_t *val, size_t len)
{
	if (!val || !len) {
		*gt = (struct global_title){};
		return 0;
	}
	if (len > sizeof(gt->val))
		return -ENOSPC;
	gt->len = len;
	memcpy(gt->val, val, len);
	return 0;
}

int global_title_set_str(struct global_title *gt, const char *str_fmt, ...)
{
	va_list ap;
	if (!str_fmt)
		return global_title_set(gt, NULL, 0);

	va_start(ap, str_fmt);
	vsnprintf((char*)(gt->val), sizeof(gt->val), str_fmt, ap);
	va_end(ap);
	gt->len = strlen((char*)(gt->val))+1;
	return 0;
}

int global_title_cmp(const struct global_title *a, const struct global_title *b)
{
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	if (!a->len && !b->len)
		return 0;
	if (!a->len && b->len)
		return -1;
	if (!b->len && a->len)
		return 1;

	if (a->len == b->len)
		return memcmp(a->val, b->val, a->len);
	else if (a->len < b->len) {
		cmp = memcmp(a->val, b->val, a->len);
		if (!cmp)
			cmp = -1;
		return cmp;
	} else {
		/* a->len > b->len */
		cmp = memcmp(a->val, b->val, b->len);
		if (!cmp)
			cmp = 1;
		return cmp;
	}
}

const char *global_title_name(const struct global_title *gt)
{
	return osmo_quote_str_c(OTC_SELECT, (char*)gt->val, gt->len);
}

