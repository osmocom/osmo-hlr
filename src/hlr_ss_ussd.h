#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0480.h>

/* Represents a single USSE (either the internal, or an external) */
struct hlr_usse {
	/* list in the per-HLR list of USSEs */
	struct llist_head list;
	/* back-pointer to the HLR instance */
	struct hlr *hlr;
	/* human-readable description */
	const char *description;
	/* name (must match the IPA ID tag) */
	const char *name;
	/* list of USSD-code matching patterns */
	struct llist_head patterns;
};

/* Matching pattern types sorted by priority */
enum hlr_usse_pattern_type {
	HLR_USSE_PATTERN_CODE = 0, /* higher priority */
	HLR_USSE_PATTERN_REGEXP,
	HLR_USSE_PATTERN_PREFIX,
};

/* Represents a USSD-code matching pattern */
struct hlr_usse_pattern {
	/* link to the parent USSE */
	struct llist_head list;
	/* back-pointer to the parent USSE */
	struct hlr_usse *usse;
	/* Patter type, e.g. code, regexp or prefix */
	enum hlr_usse_pattern_type type;
	/* Mathing pattern, e.g. '*110*' for prefix */
	const char *pattern;
	/* Response format string, e.g. 'Your MSISDN is %m' */
	char *rsp_fmt;
};

struct hlr_usse *hlr_usse_find(struct hlr *hlr, const char *name);
struct hlr_usse *hlr_usse_alloc(struct hlr *hlr, const char *name);
void hlr_usse_del(struct hlr_usse *usse);

struct hlr_usse_pattern *hlr_usse_pattern_find(struct hlr_usse *usse,
	enum hlr_usse_pattern_type type, const char *pattern);
struct hlr_usse_pattern *hlr_usse_pattern_add(struct hlr_usse *usse,
	enum hlr_usse_pattern_type type, const char *pattern);
void hlr_usse_pattern_del(struct hlr_usse_pattern *pt);

void hlr_usse_clean_up(struct hlr *hlr);
