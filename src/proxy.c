
#include <sys/time.h>
#include <string.h>
#include <talloc.h>
#include <errno.h>

#include <osmocom/core/timer.h>

#include "proxy.h"

/* Why have a separate struct to add an llist_head entry?
 * This is to keep the option open to store the proxy data in the database instead, without any visible effect outside
 * of proxy.c. */
struct proxy_subscr_listentry {
	struct llist_head entry;
	struct timeval last_update;
	struct proxy_subscr data;
};

static LLIST_HEAD(proxy_subscr_list);
static void *proxy_ctx = NULL;

/* How long to keep proxy entries without a refresh, in seconds. */
static time_t proxy_fresh_time = 60 * 60;
static time_t proxy_fresh_check_period = 60;
static struct osmo_timer_list proxy_cleanup_timer;

/* Central implementation to set a timestamp to the current time, in case we want to modify this in the future. */
void timestamp_update(struct timeval *tv)
{
	osmo_gettimeofday(tv, NULL);
}

time_t timestamp_age(const struct timeval *last_update)
{
	struct timeval age;
	struct timeval now;
	timestamp_update(&now);
	timersub(&now, last_update, &age);
	return age.tv_sec;
}

static bool proxy_subscr_matches_imsi(const struct proxy_subscr *proxy_subscr, const char *imsi)
{
	if (!proxy_subscr || !imsi)
		return false;
	return strcmp(proxy_subscr->imsi, imsi) == 0;
}

static struct proxy_subscr_listentry *_proxy_get(const char *imsi)
{
	struct proxy_subscr_listentry *e;
	llist_for_each_entry(e, &proxy_subscr_list, entry) {
		if (proxy_subscr_matches_imsi(&e->data, imsi))
			return e;
	}
	return NULL;
}

const struct proxy_subscr *proxy_subscr_get(const char *imsi)
{
	struct proxy_subscr_listentry *e = _proxy_get(imsi);
	if (!e)
		return NULL;
	return &e->data;
}

int proxy_subscr_update(const struct proxy_subscr *proxy_subscr)
{
	struct proxy_subscr_listentry *e = _proxy_get(proxy_subscr->imsi);
	if (!e) {
		/* Does not exist yet */
		e = talloc_zero(proxy_ctx, struct proxy_subscr_listentry);
		llist_add(&e->entry, &proxy_subscr_list);
	}
	e->data = *proxy_subscr;
	timestamp_update(&e->last_update);
	return 0;
}

int _proxy_subscr_del(struct proxy_subscr_listentry *e)
{
	llist_del(&e->entry);
	return 0;
}

int proxy_subscr_del(const char *imsi)
{
	struct proxy_subscr_listentry *e = _proxy_get(imsi);
	if (!e)
		return -ENOENT;
	return _proxy_subscr_del(e);
}

/* Discard stale proxy entries. */
static void proxy_cleanup(void *ignore)
{
	struct proxy_subscr_listentry *e, *n;
	llist_for_each_entry_safe(e, n, &proxy_subscr_list, entry) {
		if (timestamp_age(&e->last_update) <= proxy_fresh_time)
			continue;
		_proxy_subscr_del(e);
	}
	osmo_timer_schedule(&proxy_cleanup_timer, proxy_fresh_check_period, 0);
}

void proxy_init(void *ctx)
{
	proxy_ctx = ctx;
	osmo_timer_setup(&proxy_cleanup_timer, &proxy_cleanup, NULL);
	/* Invoke to trigger the first timer schedule */
	proxy_cleanup(NULL);
}

