
#include <sys/time.h>
#include <string.h>
#include <talloc.h>
#include <errno.h>

#include <osmocom/core/timer.h>

#include "logging.h"
#include "proxy.h"

/* Why have a separate struct to add an llist_head entry?
 * This is to keep the option open to store the proxy data in the database instead, without any visible effect outside
 * of proxy.c. */
struct proxy_subscr_listentry {
	struct llist_head entry;
	struct timeval last_update;
	struct proxy_subscr data;
};

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

static bool proxy_subscr_matches_msisdn(const struct proxy_subscr *proxy_subscr, const char *msisdn)
{
	if (!proxy_subscr || !msisdn)
		return false;
	return strcmp(proxy_subscr->msisdn, msisdn) == 0;
}

static struct proxy_subscr_listentry *_proxy_get_by_imsi(struct proxy *proxy, const char *imsi)
{
	struct proxy_subscr_listentry *e;
	llist_for_each_entry(e, &proxy->subscr_list, entry) {
		if (proxy_subscr_matches_imsi(&e->data, imsi))
			return e;
	}
	return NULL;
}

static struct proxy_subscr_listentry *_proxy_get_by_msisdn(struct proxy *proxy, const char *msisdn)
{
	struct proxy_subscr_listentry *e;
	llist_for_each_entry(e, &proxy->subscr_list, entry) {
		if (proxy_subscr_matches_msisdn(&e->data, msisdn))
			return e;
	}
	return NULL;
}

const struct proxy_subscr *proxy_subscr_get_by_imsi(struct proxy *proxy, const char *imsi)
{
	struct proxy_subscr_listentry *e = _proxy_get_by_imsi(proxy, imsi);
	if (!e)
		return NULL;
	return &e->data;
}

const struct proxy_subscr *proxy_subscr_get_by_msisdn(struct proxy *proxy, const char *msisdn)
{
	struct proxy_subscr_listentry *e = _proxy_get_by_msisdn(proxy, msisdn);
	if (!e)
		return NULL;
	return &e->data;
}

void proxy_subscrs_get_by_remote_hlr(struct proxy *proxy, const struct osmo_sockaddr_str *remote_hlr_addr,
				     bool (*yield)(struct proxy *proxy, const struct proxy_subscr *subscr, void *data),
				     void *data)
{
	struct proxy_subscr_listentry *e;
	llist_for_each_entry(e, &proxy->subscr_list, entry) {
		if (!osmo_sockaddr_str_ip_cmp(remote_hlr_addr, &e->data.remote_hlr_addr)) {
			if (!yield(proxy, &e->data, data))
				return;
		}
	}
}

int proxy_subscr_update(struct proxy *proxy, const struct proxy_subscr *proxy_subscr)
{
	struct proxy_subscr_listentry *e = _proxy_get_by_imsi(proxy, proxy_subscr->imsi);
	if (!e) {
		/* Does not exist yet */
		e = talloc_zero(proxy, struct proxy_subscr_listentry);
		llist_add(&e->entry, &proxy->subscr_list);
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

int proxy_subscr_del(struct proxy *proxy, const char *imsi)
{
	struct proxy_subscr_listentry *e = _proxy_get_by_imsi(proxy, imsi);
	if (!e)
		return -ENOENT;
	return _proxy_subscr_del(e);
}

/* Discard stale proxy entries. */
static void proxy_cleanup(void *proxy_v)
{
	struct proxy *proxy = proxy_v;
	struct proxy_subscr_listentry *e, *n;
	llist_for_each_entry_safe(e, n, &proxy->subscr_list, entry) {
		if (timestamp_age(&e->last_update) <= proxy->fresh_time)
			continue;
		_proxy_subscr_del(e);
	}
	if (proxy->gc_period)
		osmo_timer_schedule(&proxy->gc_timer, proxy->gc_period, 0);
	else
		LOGP(DDGSM, LOGL_NOTICE, "Proxy cleanup is switched off (gc_period == 0)\n");
}

void proxy_set_gc_period(struct proxy *proxy, uint32_t gc_period)
{
	proxy->gc_period = gc_period;
	proxy_cleanup(proxy);
}

struct proxy *proxy_init(void *ctx)
{
	struct proxy *proxy = talloc_zero(ctx, struct proxy);
	*proxy = (struct proxy){
		.fresh_time = 60*60,
		.gc_period = 60,
	};
	INIT_LLIST_HEAD(&proxy->subscr_list);

	osmo_timer_setup(&proxy->gc_timer, proxy_cleanup, proxy);
	/* Invoke to trigger the first timer schedule */
	proxy_set_gc_period(proxy, proxy->gc_period);
	return proxy;
}

void proxy_del(struct proxy *proxy)
{
	osmo_timer_del(&proxy->gc_timer);
	talloc_free(proxy);
}
