
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include "waiter.h"

#ifdef USE_PTHREADS

#include <pthread.h>
#include <signal.h>

struct waiter_timeout {
    struct timeval tv;
    struct waiter_timeout *prev;
    struct waiter_timeout *next;
};

struct waiter_s {
    struct selector_s *sel;
    int wake_sig;
    unsigned int count;
    pthread_mutex_t lock;
    struct waiter_timeout *wts;
};

waiter_t *alloc_waiter(struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter) {
	memset(waiter, 0, sizeof(*waiter));
	waiter->sel = sel;
	pthread_mutex_init(&waiter->lock, NULL);
    }
    return waiter;
}

void free_waiter(waiter_t *waiter)
{
    assert(waiter);
    assert(waiter->count == 0);
    assert(waiter->wts == NULL);
    pthread_mutex_destroy(&waiter->lock);
    free(waiter);
}

struct wait_data {
    pthread_t id;
    int wake_sig;
};

static void
wake_thread_send_sig(long thread_id, void *cb_data)
{
    struct wait_data *w = cb_data;

    pthread_kill(w->id, w->wake_sig);
}

void wait_for_waiter(waiter_t *waiter, unsigned int count)
{
    struct waiter_timeout wt;
    struct wait_data w;

    w.id = pthread_self();
    w.wake_sig = waiter->wake_sig;

    wt.tv.tv_sec = LONG_MAX;
    wt.next = NULL;
    wt.prev = NULL;
    pthread_mutex_lock(&waiter->lock);
    if (!waiter->wts) {
	waiter->wts = &wt;
    } else {
	waiter->wts->next->prev = &wt;
	wt.next = waiter->wts;
	waiter->wts = &wt;
    }
    while (waiter->count < count) {
	pthread_mutex_unlock(&waiter->lock);
	sel_select(waiter->sel, wake_thread_send_sig, (long) &w, NULL, NULL);
	pthread_mutex_lock(&waiter->lock);
    }
    waiter->count -= count;
    if (wt.next)
	wt.next->prev = wt.prev;
    if (waiter->wts == &wt)
	waiter->wts = wt.next;
    else
	wt.prev->next = wt.next;
    pthread_mutex_unlock(&waiter->lock);
}

void wake_waiter(waiter_t *waiter)
{
    struct waiter_timeout *wt;

    pthread_mutex_lock(&waiter->lock);
    waiter->count++;
    wt = waiter->wts;
    while (wt) {
	wt->tv.tv_sec = 0;
	wt = wt->next;
    }
    sel_wake_all(waiter->sel);
    pthread_mutex_unlock(&waiter->lock);
}
#else
struct waiter_s {
    unsigned int count;
};

waiter_t *alloc_waiter(struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter)
	memset(waiter, 0, sizeof(*waiter));
    return waiter;
}

void free_waiter(waiter_t *waiter)
{
    assert(waiter);
    assert(waiter->count == 0);
    free(waiter);
}

void wait_for_waiter(waiter_t *waiter, unsigned int count)
{
    while (waiter->count < count) {
	sel_select(waiter->sel, wake_thread_send_sig, long (&self), NULL, NULL);
    waiter->count -= count;
}

void wake_waiter(waiter_t *waiter)
{
    waiter->count++;
}
#endif
