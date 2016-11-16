//
// Created by Administrator on 2016/11/15.
//

#ifndef LIBMEM_CACHE_H
#define LIBMEM_CACHE_H

#include "debug.h"
#include <glib.h>
#include <inttypes.h> /* For PRIx64 */

static GMutex *images_cache_lock = NULL;

typedef struct display_cache_item {
    guint64                     id;
    gboolean                    lossy;
} display_cache_item;


typedef GHashTable display_cache;


static inline display_cache_item* cache_item_new(guint64 id, gboolean lossy)
{
    display_cache_item *self = g_slice_new(display_cache_item);

    LOGD("%s, malloc: %p", __FUNCTION__, self);
    self->id = id;
    self->lossy = lossy;
    return self;
}

static inline void cache_item_free(display_cache_item *self)
{
    LOGD("%s, free: %p", __FUNCTION__, self);
    g_slice_free(display_cache_item, self);
}


static inline display_cache* cache_new_images(GDestroyNotify value_destroy)
{
    GHashTable* self;

    if(images_cache_lock == NULL){
        images_cache_lock = g_mutex_new();
        LOGD("%s images_cache_lock new %p", __FUNCTION__, images_cache_lock);
    }

    self = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                 (GDestroyNotify)cache_item_free,
                                 value_destroy);
    return self;
}


static inline gpointer cache_find_images(display_cache *cache, uint64_t id)
{
    g_mutex_lock(images_cache_lock);
    gpointer p = g_hash_table_lookup(cache, &id);
    g_mutex_unlock(images_cache_lock);
    return p;
}


static inline gpointer cache_find_lossy_images(display_cache *cache, uint64_t id, gboolean *lossy)
{
    g_mutex_lock(images_cache_lock);
    gpointer value;
    display_cache_item *item;

    if (!g_hash_table_lookup_extended(cache, &id, (gpointer*)&item, &value)){
        g_mutex_unlock(images_cache_lock);
        return NULL;
    }

    *lossy = item->lossy;

    g_mutex_unlock(images_cache_lock);
    return value;
}


static inline void cache_add_lossy_images(display_cache *cache, uint64_t id,
                            gpointer value, gboolean lossy)
{
    g_mutex_lock(images_cache_lock);
    display_cache_item *item = cache_item_new(id, lossy);
    g_hash_table_replace(cache, item, value);
    g_mutex_unlock(images_cache_lock);
}


static inline void cache_add_images(display_cache *cache, uint64_t id, gpointer value)
{
    cache_add_lossy_images(cache, id, value, FALSE);
}


static inline void cache_clear_images(display_cache *cache)
{
    g_mutex_lock(images_cache_lock);
    g_hash_table_remove_all(cache);
    g_mutex_unlock(images_cache_lock);
}


static inline void cache_unref_images(display_cache *cache)
{
    g_mutex_lock(images_cache_lock);
    g_hash_table_unref(cache);
    g_mutex_unlock(images_cache_lock);

    LOGD("%s images_cache_lock free %p", __FUNCTION__, images_cache_lock);
    g_mutex_free(images_cache_lock);
    images_cache_lock = NULL;
}

void test_hash();
#endif //LIBMEM_CACHE_H
