//
// Created by Administrator on 2016/11/15.
//

#include "cache.h"


static void image_put_lossy(display_cache *cache, uint64_t id,
                            char *data) {

    LOGD("%s, id %"PRIu64"", __FUNCTION__, id);

    if (cache_find_images(cache, id) == NULL) {
        LOGD("%s, cache not found. id %"PRIu64"", __FUNCTION__, id);
    }

    cache_add_lossy_images(cache, id, data, TRUE);
}

static void image_put(display_cache *cache, uint64_t id, char *data) {

    LOGD("%s, data %p, id %"PRIu64"", __FUNCTION__, data, id);

    cache_add_images(cache, id, data);
}

void test_hash()
{
    display_cache *cache = cache_new_images(NULL);

    uint64_t key1 = 123;
    uint64_t key2 = 456;
    image_put(cache, key1, "aa");

    image_put_lossy(cache, key1, "bb");

    image_put_lossy(cache, key2, "22");

    image_put_lossy(cache, key2, "33");

    cache_clear_images(cache);
    cache_unref_images(cache);
}