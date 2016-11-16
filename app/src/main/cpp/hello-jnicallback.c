/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <string.h>
#include <pthread.h>
#include <jni.h>
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_log.h>
#include "debug.h"
#include "cache.h"

#define spice_malloc(n_bytes) __spice_malloc(n_bytes, __FUNCTION__, __LINE__)
void *__spice_malloc(int n_bytes, char *func, int line)
{
    void *p = malloc(n_bytes);
    LOGI("%s::%d: malloc %p\n", func, line, p);
    return p;
}


#define SIZE_512 512
#define SIZE_1K 1024
#define SIZE_100K (SIZE_1K * 100)
#define SIZE_200K (SIZE_1K * 200)

#define MALLOC_SIZE (SIZE_1K * SIZE_1K)

#define POOL_SIZE SIZE_512

#define ARRAY_MAX   1524
int test_malloc()
{
    void *p = spice_malloc(100);
    void *d[ARRAY_MAX];
    int i;
    const u_char     *prefix = "/data/";
    ngx_log_t        *log;
    ngx_cycle_t      *cycle, init_cycle;

    ngx_debug_init();

    if (ngx_strerror_init() != NGX_OK)
    {
        LOGE("ngx_strerror_init failed");
        return -1;
    }

    ngx_time_init();

    log = ngx_log_init(prefix);
    if (log == NULL)
    {
        LOGE("ngx_log_init failed, prefix = %s", prefix);
        return -1;
    }
    log->log_level = NGX_LOG_DEBUG_ALLOC;
    ngx_create_dir("/data/logs", 0777);

    /*
    * init_cycle->log is required for signal handlers and
    * ngx_process_options()
    */
    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    init_cycle.pool = ngx_create_pool(1024, log);
    if (init_cycle.pool == NULL) {
        LOGE("ngx_create_pool failed");
        return -1;
    }

    if (ngx_os_init(log) != NGX_OK) {
        LOGE("ngx_os_init failed");
        return -1;
    }
    /*
     * ngx_crc32_table_init() requires ngx_cacheline_size set in ngx_os_init()
     */

    if (ngx_crc32_table_init() != NGX_OK) {
        LOGE("ngx_crc32_table_init failed");
        return -1;
    }

    ngx_max_module = 0;
    for (i = 0; ngx_modules[i]; i++) {
        ngx_modules[i]->index = ngx_max_module++;
    }

    cycle = &init_cycle; //ngx_init_cycle(&init_cycle);
    if (cycle == NULL) {
        LOGE("ngx_init_cycle failed");
        return -1;
    }

    ngx_os_status(log);
    ngx_cycle = cycle;

    if (ngx_init_signals(cycle->log) != NGX_OK) {
        LOGE("ngx_init_signals failed");
        return -1;
    }

    LOGI("pid %d\n", getpid());
    ngx_pool_t *pool = cycle->pool;
    if (pool == NULL)
    {
        LOGE("ngx_create_pool null\n");
        return -1;
    }

#if (ENABLE_REALLOC)
    {
        void *p = ngx_prealloc(pool, NULL, 10);
        assert(p);

        p = ngx_prealloc(pool, p, 20);

        p = ngx_prealloc(pool, p, 10);

        p = ngx_prealloc(pool, p, 0);
        assert(!p);

        ngx_pfree(pool, p);

        p = ngx_palloc(pool, 10);
        assert(p);

        p = ngx_prealloc(pool, p, 10);
        assert(p);

        ngx_pfree(pool, p);
    }
#endif

    int loop = 30;
    LOGI("Enter Main Loop %d", loop);
    while ( --loop > 0 )
    {
        LOGI("Enter Loop %d", loop);

        for ( i = 0; i < ARRAY_MAX; i++ )
        {
            d[i] = ngx_pcalloc(pool, rand() % MALLOC_SIZE);
            LOGD("[%d] malloc %p", i, d[i]);

            ngx_pfree(pool, d[i]);
        }


#if (ENABLE_REALLOC)
        for ( i = 0; i < ARRAY_MAX; i++ )
        {
            d[i] = ngx_prealloc(pool, d[i], rand() % MALLOC_SIZE);
            LOGD("[%d] realloc %p", i, d[i]);

            ngx_pfree(pool, d[i]);
        }
#endif

        for ( i = 0; i < ARRAY_MAX; i++ )
        {
            LOGD("[%d] free %p", i, d[i]);
            ngx_pfree(pool, d[i]);
        }

        LOGI("Leave Loop %d", loop);
    }
    LOGI("Leave Main Loop %d", loop);

#if (ENABLE_MEMORY_LEAK_CHECK)
    {
        for ( i = 0; i < 2; i++ )
        {
            d[i] = ngx_palloc(pool, rand() % MALLOC_SIZE);
            LOGD("[%d] malloc %p", i, d[i]);
        }
    }
#endif

    ngx_destroy_pool(pool);
    return 0;
}


void test()
{
    test_hash();
    //test_malloc();
}

// processing callback to handler class
typedef struct tick_context {
    JavaVM  *javaVM;
    jclass   jniHelperClz;
    jobject  jniHelperObj;
    jclass   mainActivityClz;
    jobject  mainActivityObj;
    pthread_mutex_t  lock;
    int      done;
} TickContext;
TickContext g_ctx;

/* This is a trivial JNI example where we use a native method
 * to return a new VM String. See the corresponding Java source
 * file located at:
 *
 *   hello-jniCallback/app/src/main/java/com/example/hellojnicallback/MainActivity.java
 */
JNIEXPORT jstring JNICALL
Java_com_example_hellojnicallback_MainActivity_stringFromJNI( JNIEnv* env, jobject thiz )
{
#if defined(__arm__)
    #if defined(__ARM_ARCH_7A__)
    #if defined(__ARM_NEON__)
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a/NEON (hard-float)"
      #else
        #define ABI "armeabi-v7a/NEON"
      #endif
    #else
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a (hard-float)"
      #else
        #define ABI "armeabi-v7a"
      #endif
    #endif
  #else
   #define ABI "armeabi"
  #endif
#elif defined(__i386__)
#define ABI "x86"
#elif defined(__x86_64__)
#define ABI "x86_64"
#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
#define ABI "mips64"
#elif defined(__mips__)
#define ABI "mips"
#elif defined(__aarch64__)
#define ABI "arm64-v8a"
#else
#define ABI "unknown"
#endif


    test();

    return (*env)->NewStringUTF(env, "Hello from JNI !  Compiled with ABI " ABI ".");
}

/*
 *  A helper function to show how to call
 *     java static functions JniHelper::getBuildVersion()
 *     java non-static function JniHelper::getRuntimeMemorySize()
 *  The trivial implementation for these functions are inside file
 *     JniHelper.java
 */
void queryRuntimeInfo(JNIEnv *env, jobject instance) {
    // Find out which OS we are running on. It does not matter for this app
    // just to demo how to call static functions.
    // Our java JniHelper class id and instance are initialized when this
    // shared lib got loaded, we just directly use them
    //    static function does not need instance, so we just need to feed
    //    class and method id to JNI
    jmethodID versionFunc = (*env)->GetStaticMethodID(
            env, g_ctx.jniHelperClz,
            "getBuildVersion", "()Ljava/lang/String;");
    if (!versionFunc) {
        LOGE("Failed to retrieve getBuildVersion() methodID @ line %d",
             __LINE__);
        return;
    }
    jstring buildVersion = (*env)->CallStaticObjectMethod(env,
                                                          g_ctx.jniHelperClz, versionFunc);
    const char *version = (*env)->GetStringUTFChars(env, buildVersion, NULL);
    if (!version) {
        LOGE("Unable to get version string @ line %d", __LINE__);
        return;
    }
    LOGI("Android Version - %s", version);
    (*env)->ReleaseStringUTFChars(env, buildVersion, version);

    // we are called from JNI_OnLoad, so got to release LocalRef to avoid leaking
    (*env)->DeleteLocalRef(env, buildVersion);

    // Query available memory size from a non-static public function
    // we need use an instance of JniHelper class to call JNI
    jmethodID memFunc = (*env)->GetMethodID(env, g_ctx.jniHelperClz,
                                            "getRuntimeMemorySize", "()J");
    if (!memFunc) {
        LOGE("Failed to retrieve getRuntimeMemorySize() methodID @ line %d",
             __LINE__);
        return;
    }
    jlong result = (*env)->CallLongMethod(env, instance, memFunc);
    LOGI("Runtime free memory size: %lld", result);
    (void)result;  // silence the compiler warning
}

/*
 * processing one time initialization:
 *     Cache the javaVM into our context
 *     Find class ID for JniHelper
 *     Create an instance of JniHelper
 *     Make global reference since we are using them from a native thread
 * Note:
 *     All resources allocated here are never released by application
 *     we rely on system to free all global refs when it goes away;
 *     the pairing function JNI_OnUnload() never gets called at all.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    memset(&g_ctx, 0, sizeof(g_ctx));

    g_ctx.javaVM = vm;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR; // JNI version not supported.
    }

    jclass  clz = (*env)->FindClass(env,
                                    "com/example/hellojnicallback/JniHandler");
    g_ctx.jniHelperClz = (*env)->NewGlobalRef(env, clz);

    jmethodID  jniHelperCtor = (*env)->GetMethodID(env, g_ctx.jniHelperClz,
                                                   "<init>", "()V");
    jobject    handler = (*env)->NewObject(env, g_ctx.jniHelperClz,
                                           jniHelperCtor);
    g_ctx.jniHelperObj = (*env)->NewGlobalRef(env, handler);
    queryRuntimeInfo(env, g_ctx.jniHelperObj);

    g_ctx.done = 0;
    g_ctx.mainActivityObj = NULL;
    return  JNI_VERSION_1_6;
}

/*
 * A helper function to wrap java JniHelper::updateStatus(String msg)
 * JNI allow us to call this function via an instance even it is
 * private function.
 */
void   sendJavaMsg(JNIEnv *env, jobject instance,
                   jmethodID func,const char* msg) {
    jstring javaMsg = (*env)->NewStringUTF(env, msg);
    (*env)->CallVoidMethod(env, instance, func, javaMsg);
    (*env)->DeleteLocalRef(env, javaMsg);
}

/*
 * Main working thread function. From a pthread,
 *     calling back to MainActivity::updateTimer() to display ticks on UI
 *     calling back to JniHelper::updateStatus(String msg) for msg
 */
void*  UpdateTicks(void* context) {
    TickContext *pctx = (TickContext*) context;
    JavaVM *javaVM = pctx->javaVM;
    JNIEnv *env;
    jint res = (*javaVM)->GetEnv(javaVM, (void**)&env, JNI_VERSION_1_6);
    if (res != JNI_OK) {
        res = (*javaVM)->AttachCurrentThread(javaVM, &env, NULL);
        if (JNI_OK != res) {
            LOGE("Failed to AttachCurrentThread, ErrorCode = %d", res);
            return NULL;
        }
    }

    jmethodID statusId = (*env)->GetMethodID(env, pctx->jniHelperClz,
                                             "updateStatus",
                                             "(Ljava/lang/String;)V");
    sendJavaMsg(env, pctx->jniHelperObj, statusId,
                "TickerThread status: initializing...");

    // get mainActivity updateTimer function
    jmethodID timerId = (*env)->GetMethodID(env, pctx->mainActivityClz,
                                            "updateTimer", "()V");

    struct timeval beginTime, curTime, usedTime, leftTime;
    const struct timeval kOneSecond = {
            (__kernel_time_t)1,
            (__kernel_suseconds_t) 0
    };

    sendJavaMsg(env, pctx->jniHelperObj, statusId,
                "TickerThread status: start ticking ...");
    while(1) {
        gettimeofday(&beginTime, NULL);
        pthread_mutex_lock(&pctx->lock);
        int done = pctx->done;
        if (pctx->done) {
            pctx->done = 0;
        }
        pthread_mutex_unlock(&pctx->lock);
        if (done) {
            break;
        }
        (*env)->CallVoidMethod(env, pctx->mainActivityObj, timerId);

        gettimeofday(&curTime, NULL);
        timersub(&curTime, &beginTime, &usedTime);
        timersub(&kOneSecond, &usedTime, &leftTime);
        struct timespec sleepTime;
        sleepTime.tv_sec = leftTime.tv_sec;
        sleepTime.tv_nsec = leftTime.tv_usec * 1000;

        if (sleepTime.tv_sec <= 1) {
            nanosleep(&sleepTime, NULL);
        } else {
            sendJavaMsg(env, pctx->jniHelperObj, statusId,
                        "TickerThread error: processing too long!");
        }
    }

    sendJavaMsg(env, pctx->jniHelperObj, statusId,
                "TickerThread status: ticking stopped");
    (*javaVM)->DetachCurrentThread(javaVM);
    return context;
}

/*
 * Interface to Java side to start ticks, caller is from onResume()
 */
JNIEXPORT void JNICALL
Java_com_example_hellojnicallback_MainActivity_startTicks(JNIEnv *env, jobject instance) {
    pthread_t       threadInfo_;
    pthread_attr_t  threadAttr_;

    pthread_attr_init(&threadAttr_);
    pthread_attr_setdetachstate(&threadAttr_, PTHREAD_CREATE_DETACHED);

    pthread_mutex_init(&g_ctx.lock, NULL);

    jclass clz = (*env)->GetObjectClass(env, instance);
    g_ctx.mainActivityClz = (*env)->NewGlobalRef(env, clz);
    g_ctx.mainActivityObj = (*env)->NewGlobalRef(env, instance);

    int result  = pthread_create( &threadInfo_, &threadAttr_, UpdateTicks, &g_ctx);
    assert(result == 0);
    (void)result;
}

/*
 * Interface to Java side to stop ticks:
 *    we need to hold and make sure our native thread has finished before return
 *    for a clean shutdown. The caller is from onPause
 */
JNIEXPORT void JNICALL
Java_com_example_hellojnicallback_MainActivity_StopTicks(JNIEnv *env, jobject instance) {
    pthread_mutex_lock(&g_ctx.lock);
    g_ctx.done = 1;
    pthread_mutex_unlock(&g_ctx.lock);

    // waiting for ticking thread to flip the done flag
    struct timespec sleepTime;
    memset(&sleepTime, 0, sizeof(sleepTime));
    sleepTime.tv_nsec = 100000000;
    while (g_ctx.done) {
        nanosleep(&sleepTime, NULL);
    }

    // release object we allocated from StartTicks() function
    (*env)->DeleteGlobalRef(env, g_ctx.mainActivityClz);
    (*env)->DeleteGlobalRef(env, g_ctx.mainActivityObj);
    g_ctx.mainActivityObj = NULL;
    g_ctx.mainActivityClz = NULL;

    pthread_mutex_destroy(&g_ctx.lock);
}
