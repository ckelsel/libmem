cmake_minimum_required(VERSION 3.4.1)

SET (SRC libnginx/core/nginx.c)
SET (SRC ${SRC} libnginx/core/ngx_log.c)
SET (SRC ${SRC} libnginx/core/ngx_palloc.c)
SET (SRC ${SRC} libnginx/core/ngx_array.c)
SET (SRC ${SRC} libnginx/core/ngx_list.c)
SET (SRC ${SRC} libnginx/core/ngx_hash.c)
SET (SRC ${SRC} libnginx/core/ngx_buf.c)
SET (SRC ${SRC} libnginx/core/ngx_queue.c)
SET (SRC ${SRC} libnginx/core/ngx_output_chain.c)
SET (SRC ${SRC} libnginx/core/ngx_string.c)
SET (SRC ${SRC} libnginx/core/ngx_parse.c)
SET (SRC ${SRC} libnginx/core/ngx_inet.c)
SET (SRC ${SRC} libnginx/core/ngx_file.c)
SET (SRC ${SRC} libnginx/core/ngx_crc32.c)
SET (SRC ${SRC} libnginx/core/ngx_murmurhash.c)
SET (SRC ${SRC} libnginx/core/ngx_md5.c)
SET (SRC ${SRC} libnginx/core/ngx_rbtree.c)
SET (SRC ${SRC} libnginx/core/ngx_radix_tree.c)
SET (SRC ${SRC} libnginx/core/ngx_slab.c)
SET (SRC ${SRC} libnginx/core/ngx_times.c)
SET (SRC ${SRC} libnginx/core/ngx_shmtx.c)
SET (SRC ${SRC} libnginx/core/ngx_connection.c)
SET (SRC ${SRC} libnginx/core/ngx_cycle.c)
SET (SRC ${SRC} libnginx/core/ngx_spinlock.c)
SET (SRC ${SRC} libnginx/core/ngx_cpuinfo.c)
SET (SRC ${SRC} libnginx/core/ngx_conf_file.c)
SET (SRC ${SRC} libnginx/core/ngx_resolver.c)
SET (SRC ${SRC} libnginx/core/ngx_open_file_cache.c)
SET (SRC ${SRC} libnginx/core/ngx_crypt.c)
SET (SRC ${SRC} libnginx/core/ngx_proxy_protocol.c)
SET (SRC ${SRC} libnginx/event/ngx_event.c)
SET (SRC ${SRC} libnginx/event/ngx_event_timer.c)
SET (SRC ${SRC} libnginx/event/ngx_event_posted.c)
SET (SRC ${SRC} libnginx/event/ngx_event_busy_lock.c)
SET (SRC ${SRC} libnginx/event/ngx_event_accept.c)
SET (SRC ${SRC} libnginx/event/ngx_event_connect.c)
SET (SRC ${SRC} libnginx/event/ngx_event_pipe.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_time.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_errno.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_alloc.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_files.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_socket.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_recv.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_readv_chain.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_udp_recv.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_send.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_writev_chain.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_channel.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_shmem.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_process.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_daemon.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_setaffinity.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_setproctitle.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_posix_init.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_user.c)
SET (SRC ${SRC} libnginx/os/unix/ngx_process_cycle.c)
SET (SRC ${SRC} libnginx/os/unix/glob.c)
SET (SRC ${SRC} libnginx/event/modules/ngx_select_module.c)
SET (SRC ${SRC} libnginx/event/modules/ngx_poll_module.c)
SET (SRC ${SRC} libnginx/ngx_modules.c)


SET(CMAKE_C_FLAGS " -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -g")
#SET(CMAKE_C_FLAGS " -pipe  -O2 -W -Wall -Wpointer-arith -Wno-unused-parameter")

INCLUDE_DIRECTORIES(libnginx/core)
INCLUDE_DIRECTORIES(libnginx/event)
INCLUDE_DIRECTORIES(libnginx/event/modules)
INCLUDE_DIRECTORIES(libnginx/os/unix)
INCLUDE_DIRECTORIES(libnginx/include)

INCLUDE_DIRECTORIES(C:\\Users\\Administrator\\Downloads\\ConverToAndroidStudio\\app\\gstreamer\\include\\glib-2.0)
INCLUDE_DIRECTORIES(C:\\Users\\Administrator\\Downloads\\ConverToAndroidStudio\\app\\gstreamer\\lib\\glib-2.0\\include)

link_directories(C:\\Users\\Administrator\\Downloads\\ConverToAndroidStudio\\app\\gstreamer\\lib)

add_library(nginx SHARED ${SRC})
target_link_libraries(nginx android log)

add_library(hello-jnicallback SHARED
    hello-jnicallback.c
    cache.c)

# Include libraries needed for lib
target_link_libraries(hello-jnicallback

a52
ass
avcodec
avformat
avutil
bz2
cairo-gobject
cairo-script-interpreter
cairo
charset
croco-0.6
dca
dv
expat
faad
ffi
FLAC
fontconfig
freetype
fribidi
gcrypt
gdk_pixbuf-2.0
ges-1.0
gio-2.0
glib-2.0
gmodule-2.0
gmp
gnustl
gnutls-openssl
gnutls
gobject-2.0
gpg-error
gstallocators-1.0
gstapp-1.0
gstaudio-1.0
gstbadbase-1.0
gstbadvideo-1.0
gstbase-1.0
gstbasecamerabinsrc-1.0
gstcheck-1.0
gstcodecparsers-1.0
gstcontroller-1.0
gstfft-1.0
gstgl-1.0
gstinsertbin-1.0
gstmpegts-1.0
gstnet-1.0
gstpbutils-1.0
gstphotography-1.0
gstreamer-1.0
gstriff-1.0
gstrtp-1.0
gstrtsp-1.0
gstrtspserver-1.0
gstsdp-1.0
gsttag-1.0
gsturidownloader-1.0
gstvalidate-1.0
gstvideo-1.0
gthread-2.0
harfbuzz
hogweed
iconv
intl
jpeg
kate
mad
mms
mpeg2
mpeg2convert
nettle
ogg
oggkate
opencore-amrnb
opencore-amrwb
opus
orc-0.4
orc-test-0.4
pango-1.0
pangocairo-1.0
pangoft2-1.0
pixman-1
png16
rsvg-2
rtmp
schroedinger-1.0
SoundTouch
soup-2.4
speex
speexdsp
supc++
swscale
tag
tasn1
theora
theoradec
theoraenc
tiff
visual-0.4
vo-aacenc
vorbis
vorbisenc
vorbisfile
vorbisidec
vpx
wavpack
x264
xml2
z

                        nginx
                      android
                      glib-2.0
                      iconv
                      log)
