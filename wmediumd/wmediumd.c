/*
 *	wmediumd, wireless medium simulator for mac80211_hwsim kernel module
 *	Copyright (c) 2011 cozybit Inc.
 *
 *	Author:	Javier Lopez	<jlopex@cozybit.com>
 *		Javier Cardona	<javier@cozybit.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *	02110-1301, USA.
 */

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <stdint.h>
#include <getopt.h>
#include <signal.h>
#include <event.h>
#include <sys/timerfd.h>

#include "wmediumd.h"
#include "ieee80211.h"
#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <assert.h>
#include <pthread.h>
#include <netdb.h>
#include "../thpool/thpool.h"
#include <sys/sysinfo.h>

#include "message.h"

#define BUF_SIZE 65536

// otherwise use TCP!
#define SOCK_OPT_MCAST
#define MCAST_GROUP "239.0.0.1"

//#define TCP_SMALL_WRITE

/* valgrind performance study PERFECT_CHANNEL_NO_QUEUES:
    424,411,339  /build/glibc-GKVZIf/glibc-2.23/stdio-common/vfscanf.c:_IO_vfscanf [/lib/x86_64-linux-gnu/libc-2.23.so]
    227,856,759  /build/glibc-GKVZIf/glibc-2.23/stdio-common/vfprintf.c:vfprintf [/lib/x86_64-linux-gnu/libc-2.23.so]
    172,096,216  /build/glibc-GKVZIf/glibc-2.23/libio/fileops.c:_IO_file_xsputn@@GLIBC_2.2.5 [/lib/x86_64-linux-gnu/libc-2.23.so]
    169,167,248  /build/glibc-GKVZIf/glibc-2.23/stdlib/../stdlib/strtol_l.c:____strtoul_l_internal [/lib/x86_64-linux-gnu/libc-2.23.so]
    130,125,990  /build/glibc-GKVZIf/glibc-2.23/malloc/malloc.c:_int_malloc [/lib/x86_64-linux-gnu/libc-2.23.so]
    126,249,859  /build/glibc-GKVZIf/glibc-2.23/string/../sysdeps/x86_64/multiarch/../memset.S:__GI_memset [/lib/x86_64-linux-gnu/libc-2.23.so]
*/
// variadric macro -> valgrind
//#define DEBUG

#ifdef DEBUG
    #define MY_PRINTF(f_, ...) printf((f_), ##__VA_ARGS__)
#else
    #define MY_PRINTF(f_, ...)
#endif

static struct wmediumd *wmediumd;
uint8_t local_mac_addr[6];

//////////////////////////////////////////////////////////////////////////////
// Memory allocation
//////////////////////////////////////////////////////////////////////////////

static inline void* mymalloc_random(size_t size) {
    void *ptr = malloc(size);
    if(!ptr) {
        perror("Could not malloc memory: \n");
        exit(1);
    }
    return ptr;
}

static inline void* mymalloc_zero(size_t size) {
    void *ptr = calloc(1, size);
    if(!ptr) {
        perror("Could not malloc memory: \n");
        exit(1);
    }
    return ptr;
}

static inline void* mycalloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if(!ptr) {
        perror("Could not malloc memory: \n");
        exit(1);
    }
    return ptr;
}

//////////////////////////////////////////////////////////////////////////////
// Socket checking
//////////////////////////////////////////////////////////////////////////////

static inline void check_recv_call(int retcode) {
    if(retcode < 0) {
        // TODO: how to use perror here?
        fprintf(stderr, "socket recv error!\n");
        exit(1);
    }
}

//////////////////////////////////////////////////////////////////////////////
// MAC stuff
//////////////////////////////////////////////////////////////////////////////

static inline bool is_multicast_ether_addr(const u8 *addr)
{
//	MY_PRINTF("is_multicast_ether_addr: %d\n", 0x01 & addr[0]);
	return 0x01 & addr[0];
}

void remember_local_mac() {

    FILE *fd;

    unsigned int values[6];

    char *path_to_mac_addr = "/sys/class/net/wlan0/address";
    fd = fopen(path_to_mac_addr, "r");
    if (fd == NULL) {
        fprintf(stderr, "Could not open '%s'\n", path_to_mac_addr);
        exit(1);
    }

    fscanf(fd, "%X:%X:%X:%X:%X:%X", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);
    /* convert to uint8_t */
    for( int i = 0; i < 6; ++i ) {
        local_mac_addr[i] = (uint8_t) values[i];
    }

    fclose(fd);
}

// TODO: make more generic
static inline bool is_local_mac(uint8_t *mac) {

	return memcmp(mac, local_mac_addr, 6) == 0;
}

//////////////////////////////////////////////////////////////////////////////
// Network receiving methods
//////////////////////////////////////////////////////////////////////////////
/**
 * Receive a `struct frame` from the socket.
 * NOTE: the caller is responsible for freeing up the space!
 */

#ifdef SOCK_OPT_MCAST
static inline struct frame** recv_frame(int socket) {
	ssize_t len;
	char buffer[BUF_SIZE];

	len = recv(socket, buffer, BUF_SIZE, 0);
	if(0 >= len) {
		perror("socket recv error: \n");
		exit(1);
	}
	MY_PRINTF("Received frame with length: %ld\n", len);

	// we can safely allocate memory with random bytes because after memcpy they could be random again!
	struct frame *frame = mymalloc_random(len);
	memcpy(frame, buffer, len);

	return frame;
}
#else
struct frame** recv_frame(int socket) {

	ssize_t len = 0;
	ssize_t ret_code;

//	fd_set rfds;
//
//	MY_PRINTF("waiting for select ...\n");
//	FD_ZERO(&rfds);
//	FD_SET(socket, &rfds);
//
//	if (0 >= select(FD_SETSIZE, &rfds, NULL, NULL, NULL)) {
//		perror("select()");
//		return EXIT_FAILURE;
//	}
	uint16_t frame_size;
	ret_code = recv(socket, &frame_size, sizeof(frame_size), MSG_WAITALL);
   	check_recv_call(ret_code == sizeof(frame_size) && ret_code > 0);
	len += ret_code;
	MY_PRINTF("len: %d\n", len);
	MY_PRINTF(">>> frame size: %d\n", frame_size);

	char *buffer = mymalloc_random(frame_size);
	memcpy(buffer, &frame_size, sizeof(frame_size));

	// recv rest of frame
	size_t rest_of_frame_size = frame_size - sizeof(frame_size);
	ret_code = recv(socket, buffer + sizeof(frame_size), rest_of_frame_size, MSG_WAITALL);
	check_recv_call(ret_code == (ssize_t)rest_of_frame_size && ret_code > 0);
	len += ret_code;
	MY_PRINTF("Received frame with length: %ld\n", len);



	return (struct frame*)buffer;
}
#endif

//////////////////////////////////////////////////////////////////////////////
// Socket creation/connection/binding/teardown
//////////////////////////////////////////////////////////////////////////////

int connect_frame_distribution_socket() {
	MY_PRINTF("connecting socket ...\n");

	// Socket address, internet style
	struct sockaddr_in addr;

#ifdef SOCK_OPT_MCAST
	struct ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr(MCAST_GROUP);
	// TODO: listen only on configurable interface
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);

	// TODO: use raw socket!
	mysocket = socket(AF_INET, SOCK_DGRAM, 0);

	// disable receiving of own packets
	int loop = 0;
	setsockopt(mysocket, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

#else
	mysocket = socket(AF_INET, SOCK_STREAM, 0);
	#ifdef TCP_SMALL_WRITE
	int one = 1;

	setsockopt(mysocket, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
	#endif
#endif

    int reuse = 1;
    if (setsockopt(mysocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }
	if(0 > mysocket) {
		fprintf(stderr, "Error: Could not create socket!\n");
		return EXIT_FAILURE;
	}

	// zero struct
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	// TODO: listen only on configurable interface
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(PORTNUM);

#ifdef SOCK_OPT_MCAST
	if(0 > bind(mysocket, (struct sockaddr*) &addr, sizeof(addr))) {
#else
	// TODO: remove hardcoded IP addresses and use CLI instead
	unsigned long ip_addr = inet_addr("172.21.0.254");
	memcpy( (char *)&addr.sin_addr, &ip_addr, sizeof(ip_addr));

	if(0 > connect(mysocket, (struct sockaddr *)&addr, sizeof(addr))) {
#endif
		perror("Connect Failed\n");
		return EXIT_FAILURE;
	}
#ifdef SOCK_OPT_MCAST
	else {
		// TODO: use same var as s.addr!
		fprintf(stderr, "bound to %d\n", htonl(INADDR_ANY));
	}
	// add mcast membership
	if (setsockopt(mysocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		perror("setsockopt mreq\n");
		exit(1);
	}
#endif

	//fcntl(mysocket, F_SETFL, O_NONBLOCK);
	return EXIT_SUCCESS;
}

int disconnect_frame_distribution_socket() {
	// TODO: how to handle close and free if returned by error?
	close(mysocket);
	return EXIT_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
//// Frame (de)serialization
////////////////////////////////////////////////////////////////////////////////
//
static inline struct station *get_sender_station_by_index(unsigned int index) {
	struct station *cur_station;
	list_for_each_entry(cur_station, &wmediumd->stations, list) {
		if(cur_station->index == index) {
			return cur_station;
		}
	}
	// TODO: fprintf with format string?
	printf("Station not found for index: %d\n", index);
	exit(1);

	return NULL;
}

//
///**
// * Serialize frame by copying all pointers content.
// * The station struct is replaced by it's index.
// * NOTE: caller has the responsibility to free!
// */
//struct frame_copy* frame_serialize(struct frame *frame) {
//	int total_struct_length = sizeof(struct frame_copy) + frame->data_len;
//	struct frame_copy *frame_copy = mymalloc_zero(total_struct_length);
//
//	frame_copy->expires.tv_sec = frame->expires.tv_sec;
//	frame_copy->expires.tv_nsec = frame->expires.tv_nsec;
//
//	frame_copy->acked = frame->acked;
//	frame_copy->cookie = frame->cookie;
//	frame_copy->flags = frame->flags;
//	frame_copy->signal = frame->signal;
//	frame_copy->tx_rates_count = frame->tx_rates_count;
//	// copy index of station instead of whole structure
//	frame_copy->sender = frame->sender->index;
//
//	// copy array value by value
//	for(int i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
//		frame_copy->tx_rates[i] = frame->tx_rates[i];
//	}
//
//	frame_copy->data_len = frame->data_len;
//
//	// copy data array
//	memcpy(frame_copy->data, frame->data, frame->data_len);
//
//	frame_copy->total_struct_length = total_struct_length;
//
//	return frame_copy;
//}
//
///**
// * Deserialize a frame and get the station from the index.
// */
//struct frame* frame_deserialization(struct frame_copy *frame_copy) {
//	struct frame *frame = mymalloc_zero(sizeof(struct frame) + frame_copy->data_len);
//
//	frame->expires.tv_sec = frame_copy->expires.tv_sec;
//	frame->expires.tv_nsec = frame_copy->expires.tv_nsec;
//
//	frame->acked = frame_copy->acked;
//	frame->cookie = frame_copy->cookie;
//	frame->flags = frame_copy->flags;
//	frame->signal = frame_copy->signal;
//	frame->tx_rates_count = frame_copy->tx_rates_count;
//	// copy index of station instead of whole structure
//	frame->sender = get_sender_station_by_index(frame_copy->sender);
//	if(!frame->sender) {
//		fprintf(stderr, "frame_deserialization: \n");
//	}
//
//	for(int i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
//		frame->tx_rates[i] = frame_copy->tx_rates[i];
//	}
//
//	memcpy(frame->data, frame_copy->data, frame_copy->data_len);
//	frame->data_len = frame_copy->data_len;
//
//	return frame;
//}

static inline bool is_multicast_frame(struct frame *frame) {
	struct ieee80211_hdr *hdr = (void *) frame->data;
	u8 *dest = hdr->addr1;
	return is_multicast_ether_addr(dest);
}

// TODO: convert to big-endian!
/**
 * Send a `frame` via the network
 */

static inline int send_frame(struct frame *frame)
{
	uint16_t frame_len = frame->frame_len;

#ifdef SOCK_OPT_MCAST

	struct sockaddr_in addr;

	// configure addr struct
	// zero struct
	// TODO: reuse addr struct! refactoring!
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(MCAST_GROUP);
	addr.sin_port = htons(PORTNUM);

	// send actual payload
	if(0 >= sendto(mysocket, frame, frame_len, MSG_DONTWAIT, (struct sockaddr*) &addr, sizeof(addr)))  {
		fprintf(stderr, "Error : Send Failed \n");
		return EXIT_FAILURE;
	}
	else {
		MY_PRINTF("Sent ieee80211 frame ...\n");
	}

#else

	// send actual payload
	if(0 >= send(mysocket, frame, frame_len, MSG_DONTWAIT)) {
		MY_PRINTF("Error : Send Failed \n");
		return EXIT_FAILURE;
	}
	else {
		MY_PRINTF("Sent ieee80211 frame ...\n");
	}
#endif

	return EXIT_SUCCESS;
}

#define index_to_rate_size 8
static int index_to_rate[] = {
	60, 90, 120, 180, 240, 360, 480, 540
};

static struct station *get_station_by_addr(u8 *addr)
{
	struct station *station;

	list_for_each_entry(station, &wmediumd->stations, list) {
		if (memcmp(station->addr, addr, ETH_ALEN) == 0)
			return station;
	}
	return NULL;
}

/*
 * Report transmit status to the kernel.
 */
int send_tx_info_frame_nl(struct station *src,
			  unsigned int flags, uint32_t signal,
			  struct hwsim_tx_rate *tx_attempts,
			  u64 cookie)
{

	struct nl_sock *sock = wmediumd->sock;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg) {
		MY_PRINTF("Error allocating new message MSG!\n");
		goto out;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(wmediumd->family),
				0, NLM_F_REQUEST, HWSIM_CMD_TX_INFO_FRAME, VERSION_NR);

	int rc;

	rc = nla_put(msg, HWSIM_ATTR_ADDR_TRANSMITTER, ETH_ALEN, src->hwaddr);
	rc = nla_put_u32(msg, HWSIM_ATTR_FLAGS, flags);
	rc = nla_put_u32(msg, HWSIM_ATTR_SIGNAL, signal);
	rc = nla_put(msg, HWSIM_ATTR_TX_INFO,
				 IEEE80211_TX_MAX_RATES * sizeof(struct hwsim_tx_rate),
				 tx_attempts);

	rc = nla_put_u64(msg, HWSIM_ATTR_COOKIE, cookie);

	if (rc != 0) {
		MY_PRINTF("Error filling payload\n");
		goto out;
	}

	nl_send_auto_complete(sock, msg);
	nlmsg_free(msg);
	return 0;
	out:
	nlmsg_free(msg);
	return -1;

	return 0;
}

/*
 * Send a data frame to the kernel for reception at a specific radio.
 */
int send_cloned_frame_msg(struct station *dst,
			  u8 *data, int data_len, uint32_t signal)
{
	struct nl_msg *msg;
	struct nl_sock *sock = wmediumd->sock;

	msg = nlmsg_alloc();
	if (!msg) {
		MY_PRINTF("Error allocating new message MSG!\n");
		goto out;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(wmediumd->family),
		    0, NLM_F_REQUEST, HWSIM_CMD_FRAME, VERSION_NR);

	int rc;

	rc = nla_put(msg, HWSIM_ATTR_ADDR_RECEIVER, ETH_ALEN, dst->hwaddr);
	rc = nla_put(msg, HWSIM_ATTR_FRAME, data_len, data);
	// TODO: modify?
	rc = nla_put_u32(msg, HWSIM_ATTR_RX_RATE, 1);
	rc = nla_put_u32(msg, HWSIM_ATTR_SIGNAL, -50);

	if (rc != 0) {
		MY_PRINTF("Error filling payload\n");
		goto out;
	}
	MY_PRINTF("cloned msg dest " MAC_FMT " (radio: " MAC_FMT ") len %d\n",
	       MAC_ARGS(dst->addr), MAC_ARGS(dst->hwaddr), data_len);

	nl_send_auto(sock, msg);
	nlmsg_free(msg);
	return 0;
out:
	nlmsg_free(msg);
	return -1;
}

void deliver_frame(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *) frame->data;
	struct station *station;
	u8 *dest = hdr->addr1;
	struct station *sender = get_sender_station_by_index(frame->sender);
	u8 *src = sender->addr;

	if (frame->flags & HWSIM_TX_STAT_ACK) {
		// for each station copy the frame
		/* rx the frame on the dest interface */
		list_for_each_entry(station, &wmediumd->stations, list) {

			// we have only one local station!
			// necessary to prevent netlink errors (code 2)
			if(!is_local_mac(station->addr))
				continue;

			// do not send sent packets back to the kernel
			if (memcmp(src, station->addr, ETH_ALEN) == 0)
				continue;

			// beacon frames
			if (is_multicast_ether_addr(dest)) {
				uint32_t signal;
				int rate_idx;

				double error_prob;
				/*
				 * we may or may not receive this based on
				 * reverse link from sender -- check for
				 * each receiver.
				 */
				signal = SNR_DEFAULT;
				frame->signal = signal;

				send_cloned_frame_msg(station,
						      frame->data,
						      frame->data_len,
							  // use signal calculated by snr matrix
						      signal);

			}
			// data frame
			else if (memcmp(dest, station->addr, ETH_ALEN) == 0) {
				send_cloned_frame_msg(station,
						      frame->data,
						      frame->data_len,
							  // use signal from frame
						      frame->signal);
			}
		}
	}

	// necessary to prevent netlink errors (code 3)
	// NOTE: the method is used by process_incoming_frames too!
	if(is_local_mac(src)) {

		send_tx_info_frame_nl(sender, frame->flags,
							  frame->signal, frame->tx_rates, frame->cookie);
	}

}

static
int nl_err_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(&nlerr->msg);

	fprintf(stderr, "nl: cmd %d, seq %d: error_code: %s, error_message: %s\n", gnlh->cmd,
			nlerr->msg.nlmsg_seq, strerror(abs(nlerr->error)), nl_geterror(nlerr->error));

	return NL_SKIP;
}


// TODO: libevent
//static void process_incoming_frames(int fd, short what, void *data) {
/**
 * Receives new frames and delivers them to the kernel via `queue_frame`.
 */

static void process_incoming_frames() {
	while(1) {

		MY_PRINTF("process_incoming_frames ...\n");

		// receive frame
		struct frame *frame = recv_frame(mysocket);
		deliver_frame(frame);
		free(frame);

	}
}

void process_frame(struct frame *frame) {

    frame->flags |= HWSIM_TX_STAT_ACK;
    deliver_frame(frame);

    MY_PRINTF("sending frame ...\n");
    if (0 > send_frame(frame)) {
        // TODO: replace perror calls?
        perror("Could not send frame!\n");
        exit(1);
    }

    free(frame);
}

threadpool thpool;

/*
 * Handle events from the kernel.  Process CMD_FRAME events and queue them
 * for later delivery with the scheduler.
 */
static int process_messages_cb(struct nl_msg *msg)
{

	struct nlattr *attrs[HWSIM_ATTR_MAX+1];

	// split kernel `msg` into header and body

	/* netlink header */
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	/* generic netlink header*/
	struct genlmsghdr *gnlh = nlmsg_data(nlh);

	struct station *sender;
	struct frame *frame;
	struct ieee80211_hdr *hdr;
	u8 *src;

	// handle only command frames
	if (gnlh->cmd == HWSIM_CMD_FRAME) {
		/* we get the attributes from `nlh` */
		genlmsg_parse(nlh, 0, attrs, HWSIM_ATTR_MAX, NULL);
		if (attrs[HWSIM_ATTR_ADDR_TRANSMITTER]) {

            // put items from `attrs` into local vars
            u8 *hwaddr = (u8 *) nla_data(attrs[HWSIM_ATTR_ADDR_TRANSMITTER]);
            unsigned int data_len =
                    nla_len(attrs[HWSIM_ATTR_FRAME]);
            char *data = (char *) nla_data(attrs[HWSIM_ATTR_FRAME]);
            uint32_t flags =
                    nla_get_u32(attrs[HWSIM_ATTR_FLAGS]);
            unsigned int tx_rates_len =
                    nla_len(attrs[HWSIM_ATTR_TX_INFO]);
            struct hwsim_tx_rate *tx_rates =
                    (struct hwsim_tx_rate *)
                            nla_data(attrs[HWSIM_ATTR_TX_INFO]);
            u64 cookie = nla_get_u64(attrs[HWSIM_ATTR_COOKIE]);
			// TODO: get HWSIM_ATTR_SIGNAL and HWSIM_ATTR_RX_RATE?
			// See also: http://lxr.free-electrons.com/source/drivers/net/wireless/mac80211_hwsim.h

            // ieee80211 frame
            hdr = (struct ieee80211_hdr *) data;
            src = hdr->addr2;

            if (data_len < 6 + 6 + 4)
                goto out;

            // create sender struct
            // TODO:
            sender = get_station_by_addr(src);
            if (!sender) {
                fprintf(stderr, "Unable to find sender station " MAC_FMT "\n", MAC_ARGS(src));
                goto out;
            }
            memcpy(sender->hwaddr, hwaddr, ETH_ALEN);

            frame = mymalloc_zero(sizeof(*frame) + data_len);

            if (!frame)
                goto out;

            // envelope IEEE 802.11 frame
            memcpy(frame->data, data, data_len);
            frame->data_len = data_len;
            frame->flags = flags;
            frame->cookie = cookie;
            frame->sender = sender->index;
            frame->tx_rates_count =
                    tx_rates_len / sizeof(struct hwsim_tx_rate);
            memcpy(frame->tx_rates, tx_rates,
                   min(tx_rates_len, sizeof(frame->tx_rates)));

            frame->frame_len = sizeof(struct frame) + frame->data_len;
            process_frame(frame);

        }
	}
	out:
	return 0;
}

/*
 * Register with the kernel to start receiving new frames.
 */
int send_register_msg()
{
	struct nl_sock *sock = wmediumd->sock;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Error allocating new message MSG!\n");
		return -1;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(wmediumd->family),
		    0, NLM_F_REQUEST, HWSIM_CMD_REGISTER, VERSION_NR);
	nl_send_auto_complete(sock, msg);
	nlmsg_free(msg);

	return 0;
}

static void sock_event_cb(int fd, short what, void *data)
{

	nl_recvmsgs_default(wmediumd->sock);
}

/*
 * Setup netlink socket and callbacks.
 */
void init_netlink()
{
	struct nl_sock *sock;

	wmediumd->cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!wmediumd->cb) {
		fprintf(stderr, "Error allocating netlink callbacks\n");
		exit(EXIT_FAILURE);
	}

	sock = nl_socket_alloc_cb(wmediumd->cb);
	if (!sock) {
		fprintf(stderr, "Error allocating netlink socket\n");
		exit(EXIT_FAILURE);
	}

	wmediumd->sock = sock;

	genl_connect(sock);
	genl_ctrl_alloc_cache(sock, &wmediumd->cache);

	wmediumd->family = genl_ctrl_search_by_name(wmediumd->cache, "MAC80211_HWSIM");

	if (!wmediumd->family) {
		fprintf(stderr, "Family MAC80211_HWSIM not registered\n");
		exit(EXIT_FAILURE);
	}

	// register methods to be called for netlink events
	nl_cb_set(wmediumd->cb, NL_CB_MSG_IN, NL_CB_CUSTOM, process_messages_cb, wmediumd);
	nl_cb_err(wmediumd->cb, NL_CB_CUSTOM, nl_err_cb, wmediumd);
}

/*
 *	Print the CLI help
 */
void print_help(int exval)
{
	printf("wmediumd v%s - a wireless medium simulator\n", VERSION_STR);
	printf("wmediumd [-h] [-V] [-c FILE]\n\n");

	printf("  -h              print this help and exit\n");
	printf("  -V              print version and exit\n\n");

	printf("  -c FILE         set input config file\n");

	exit(exval);
}

int main(int argc, char *argv[])
{
	int opt;
	struct event ev_cmd;
	struct event ev_timer;
	struct wmediumd ctx;
	wmediumd = &ctx;

	char *config_file = NULL;

	setvbuf(stdout, NULL, _IOLBF, BUFSIZ);

	if (argc == 1) {
		fprintf(stderr, "This program needs arguments....\n\n");
		print_help(EXIT_FAILURE);
	}

	while ((opt = getopt(argc, argv, "hVc:")) != -1) {
		switch (opt) {
		case 'h':
			print_help(EXIT_SUCCESS);
			break;
		case 'V':
			printf("wmediumd v%s - a wireless medium simulator "
			       "for mac80211_hwsim\n", VERSION_STR);
			exit(EXIT_SUCCESS);
			break;
		case 'c':
			printf("Input configuration file: %s\n", optarg);
			config_file = optarg;
			break;
		case ':':
			printf("wmediumd: Error - Option `%c' "
			       "needs a value\n\n", optopt);
			print_help(EXIT_FAILURE);
			break;
		case '?':
			printf("wmediumd: Error - No such option: "
			       "`%c'\n\n", optopt);
			print_help(EXIT_FAILURE);
			break;
		}

	}

	if (optind < argc)
		print_help(EXIT_FAILURE);

	if (!config_file) {
		fprintf(stderr, "%s: config file must be supplied\n", argv[0]);
		print_help(EXIT_FAILURE);
	}

	INIT_LIST_HEAD(&ctx.stations);
	load_config(&ctx, config_file);

	/* init libevent */
	event_init();

    // valgrind profiling showed that is_local_mac() is very expensive when calculation the wifi0 mac addr every time
    remember_local_mac();
	if(connect_frame_distribution_socket() == EXIT_FAILURE) {
		fprintf(stderr, "Could not open frame distribution channel!\n");
		return EXIT_FAILURE;
	}

	/* init netlink */
	init_netlink();
	event_set(&ev_cmd, nl_socket_get_fd(ctx.sock), EV_READ | EV_PERSIST,
		  sock_event_cb, &ctx);
	event_add(&ev_cmd, NULL);

	// process incoming frames
	// TODO: libevent
//	event_set(&ev_timer, mysocket, EV_READ | EV_PERSIST, process_incoming_frames, NULL);
//	event_add(&ev_timer, NULL);

	pthread_t t_frame_receiver;
	int rc;
	rc = pthread_create( &t_frame_receiver, NULL, process_incoming_frames, NULL);
	if( rc != 0 ) {
		perror("Could not create frame receiver thread!\n");
		exit(1);
	}
	// TODO: signal handler to wait for processing of frames???

	/* register for new frames */
	if (send_register_msg() == 0)
		MY_PRINTF("REGISTER SENT!\n");

	/* enter libevent main loop */
	event_dispatch();

	free(ctx.sock);
	free(ctx.cb);
	free(ctx.cache);
	free(ctx.family);

	disconnect_frame_distribution_socket();

	return EXIT_SUCCESS;
}
