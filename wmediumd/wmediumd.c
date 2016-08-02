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

#include "message.h"

// TODO:
#define PDU 1400

#define BUF_SIZE 65507
static struct wmediumd *wmediumd;


#define PERFECT_CHANNEL

// otherwise use TCP!
#define SOCK_OPT_MCAST
#define MCAST_GROUP "239.0.0.1"

#define MODE_DISTRIBUTED

bool is_multicast_ether_addr(const u8 *addr)
{
	return 0x01 & addr[0];
}

// TODO: make more generic
bool is_local_mac(uint8_t *mac) {

	FILE *fd;

	uint8_t mac_addr[6];
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
		mac_addr[i] = (uint8_t) values[i];
	}

	fclose(fd);
	return memcmp(mac, mac_addr, 6) == 0;
}

//////////////////////////////////////////////////////////////////////////////
// Network receiving methods
//////////////////////////////////////////////////////////////////////////////

/**
 * Receive a `struct frame_copy` from the socket.
 */
char* recv_frames(int socket, char *buffer, ssize_t buf_size) {
	ssize_t len;

	len = recv(socket, buffer, buf_size, 0);
	if(0 >= len) {
		fprintf(stderr, "socket EOF!\n");
		exit(1);
	}
	printf("Received frame length: %ld\n", len);

	return buffer;
}

///**
// * Receive a `struct frame_copy` from the socket.
// */
//struct frame_copy** recv_frame_copy(int socket, char *buffer, ssize_t buf_size) {
//	ssize_t len;
//
//	len = recv(socket, buffer, buf_size, 0);
//	if(0 >= len) {
//		fprintf(stderr, "socket EOF!\n");
//		exit(1);
//	}
//	printf("Received frame length: %ld\n", len);
//
//	// get struct from buffer
//	// TODO: check every malloc call for failure ...
//	struct frame_copy *frame_copy = malloc(len);
//	memcpy(frame_copy, buffer, len);
//	printf("received frame ...\n");
//
//	return frame_copy;
//}

//////////////////////////////////////////////////////////////////////////////
// Socket creation/connection/binding/teardown
//////////////////////////////////////////////////////////////////////////////

int connect_frame_distribution_socket() {
	printf("connecting socket ...\n");

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
#endif
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
		if(0 > connect(mysocket, (struct sockaddr *)&addr, sizeof(struct sockaddr))) {
#endif
		fprintf(stderr, "Error : Connect Failed \n");
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

	return EXIT_SUCCESS;
}

int disconnect_frame_distribution_socket() {
	// TODO: how to handle close and free if returned by error?
	close(mysocket);
	return EXIT_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////
// Frame (de)serialization
//////////////////////////////////////////////////////////////////////////////

struct station *get_sender_station_by_index(int index) {
	struct station *cur_station;
	list_for_each_entry(cur_station, &wmediumd->stations, list) {
		if(cur_station->index == index) {
			return cur_station;
		}
	}

	//perror("Station not found for index: %d\n", index);
	return NULL;
}

/**
 * Serialize frame by copying all pointers content.
 * The station struct is replaced by it's index.
 */
struct frame_copy* frame_serialize(struct frame *frame) {
	int total_struct_length = sizeof(struct frame_copy) + frame->data_len;
	struct frame_copy *frame_copy = malloc(total_struct_length);

	frame_copy->expires.tv_sec = frame->expires.tv_sec;
	frame_copy->expires.tv_nsec = frame->expires.tv_nsec;

	frame_copy->acked = frame->acked;
	frame_copy->cookie = frame->cookie;
	frame_copy->flags = frame->flags;
	frame_copy->signal = frame->signal;
	frame_copy->tx_rates_count = frame->tx_rates_count;
	// copy index of station instead of whole structure
	frame_copy->sender = frame->sender->index;

	// copy array value by value
	for(int i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
		frame_copy->tx_rates[i] = frame->tx_rates[i];
	}

	frame_copy->data_len = frame->data_len;

	// copy data array
	memcpy(frame_copy->data, frame->data, frame->data_len);

	frame_copy->total_struct_length = total_struct_length;

	return frame_copy;
}

/**
 * Deserialize a frame and get the station from the index.
 */
struct frame* frame_deserialization(struct frame_copy *frame_copy) {
	struct frame *frame = malloc(sizeof(struct frame) + frame_copy->data_len);

	frame->expires.tv_sec = frame_copy->expires.tv_sec;
	frame->expires.tv_nsec = frame_copy->expires.tv_nsec;

	frame->acked = frame_copy->acked;
	frame->cookie = frame_copy->cookie;
	frame->flags = frame_copy->flags;
	frame->signal = frame_copy->signal;
	frame->tx_rates_count = frame_copy->tx_rates_count;
	// copy index of station instead of whole structure
	frame->sender = get_sender_station_by_index(frame_copy->sender);
	if(!frame->sender) {
		fprintf(stderr, "frame_deserialization: \n");
	}

	for(int i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
		frame->tx_rates[i] = frame_copy->tx_rates[i];
	}

	memcpy(frame->data, frame_copy->data, frame_copy->data_len);
	frame->data_len = frame_copy->data_len;

	return frame;
}

static char buffer[PDU];
static int buf_size = 0;

typedef unsigned char buffer_len;

#define END_OF_BUFFER 0

/**
 * Fill the buffer and return the new buffer size. -1 if buffer full.
 *
 */
ssize_t fill_buffer(char *data, buffer_len byte_len) {

	// append END_OF_BUFFER
	if(buf_size + byte_len + 1 >= PDU) {
		//buffer[buf_size] = END_OF_BUFFER;
		// include at least one END_OF_BUFFER
		buf_size += 1;
		return 	-1;
	}
	else {

		// include length of following data
		buffer[buf_size] = byte_len;
		buf_size += 1;

		// append data to buffer
		memcpy(buffer + buf_size, data, byte_len);
		buf_size += byte_len;

		fprintf(stderr, "buffer_fill: %d\n", buf_size);
		return buf_size;
	}
}

void clear_buffer() {
	buf_size = 0;
	// clear buffer
	memset(buffer, END_OF_BUFFER, PDU);
}

bool is_multicast_frame(struct frame_copy *frame_copy) {
	struct ieee80211_hdr *hdr = (void *) frame_copy->data;
	u8 *dest = hdr->addr1;
	return is_multicast_ether_addr(dest);
}

// TODO: convert to big-endian!
/**
 * Send a `frame_copy` via the network
 */
int send_frame(struct frame_copy *frame_copy)
{

#ifdef SOCK_OPT_MCAST

	struct sockaddr_in addr;
	ssize_t bytes_to_send = frame_copy->total_struct_length;
	// configure addr struct
	// zero struct
	// TODO: reuse addr struct! refactoring!
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(MCAST_GROUP);
	addr.sin_port = htons(PORTNUM);

	// beacon frames
	if (is_multicast_frame(frame_copy)) {
		printf("sending baecon (%d) via mcast ...\n", frame_copy->total_struct_length);

		int frame_size = frame_copy->total_struct_length + 1;
		char buffer[frame_size];
		buffer[0] = frame_copy->total_struct_length;
		memcpy(buffer+1, frame_copy, frame_copy->total_struct_length);

		if (0 >= sendto(mysocket, buffer, frame_size, 0, (struct sockaddr *) &addr, sizeof(addr))) {
			perror("Error : Send Failed");
			return EXIT_FAILURE;
		}
		else {
			printf("Sent ieee80211 frame ...\n");
		}
		// TODO:
		//free(frame_copy_with_length);
	}
	else {
		// send the full buffer and clear it afterwards
		if (-1 == fill_buffer((char *) frame_copy, (buffer_len) bytes_to_send)) {

			// send actual payload
			printf("sending local frame (%d) via mcast ...\n", buf_size);
			if (0 >= sendto(mysocket, buffer, buf_size, 0, (struct sockaddr *) &addr, sizeof(addr))) {
				perror("Error : Send Failed");
				return EXIT_FAILURE;
			}
			else {
				printf("Sent ieee80211 frame ...\n");
			}
			clear_buffer();

		}
			// add data to empty buffer
		else {
			fill_buffer((char *) frame_copy, bytes_to_send);
		}
	}
#else

	// send actual payload
	if(0 >= send(mysocket, frame_copy, frame_copy->total_struct_length, 0)) {
		perror("Error : Send Failed");
		return EXIT_FAILURE;
	}
	else {
		printf("Sent ieee80211 frame ...\n");
	}
#endif

	return EXIT_SUCCESS;
}


# define index_to_rate_size 8
static int index_to_rate[] = {
	60, 90, 120, 180, 240, 360, 480, 540
};

static inline int div_round(int a, int b)
{
	return (a + b - 1) / b;
}

static inline int pkt_duration(int len, int rate)
{
	/* preamble + signal + t_sym * n_sym, rate in 100 kbps */
	return 16 + 4 + 4 * div_round((16 + 8 * len + 6) * 10, 4 * rate);
}

static void wqueue_init(struct wqueue *wqueue, int cw_min, int cw_max)
{
	INIT_LIST_HEAD(&wqueue->frames);
	wqueue->cw_min = cw_min;
	wqueue->cw_max = cw_max;
}

/**
 * http://permalink.gmane.org/gmane.linux.kernel.wireless.general/98501
 * IEEE802.11e (Quality of Service)
 *
 * IEEE80211_AC_BE is best-effort traffic,
 * IEEE80211_AC_BK is background traffic,
 * IEEE80211_AC_VI is video traffic,
 * IEEE80211_AC_VO is voice traffic.
 */
void station_init_queues(struct station *station)
{
	wqueue_init(&station->queues[IEEE80211_AC_BK], 15, 1023);
	wqueue_init(&station->queues[IEEE80211_AC_BE], 15, 1023);
	wqueue_init(&station->queues[IEEE80211_AC_VI], 7, 15);
	wqueue_init(&station->queues[IEEE80211_AC_VO], 3, 7);
}

bool timespec_before(struct timespec *t1, struct timespec *t2)
{
	return t1->tv_sec < t2->tv_sec ||
	       (t1->tv_sec == t2->tv_sec && t1->tv_nsec < t2->tv_nsec);
}

void timespec_add_usec(struct timespec *t, int usec)
{
	t->tv_nsec += usec * 1000;
	if (t->tv_nsec >= 1000000000) {
		t->tv_sec++;
		t->tv_nsec -= 1000000000;
	}
}

void rearm_timer()
{
	struct timespec min_expires;
	struct itimerspec expires = {};
	struct station *station;
	struct frame *frame;
	int i;

	bool set_min_expires = false;

	/*
	 * Iterate over all the interfaces to find the next frame that
	 * will be delivered, and set the timerfd accordingly.
	 */
	list_for_each_entry(station, &wmediumd->stations, list) {
		for (i = 0; i < IEEE80211_NUM_ACS; i++) {
			frame = list_first_entry_or_null(&station->queues[i].frames,
							 struct frame, list);

			// find earliest frame expiration time
			if (frame && (!set_min_expires ||
					  // frame expires before current min_expires ?
				      timespec_before(&frame->expires,
						      &min_expires))) {
				set_min_expires = true;
				min_expires = frame->expires;
			}
		}
	}
	expires.it_value = min_expires;
	// arm timer at expires->it_value
	timerfd_settime(wmediumd->timerfd, TFD_TIMER_ABSTIME, &expires, NULL);
}

static inline bool frame_has_a4(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[1] & (FCTL_TODS | FCTL_FROMDS)) ==
		(FCTL_TODS | FCTL_FROMDS);
}

static inline bool frame_is_mgmt(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[0] & FCTL_FTYPE) == FTYPE_MGMT;
}

static inline bool frame_is_data(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[0] & FCTL_FTYPE) == FTYPE_DATA;
}

static inline bool frame_is_data_qos(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	return (hdr->frame_control[0] & (FCTL_FTYPE | STYPE_QOS_DATA)) ==
		(FTYPE_DATA | STYPE_QOS_DATA);
}

static inline u8 *frame_get_qos_ctl(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *)frame->data;

	if (frame_has_a4(frame))
		return (u8 *)hdr + 30;
	else
		return (u8 *)hdr + 24;
}

static enum ieee80211_ac_number frame_select_queue_80211(struct frame *frame)
{
	u8 *p;
	int priority;

	if (!frame_is_data(frame))
		return IEEE80211_AC_VO;

	if (!frame_is_data_qos(frame))
		return IEEE80211_AC_BE;

	p = frame_get_qos_ctl(frame);
	priority = *p & QOS_CTL_TAG1D_MASK;

	return ieee802_1d_to_ac[priority];
}

bool is_multicast_ether_addr(const u8 *addr)
{
	return 0x01 & addr[0];
}

static struct station *get_station_by_addr(u8 *addr)
{
	struct station *station;

	list_for_each_entry(station, &wmediumd->stations, list) {
		if (memcmp(station->addr, addr, ETH_ALEN) == 0)
			return station;
	}
	return NULL;
}

static int get_link_snr(struct station *sender,
			struct station *receiver)
{
	return wmediumd->snr_matrix[sender->index * wmediumd->num_stas + receiver->index];
}

void queue_frame(struct frame *frame)
{
	struct station *station = frame->sender;

	struct ieee80211_hdr *hdr = (void *)frame->data;
	u8 *dest = hdr->addr1;
	struct timespec now, target;
	struct wqueue *queue;
	struct frame *tail;
	struct station *tmpsta;
	int send_time;
	int cw;
	double error_prob;
	bool is_acked = false;
	bool noack = false;
	int i, j;
	int rate_idx;
	int ac;

	/* TODO configure phy parameters */
	int slot_time = 9;
	int sifs = 16;
	int difs = 2 * slot_time + sifs;

	int retries = 0;

	clock_gettime(CLOCK_MONOTONIC, &now);

	int ack_time_usec = pkt_duration(14, index_to_rate[0]) + sifs;

	/*
	 * To determine a frame's expiration time, we compute the
	 * number of retries we might have to make due to radio conditions
	 * or contention, and add backoff time accordingly.  To that, we
	 * add the expiration time of the previous frame in the queue.
	 */

	// get 80211 qos queue
	ac = frame_select_queue_80211(frame);
	// add to station queue
	queue = &station->queues[ac];

	/* try to "send" this frame at each of the rates in the rateset */
	send_time = 0;
	cw = queue->cw_min;

	int snr = SNR_DEFAULT;

	if (!is_multicast_ether_addr(dest)) {
		struct station *deststa;
		deststa = get_station_by_addr(dest);
		if (deststa) {
			snr = get_link_snr(station, deststa);
		}
		else {
			fprintf(stderr, "Station not found!\n");
		}
	}

	frame->signal = snr;

	noack = frame_is_mgmt(frame) || is_multicast_ether_addr(dest);
	double choice = -3.14;

	for (i = 0; i < IEEE80211_TX_MAX_RATES && !is_acked; i++) {

		rate_idx = frame->tx_rates[i].idx;

		/* no more rates in MRR */
		if (rate_idx < 0)
			break;

		error_prob = get_error_prob(snr, rate_idx, frame->data_len);
		for (j = 0; j < frame->tx_rates[i].count; j++) {

			if(rate_idx > index_to_rate_size -1) {

				fprintf(stderr, "Invalid rate_idx!\n");
				rate_idx = index_to_rate_size -1;
			}

			int rate = index_to_rate[rate_idx];
			send_time += difs + pkt_duration(frame->data_len, rate);

			retries++;

			/* skip ack/backoff/retries for noack frames */
			if (noack) {
				is_acked = true;
				break;
			}

			/* TODO TXOPs */

			/* backoff */
			if (j > 0) {
				send_time += (cw * slot_time) / 2;
				cw = (cw << 1) + 1;
				if (cw > queue->cw_max)
					cw = queue->cw_max;
			}
			choice = drand48();
			if (choice > error_prob) {
				is_acked = true;
				break;
			}
			send_time += ack_time_usec;
		}
	}

	if (is_acked) {
		frame->tx_rates[i-1].count = j + 1;
		for (; i < IEEE80211_TX_MAX_RATES; i++) {
			frame->tx_rates[i].idx = -1;
			frame->tx_rates[i].count = -1;
		}
		frame->flags |= HWSIM_TX_STAT_ACK;
	}

	/*
	 * delivery time starts after any equal or higher prio frame
	 * (or now, if none).
	 */
	target = now;
	for (i = 0; i <= ac; i++) {
		list_for_each_entry(tmpsta, &wmediumd->stations, list) {
			tail = list_last_entry_or_null(&tmpsta->queues[i].frames,
						       struct frame, list);
			if (tail && timespec_before(&target, &tail->expires))
				target = tail->expires;
		}
	}

	timespec_add_usec(&target, send_time);

	frame->expires = target;
	list_add_tail(&frame->list, &queue->frames);
	rearm_timer(wmediumd);
}

/*
 * Report transmit status to the kernel.
 */
int send_tx_info_frame_nl(struct station *src,
			  unsigned int flags, int signal,
			  struct hwsim_tx_rate *tx_attempts,
			  u64 cookie)
{

	if(is_local_mac(src->hwaddr)) {
		struct nl_sock *sock = wmediumd->sock;
		struct nl_msg *msg;

		msg = nlmsg_alloc();
		if (!msg) {
			printf("Error allocating new message MSG!\n");
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
			printf("Error filling payload\n");
			goto out;
		}

		nl_send_auto_complete(sock, msg);
		nlmsg_free(msg);
		return 0;
		out:
		nlmsg_free(msg);
		return -1;
	}
	else {
		printf("No local tx info!\n");
	}
	return 0;
}

/*
 * Send a data frame to the kernel for reception at a specific radio.
 */
int send_cloned_frame_msg(struct station *dst,
			  u8 *data, int data_len, int signal)
{
	struct nl_msg *msg;
	struct nl_sock *sock = wmediumd->sock;

	msg = nlmsg_alloc();
	if (!msg) {
		printf("Error allocating new message MSG!\n");
		goto out;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(wmediumd->family),
		    0, NLM_F_REQUEST, HWSIM_CMD_FRAME, VERSION_NR);

	int rc;

	rc = nla_put(msg, HWSIM_ATTR_ADDR_RECEIVER, ETH_ALEN, dst->hwaddr);
	rc = nla_put(msg, HWSIM_ATTR_FRAME, data_len, data);
	rc = nla_put_u32(msg, HWSIM_ATTR_RX_RATE, 1);
	rc = nla_put_u32(msg, HWSIM_ATTR_SIGNAL, -50);

	if (rc != 0) {
		printf("Error filling payload\n");
		goto out;
	}
	printf("cloned msg dest " MAC_FMT " (radio: " MAC_FMT ") len %d\n",
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
	u8 *src = frame->sender->addr;

	if (frame->flags & HWSIM_TX_STAT_ACK) {
		// for each station copy the frame
		/* rx the frame on the dest interface */
		// TODO: we have only one interface in the distributed mode! therefore we can save performance here!
		list_for_each_entry(station, &wmediumd->stations, list) {

			// we have only one local station!
			// necessary to prevent netlink errors (code 2)
			if(!is_local_mac(station->addr))
				continue;

			// do not send sent packets back to the kernel
			if (memcmp(src, station->addr, ETH_ALEN) == 0)
				continue;

			// necessary to prevent netlink errors
			if(!is_local_mac(station->addr))
				break;

			// beacon frames
			if (is_multicast_ether_addr(dest)) {
				int signal, rate_idx;
				double error_prob;

				/*
				 * we may or may not receive this based on
				 * reverse link from sender -- check for
				 * each receiver.
				 */
				signal = get_link_snr(station, frame->sender);
				// TODO:
				rate_idx = index_to_rate[index_to_rate_size];
				error_prob = get_error_prob((double)signal,
							    rate_idx, frame->data_len);

				if (drand48() <= error_prob) {
					printf("Dropped mcast from "
					       MAC_FMT " to " MAC_FMT " at receiver\n",
					       MAC_ARGS(src), MAC_ARGS(station->addr));
					continue;
				}

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
	send_tx_info_frame_nl(frame->sender, frame->flags,
						  frame->signal, frame->tx_rates, frame->cookie);

	// necessary to prevent netlink errors (code 3)
	if(is_local_mac(src)) {

		send_tx_info_frame_nl(frame->sender, frame->flags,
							  frame->signal, frame->tx_rates, frame->cookie);
	}

	free(frame);
}

void deliver_expired_frames_queue(struct list_head *queue,
				  struct timespec *now)
{
	struct frame *frame, *tmp;

	list_for_each_entry_safe(frame, tmp, queue, list) {
		if (timespec_before(&frame->expires, now)) {
			// deliver frame and remove it from the queue
			list_del(&frame->list);
			deliver_frame(frame);
		} else {
			break;
		}
	}
}

void deliver_expired_frames(struct wmediumd *ctx)
{
	struct timespec now;
	struct station *station;
	struct list_head *l;
	int i;

	clock_gettime(CLOCK_MONOTONIC, &now);
	// TODO: we have only one station
	list_for_each_entry(station, &ctx->stations, list) {

		// TODO: needs to be copied to each station!
//		if(is_local_mac(station->hwaddr)) {
			int q_ct[IEEE80211_NUM_ACS] = {};
			// iterate over wlan queues
			for (i = 0; i < IEEE80211_NUM_ACS; i++) {
				list_for_each(l, &station->queues[i].frames) {
					q_ct[i]++;
				}
			}
			printf("[" TIME_FMT "] Station " MAC_FMT
						   " BK %d BE %d VI %d VO %d\n",
				   TIME_ARGS(&now), MAC_ARGS(station->addr),
				   q_ct[IEEE80211_AC_BK], q_ct[IEEE80211_AC_BE],
				   q_ct[IEEE80211_AC_VI], q_ct[IEEE80211_AC_VO]);

			for (i = 0; i < IEEE80211_NUM_ACS; i++)
				deliver_expired_frames_queue(&station->queues[i].frames, &now);
//		}
//		else {
//			printf("skipping deliver_expired_frames for non-local station ...\n");
//		}
	}
	printf("\n\n");
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

		printf("process_incoming_frames ...\n");

		char buffer[PDU];
		// receive frame(s)
		recv_frames(mysocket, buffer, PDU);

		// pointer in stream
		ssize_t offset = 0;

		// demultiplex frame(s)
		while(1) {
			buffer_len len = buffer[offset];

			if((char)len == END_OF_BUFFER) {
				break;
			}

			offset += 1;

			struct frame_copy *frame_copy = malloc(len);
			// copy frame from buffer
			memcpy(frame_copy, buffer + offset, len);

			offset += len;

			struct frame *detransformed_frame;

			// TODO: free
			// deserialize it
			detransformed_frame = frame_deserialization(frame_copy);

			// queue frame
			queue_frame(detransformed_frame);

			free(frame_copy);

			// received baecon -> enter while loop again
			if(is_multicast_frame(frame_copy)) {
				printf("received baecon ...\n");
				break;
			}
		}

	}
}

/*
 * Handle events from the kernel.  Process CMD_FRAME events and queue them
 * for later delivery with the scheduler.
 */
static int process_messages_cb(struct nl_msg *msg, void *arg)
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
			u8 *hwaddr = (u8 *)nla_data(attrs[HWSIM_ATTR_ADDR_TRANSMITTER]);
			unsigned int data_len =
				nla_len(attrs[HWSIM_ATTR_FRAME]);
			char *data = (char *)nla_data(attrs[HWSIM_ATTR_FRAME]);
			unsigned int flags =
				nla_get_u32(attrs[HWSIM_ATTR_FLAGS]);
			unsigned int tx_rates_len =
				nla_len(attrs[HWSIM_ATTR_TX_INFO]);
			struct hwsim_tx_rate *tx_rates =
				(struct hwsim_tx_rate *)
				nla_data(attrs[HWSIM_ATTR_TX_INFO]);
			u64 cookie = nla_get_u64(attrs[HWSIM_ATTR_COOKIE]);

			// ieee80211 frame
			hdr = (struct ieee80211_hdr *)data;
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

			frame = malloc(sizeof(*frame) + data_len);
			if (!frame)
				goto out;

			// envelope IEEE 802.11 frame
			memcpy(frame->data, data, data_len);
			frame->data_len = data_len;
			frame->flags = flags;
			frame->cookie = cookie;
			frame->sender = sender;
			frame->tx_rates_count =
				tx_rates_len / sizeof(struct hwsim_tx_rate);
			memcpy(frame->tx_rates, tx_rates,
			       min(tx_rates_len, sizeof(frame->tx_rates)));

			queue_frame(frame);

			struct frame_copy *transformed_frame;
			// TODO: do not send local frames?
			// send frame via network, but ignore received frames from others
			transformed_frame = frame_serialize(frame);
			printf("sending local frame via mcast ...\n");
			if (0 > send_frame(transformed_frame)) {
				// TODO: replace perror calls?
				perror("Could not send frame!\n");
				exit(1);
			}
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

static void timer_cb(int fd, short what, void *data)
{
	struct wmediumd *ctx = data;

	deliver_expired_frames(ctx);
	rearm_timer(ctx);
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

	if(connect_frame_distribution_socket() == EXIT_FAILURE) {
		fprintf(stderr, "Could not open frame distribution channel!\n");
		return EXIT_FAILURE;
	}

	/* init netlink */
	init_netlink();
	event_set(&ev_cmd, nl_socket_get_fd(ctx.sock), EV_READ | EV_PERSIST,
		  sock_event_cb, &ctx);
	event_add(&ev_cmd, NULL);

	/* setup timers */
	ctx.timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	event_set(&ev_timer, ctx.timerfd, EV_READ | EV_PERSIST, timer_cb, &ctx);
	event_add(&ev_timer, NULL);

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
		printf("REGISTER SENT!\n");

	/* enter libevent main loop */
	event_dispatch();

	free(ctx.sock);
	free(ctx.cb);
	free(ctx.cache);
	free(ctx.family);

	disconnect_frame_distribution_socket();

	return EXIT_SUCCESS;
}
