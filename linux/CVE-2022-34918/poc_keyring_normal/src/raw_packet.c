#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "raw_packet.h"

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                unsigned int frame_size, unsigned int block_nr,
                                unsigned int sizeof_priv, unsigned int timeout) {
    int v = TPACKET_V3;
    int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (rv < 0) {
        die("setsockopt(PACKET_VERSION): %m");
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = timeout;
    req.tp_sizeof_priv = sizeof_priv;
    req.tp_feature_req_word = 0;

    rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rv < 0) {
        die("setsockopt(PACKET_RX_RING): %m");
    }
}

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                        unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        die("socket(AF_PACKET): %m");
    }

    packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
                               sizeof_priv, timeout);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    sa.sll_halen = 0;

    int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rv < 0) {
        die("bind(AF_PACKET): %m");
    }

    return s;
}

int pagealloc_pad(int count, int size) {
    return packet_socket_setup(size, 2048, count, 0, 100);
}
