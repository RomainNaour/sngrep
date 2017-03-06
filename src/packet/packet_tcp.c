/**************************************************************************
 **
 ** sngrep - SIP Messages flow viewer
 **
 ** Copyright (C) 2013-2016 Ivan Alonso (Kaian)
 ** Copyright (C) 2013-2016 Irontec SL. All rights reserved.
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **
 ****************************************************************************/
/**
 * @file capture_tcp.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in capture_tcp.h
 *
 * Support for TCP transport layer
 *
 */

#include "config.h"
#include "capture/capture.h"
#include "util/util.h"
#include "sip.h"
#include "packet_ws.h"
#include "packet_tcp.h"

// Capture information
extern capture_config_t capture_cfg;

packet_t *
capture_packet_reasm_tcp(packet_t *packet, struct tcphdr *tcp, u_char *payload, int size_payload) {

    vector_iter_t it = vector_iterator(capture_cfg.tcp_reasm);
    packet_t *pkt;
    u_char *new_payload;
    u_char full_payload[MAX_CAPTURE_LEN + 1];

    //! Assembled
    if ((int32_t) size_payload <= 0)
        return packet;

    while ((pkt = vector_iterator_next(&it))) {
        if (addressport_equals(pkt->src, packet->src) &&
                addressport_equals(pkt->dst, packet->dst)) {
            break;
        }
    }

    // If we already have this packet stored
    if (pkt) {
        frame_t *frame;
        // Append this frames to the original packet
        vector_iter_t frames = vector_iterator(packet->frames);
        while ((frame = vector_iterator_next(&frames)))
            packet_add_frame(pkt, frame->header, frame->data);
        // Destroy current packet as its frames belong to the stored packet
        packet_destroy(packet);
    } else {
        // First time this packet has been seen
        pkt = packet;
        // Add To the possible reassembly list
        vector_append(capture_cfg.tcp_reasm, packet);
    }

    // Store firt tcp sequence
    if (pkt->tcp_seq == 0) {
        pkt->tcp_seq = ntohl(tcp->th_seq);
    }

    // If the first frame of this packet
    if (vector_count(pkt->frames) == 1) {
        // Set initial payload
        packet_set_payload(pkt, payload, size_payload);
    } else {
        // Check payload length. Dont handle too big payload packets
        if (pkt->payload_len + size_payload > MAX_CAPTURE_LEN) {
            packet_destroy(pkt);
            vector_remove(capture_cfg.tcp_reasm, pkt);
            return NULL;
        }
        new_payload = sng_malloc(pkt->payload_len + size_payload);
        if (pkt->tcp_seq < ntohl(tcp->th_seq)) {
            // Append payload to the existing
            pkt->tcp_seq =  ntohl(tcp->th_seq);
            memcpy(new_payload, pkt->payload, pkt->payload_len);
            memcpy(new_payload + pkt->payload_len, payload, size_payload);
        } else {
            // Prepend payload to the existing
            memcpy(new_payload, payload, size_payload);
            memcpy(new_payload + size_payload, pkt->payload, pkt->payload_len);
        }
        packet_set_payload(pkt, new_payload, pkt->payload_len + size_payload);
        sng_free(new_payload);
    }

    // Store full payload content
    memset(full_payload, 0, MAX_CAPTURE_LEN);
    memcpy(full_payload, pkt->payload, pkt->payload_len);

    // This packet is ready to be parsed
    int valid = sip_validate_packet(pkt);
    if (valid == VALIDATE_COMPLETE_SIP) {
        // Full SIP packet!
        vector_remove(capture_cfg.tcp_reasm, pkt);
        return pkt;
    } else if (valid == VALIDATE_MULTIPLE_SIP) {
        vector_remove(capture_cfg.tcp_reasm, pkt);

        // We have a full SIP Packet, but do not remove everything from the reasm queue
        packet_t *cont = packet_clone(pkt);
        int pldiff = size_payload - pkt->payload_len;
        packet_set_payload(cont, full_payload + pkt->payload_len, pldiff);
        vector_append(capture_cfg.tcp_reasm, cont);

        // Return the full initial packet
        return pkt;
    } else if (valid == VALIDATE_NOT_SIP) {
        // Not a SIP packet, store until PSH flag
        if (tcp->th_flags & TH_PUSH) {
            vector_remove(capture_cfg.tcp_reasm, pkt);
            return pkt;
        }
    }

    // An incomplete SIP Packet
    return NULL;
}

packet_t *
parse_packet_tcp(packet_t *packet, u_char *data, int size_payload)
{
    // TCP header data
    struct tcphdr *tcp;
    // TCP header size
    uint16_t tcp_off;
    // Packet payload data
    u_char *payload = NULL;

    // Get TCP header
    tcp = (struct tcphdr *) data;
    tcp_off = (tcp->th_off * 4);

    // Set packet ports
    packet->src.port = htons(tcp->th_sport);
    packet->dst.port = htons(tcp->th_dport);

    // Get actual payload size
    size_payload -= tcp_off;

    if ((int32_t)size_payload < 0)
        size_payload = 0;

    // Get payload start
    payload = (u_char *)(tcp) + tcp_off;

    // Complete packet with Transport information
    packet_set_type(packet, PACKET_SIP_TCP);
    packet_set_payload(packet, payload, size_payload);

    // Create a structure for this captured packet
    if (!(packet = capture_packet_reasm_tcp(packet, tcp, payload, size_payload)))
        return NULL;

#if defined(WITH_GNUTLS) || defined(WITH_OPENSSL)
    // Check if packet is TLS
    if (capture_cfg.keyfile) {
        tls_process_segment(packet, tcp);
    }
#endif

    // Check if packet is WS or WSS
    capture_ws_check_packet(packet);

    return packet;
}

