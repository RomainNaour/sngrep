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
 * @file packet_ip.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in packet_ip.h
 *
 * Support for IPv4 and IPv6 packets
 *
 */

#include "config.h"
#include <netdb.h>
#include <string.h>
#include <stdbool.h>
#include "capture/capture.h"
#include "util/util.h"

// Capture information
extern capture_config_t capture_cfg;

packet_t *
capture_packet_reasm_ip(capture_info_t *capinfo, const struct pcap_pkthdr *header, u_char *packet, uint32_t *size, uint32_t *caplen)
{
    // IP header data
    struct ip *ip4;
#ifdef USE_IPV6
    // IPv6 header data
    struct ip6_hdr *ip6;
#endif
    // IP version
    uint32_t ip_ver;
    // IP protocol
    uint8_t ip_proto;
    // IP header size
    uint32_t ip_hl = 0;
    // Fragment offset
    uint16_t ip_off = 0;
    // IP content len
    uint16_t ip_len = 0;
    // Fragmentation flag
    uint16_t ip_frag = 0;
    // Fragmentation identifier
    uint32_t ip_id = 0;
    // Fragmentation offset
    uint16_t ip_frag_off = 0;
    //! Source Address
    address_t src = { };
    //! Destination Address
    address_t dst = { };
    //! Common interator for vectors
    vector_iter_t it;
    //! Packet containers
    packet_t *pkt;
    //! Storage for IP frame
    frame_t *frame;
    uint32_t len_data = 0;
    //! Link + Extra header size
    int8_t link_hl = capinfo->link_hl;

    // Skip VLAN header if present
    if (capinfo->link == DLT_EN10MB) {
        struct ether_header *eth = (struct ether_header *) packet;
        if (ntohs(eth->ether_type) == ETHERTYPE_8021Q) {
            link_hl += 4;
        }
    }

    // Get IP header
    ip4 = (struct ip *) (packet + link_hl);

#ifdef USE_IPV6
    // Get IPv6 header
    ip6 = (struct ip6_hdr *) (packet + link_hl);
#endif

    // Get IP version
    ip_ver = ip4->ip_v;

    switch (ip_ver) {
        case 4:
            ip_hl = ip4->ip_hl * 4;
            ip_proto = ip4->ip_p;
            ip_off = ntohs(ip4->ip_off);
            ip_len = ntohs(ip4->ip_len);

            ip_frag = ip_off & (IP_MF | IP_OFFMASK);
            ip_frag_off = (ip_frag) ? (ip_off & IP_OFFMASK) * 8 : 0;
            ip_id = ntohs(ip4->ip_id);

            inet_ntop(AF_INET, &ip4->ip_src, src.ip, sizeof(src.ip));
            inet_ntop(AF_INET, &ip4->ip_dst, dst.ip, sizeof(dst.ip));
            break;
#ifdef USE_IPV6
        case 6:
            ip_hl = sizeof(struct ip6_hdr);
            ip_proto = ip6->ip6_nxt;
            ip_len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) + ip_hl;

            if (ip_proto == IPPROTO_FRAGMENT) {
                struct ip6_frag *ip6f = (struct ip6_frag *) (ip6 + ip_hl);
                ip_frag_off = ntohs(ip6f->ip6f_offlg & IP6F_OFF_MASK);
                ip_id = ntohl(ip6f->ip6f_ident);
            }

            inet_ntop(AF_INET6, &ip6->ip6_src, src.ip, sizeof(src.ip));
            inet_ntop(AF_INET6, &ip6->ip6_dst, dst.ip, sizeof(dst.ip));
            break;
#endif
        default:
            return NULL;
    }

    // Fixup VSS trailer in ethernet packets
    *caplen = link_hl + ip_len;

    // Remove IP Header length from payload
    *size = *caplen - link_hl - ip_hl;

    // If no fragmentation
    if (ip_frag == 0) {
        // Just create a new packet with given network data
        pkt = packet_create(ip_ver, ip_proto, src, dst, ip_id);
        packet_add_frame(pkt, header, packet);
        return pkt;
    }

    // Look for another packet with same id in IP reassembly vector
    it = vector_iterator(capture_cfg.ip_reasm);
    while ((pkt = vector_iterator_next(&it))) {
        if (addressport_equals(pkt->src, src)
                && addressport_equals(pkt->dst, dst)
                && pkt->ip_id == ip_id) {
            break;
        }
    }

    // If we already have this packet stored, append this frames to existing one
    if (pkt) {
        packet_add_frame(pkt, header, packet);
    } else {
        // Add To the possible reassembly list
        pkt = packet_create(ip_ver, ip_proto, src, dst, ip_id);
        packet_add_frame(pkt, header, packet);
        vector_append(capture_cfg.ip_reasm, pkt);
    }

    // Add this IP content length to the total captured of the packet
    pkt->ip_cap_len += ip_len - ip_hl;

    // Calculate how much data we need to complete this packet
    // The total packet size can only be known using the last fragment of the packet
    // where 'No more fragments is enabled' and it's calculated based on the
    // last fragment offset
    if ((ip_off & IP_MF) == 0) {
        pkt->ip_exp_len = ip_frag_off + ip_len - ip_hl;
    }

    // If we have the whole packet (captured length is expected length)
    if (pkt->ip_cap_len == pkt->ip_exp_len) {
        // TODO Dont check the flag, check the holes
        // Calculate assembled IP payload data
        it = vector_iterator(pkt->frames);
        while ((frame = vector_iterator_next(&it))) {
            struct ip *frame_ip = (struct ip *) (frame->data + link_hl);
            len_data += ntohs(frame_ip->ip_len) - frame_ip->ip_hl * 4;
        }

        // Check packet content length
        if (len_data > MAX_CAPTURE_LEN)
            return NULL;

        // Initialize memory for the assembly packet
        memset(packet, 0, link_hl + ip_hl + len_data);

        it = vector_iterator(pkt->frames);
        while ((frame = vector_iterator_next(&it))) {
            // Get IP header
            struct ip *frame_ip = (struct ip *) (frame->data + link_hl);
            memcpy(packet + link_hl + ip_hl + (ntohs(frame_ip->ip_off) & IP_OFFMASK) * 8,
                   frame->data + link_hl + frame_ip->ip_hl * 4,
                   ntohs(frame_ip->ip_len) - frame_ip->ip_hl * 4);
        }

        *caplen = link_hl + ip_hl + len_data;
        *size = len_data;

        // Return the assembled IP packet
        vector_remove(capture_cfg.ip_reasm, pkt);
        return pkt;
    }

    return NULL;
}

