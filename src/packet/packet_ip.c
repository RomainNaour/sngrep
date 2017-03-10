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
#include "packet_tcp.h"
#include "packet_udp.h"
#include "packet_ip.h"

// Vector of ip_frag_data_t
vector_t *ip_reasm = NULL;

void
packet_parse_ip(packet_t *packet, sng_buff_t data)
{
    ip_frag_data_t fragment = {};

    // Get IP header
    struct ip *ip4 = (struct ip *) data.ptr;

#ifdef USE_IPV6
    // Get IPv6 header
    struct ip6_hdr *ip6 = (struct ip6_hdr *) data.ptr;
#endif

    // Set Fragment packet
    fragment.packet = packet;

    // Set IP version
    fragment.version  = ip4->ip_v;

    // Get IP version
    switch (fragment.version) {
        case 4:
            fragment.hl = ip4->ip_hl * 4;
            fragment.proto = ip4->ip_p;
            fragment.off = ntohs(ip4->ip_off);
            fragment.len = ntohs(ip4->ip_len);

            fragment.frag = fragment.off & (IP_MF | IP_OFFMASK);
            fragment.frag_off = (fragment.frag) ? (fragment.off & IP_OFFMASK) * 8 : 0;
            fragment.id = ntohs(ip4->ip_id);
            fragment.more = fragment.off & IP_MF;

            // Get source and destination IP addresses
            inet_ntop(AF_INET, &ip4->ip_src, packet->src.ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip4->ip_dst, packet->dst.ip, INET_ADDRSTRLEN);
            break;
#ifdef USE_IPV6
        case 6:
            fragment.hl = sizeof(struct ip6_hdr);
            fragment.proto = ip6->ip6_nxt;
            fragment.len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) + fragment.hl;

            if (fragment.proto == IPPROTO_FRAGMENT) {
                struct ip6_frag *ip6f = (struct ip6_frag *) (ip6 + fragment.hl);
                fragment.frag_off = ntohs(ip6f->ip6f_offlg & IP6F_OFF_MASK);
                fragment.id = ntohl(ip6f->ip6f_ident);
            }

            // Get source and destination IP addresses
            inet_ntop(AF_INET6, &ip6->ip6_src, packet->src.ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6->ip6_dst, packet->dst.ip, INET6_ADDRSTRLEN);
            break;
#endif
        default:
            return;
    }

    // IP packet without payload
    if (fragment.len == 0)
        return;

    // Get pending payload
    data = sng_buff_shift(data, fragment.hl);

    // Remove any payload trailer (trust IP len content field)
    data.len = fragment.len - fragment.hl;

    // This is an IP packet!
    packet_add_type(packet, PACKET_TYPE_IP);

    // Fragmented IP packet, try to assemble it
    if (fragment.frag) {
        // Allocate memory for this fragment
        ip_frag_data_t *packet_fragment = malloc(sizeof(ip_frag_data_t));
        memcpy(packet_fragment, &fragment, sizeof(ip_frag_data_t));

        // Store packet content
        packet->content = data;

        if (!(packet = packet_ip_reassembly(packet_fragment))) {
            return;
        }
        data = packet->content;
    }

    // Parsed supported IP packetcols
    switch (fragment.proto) {
        case IPPROTO_UDP:
            packet_parse_udp(packet, data);
            break;
        case IPPROTO_TCP:
            packet_parse_tcp(packet, data);
            break;
        default:
            // Not supported IP packetcol
            break;
    }
}

packet_t *
packet_ip_reassembly(ip_frag_data_t *fragment)
{
    //
    if (!ip_reasm) {
        ip_reasm = vector_create(5, 10);
    }

    packet_t *ret = fragment->packet;

    // Vector of IP fragments
    vector_t *fragments = vector_create(2, 1);
    vector_set_sorter(fragments, packet_ip_reassembly_offset_sorter);

    // Add current fragment to the reassembly list (you'll find yourself later)
    vector_append(ip_reasm, fragment);

    // Total IP fragments size
    size_t captured_len = 0;

    // Look for another fragments with same id in IP reassembly vector
    vector_iter_t it = vector_iterator(ip_reasm);
    ip_frag_data_t *other;
    while ((other = vector_iterator_next(&it))) {
        if (address_equals(fragment->src, other->src)
                && addressport_equals(fragment->dst, other->dst)
                && fragment->id == other->id) {
            captured_len += other->packet->content.len;
            vector_append(fragments, other);
        }
    }

    // If this is the first fragment, wait for the rest
    if (vector_count(fragments) <= 1) {
        return NULL;
    }

    // If last fragmet doesn't have 'No more fragments' wait for the rest
    ip_frag_data_t *last = vector_last(fragments);
    if (last->more) {
        return NULL;
    }

    // If we haven't received all the expected data
    if (captured_len < (last->frag_off + last->packet->content.len)) {
        return NULL;
    }

    // If captured length is too big, ignore this IP packet
    if (captured_len > MAX_CAPTURE_LEN) {
        packet_ip_reassembly_remove(fragments);
        return NULL;
    }


    // Assembly all the frames payload
    sng_buff_t data;
    data.ptr = malloc(captured_len);
    data.len = captured_len;

    it = vector_iterator(fragments);
    while ((fragment = vector_iterator_next(&it))) {
        //vector_append_vector(ret->frames, fragment->packet->frames);
        memcpy(data.ptr + fragment->frag_off,
               fragment->packet->content.ptr,
               fragment->packet->content.len);
    }


    // Remove all the packets from the reassembly queue
    packet_ip_reassembly_remove(fragments);

    // Set the new content to the packet
    ret->content = data;
    return ret;
}

void
packet_ip_reassembly_offset_sorter(vector_t *vector, void *item)
{
    ip_frag_data_t *cur = (ip_frag_data_t *) item;

    int i;
    for (i = vector_count(vector) - 2 ; i >= 0; i--) {
        ip_frag_data_t *prev = vector_item(vector, i);
        if (prev->frag_off < cur->frag_off) {
            vector_insert(vector, item, i + 1);
            return;
        }
    }

    // Put this item at the begining of the vector
    vector_insert(vector, item, 0);
}

void
packet_ip_reassembly_remove(vector_t *fragments)
{
    vector_iter_t it = vector_iterator(fragments);
    void *fragment = NULL;

    while ((fragment = vector_iterator_next(&it))) {
        vector_remove(ip_reasm, fragment);
    }
}

