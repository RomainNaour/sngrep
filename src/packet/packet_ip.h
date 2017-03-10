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
 * @file packet_ip.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage IPv4 and IPv6 protocol
 *
 */
#ifndef __SNGREP_PACKET_IP_H
#define __SNGREP_PACKET_IP_H

#include "config.h"

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif

#include <netinet/ip.h>
#include <stdbool.h>
#include "packet/packet.h"
#include "util/vector.h"

//! Shorter declaration of ip_frag_data structure
typedef struct ip_frag_data ip_frag_data_t;

//! @brief IP assembly data.
struct ip_frag_data
{
    //! Packet IP addresses
    address_t src, dst;
    // IP version
    uint32_t version;
    // IP transport proto
    uint8_t proto;
    // IP header size
    uint32_t hl;
    // Fragment offset
    uint16_t off;
    // IP content len
    uint16_t len;
    // Fragmentation flag
    uint16_t frag;
    // Fragmentation identifier
    uint32_t id;
    // Fragmentation offset
    uint16_t frag_off;
    //! More fragments expected
    uint16_t more;
    //! Packet with this frame data
    packet_t *packet;
};

void
packet_parse_ip(packet_t *packet, sng_buff_t data);

packet_t *
packet_ip_reassembly(ip_frag_data_t *fragment);

void
packet_ip_reassembly_offset_sorter(vector_t *vector, void *item);

void
packet_ip_reassembly_remove(vector_t *fragments);

/**
 * @brief Reassembly capture IP fragments
 *
 * This function will try to assemble received PCAP data into a single IP packet.
 * It will return a packet structure if no fragmentation is found or a full packet
 * has been assembled.
 *
 * @note We assume packets higher than MAX_CAPTURE_LEN won't be SIP. This has been
 * done to avoid reassembling too big packets, that aren't likely to be interesting
 * for sngrep.
 *
 * TODO
 * Assembly only works when all of the IP fragments are received in the good order.
 * Properly check memory boundaries during packet reconstruction.
 * Implement a way to timeout pending IP fragments after some time.
 * TODO
 *
 * @param capinfo Packet capture session information
 * @para header Header received from libpcap callback
 * @para packet Packet contents received from libpcap callback
 * @param size Packet size (not including Layer and Network headers)
 * @param caplen Full packet size (current fragment -> whole assembled packet)
 * @return a Packet structure when packet is not fragmented or fully reassembled
 * @return NULL when packet has not been completely assembled
 */
/*
packet_t *
capture_packet_reasm_ip(capture_info_t *capinfo, const struct pcap_pkthdr *header,
                        u_char *packet, uint32_t *size, uint32_t *caplen);
*/
#endif
