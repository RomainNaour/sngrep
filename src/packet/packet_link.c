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
 * @file packet_rtcp.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in packet_link.h
 */

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include "packet_ip.h"
#include "packet_link.h"


void
packet_parse_link(packet_t *packet, sng_buff_t data, int linktype)
{
    // Get Layer header size from link type
    size_t offset = packet_link_size(linktype);

    // For ethernet, skip VLAN header if present
    if (linktype == DLT_EN10MB) {
        struct ether_header *eth = (struct ether_header *) data.ptr;
        if (ntohs(eth->ether_type) == ETHERTYPE_8021Q) {
            offset += 4;
        }
    }

    // Not enough data
    if (data.len <= offset)
        return;

    // Update pending data
    data = sng_buff_shift(data, offset);

    // Try to parse next headers
    packet_parse_ip(packet, data);
}

int8_t
packet_link_size(int linktype)
{
    // Datalink header size
    switch (linktype) {
        case DLT_EN10MB:
            return 14;
        case DLT_IEEE802:
            return 22;
        case DLT_LOOP:
        case DLT_NULL:
            return 4;
        case DLT_SLIP:
        case DLT_SLIP_BSDOS:
            return 16;
        case DLT_PPP:
        case DLT_PPP_BSDOS:
        case DLT_PPP_SERIAL:
        case DLT_PPP_ETHER:
            return 4;
        case DLT_RAW:
            return 0;
        case DLT_FDDI:
            return 21;
        case DLT_ENC:
            return 12;
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            return 16;
#endif
#ifdef DLT_IPNET
        case DLT_IPNET:
            return 24;
#endif
        default:
            // Not handled datalink type
            return -1;
    }
}

