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
 * @file packet_udp.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in packet_udp.h
 *
 * Support for UDP transport layer
 *
 */
#include "config.h"
#include <netinet/udp.h>
#include "packet_udp.h"

void
packet_parse_udp(packet_t *packet, sng_buff_t data)
{
    struct udphdr *udp  = (struct udphdr *) data.ptr;
    uint16_t udp_off = sizeof(struct udphdr);

    // Check payload can contain an UDP header
    if (data.len < udp_off)
        return;

    // Set packet ports
#ifdef __FAVOR_BSD
    packet->src.port = htons(udp->uh_sport);
    packet->dst.port = htons(udp->uh_dport);
#else
    packet->src.port = htons(udp->source);
    packet->dst.port = htons(udp->dest);
#endif

    // Get pending payload
    data = sng_buff_shift(data, udp_off);

    // Check if this packet contains RTP
    packet_parse_rtp(packet, data);

    // Check if this packet contains RTCP
    if (!packet_has_type(packet, PACKET_TYPE_RTP)) {
        packet_parse_rtcp(packet, data);
    }

    // Check if this packet contains SIP
    if (!packet_has_type(packet, PACKET_TYPE_RTCP)) {
        packet_parse_sip(packet, data);
    }
}

