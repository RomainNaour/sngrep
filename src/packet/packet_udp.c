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
 * @file capture_udp.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in capture_udp.h
 *
 * Support for UDP transport layer
 *
 */

#include "config.h"
#include "capture/capture.h"
#include "util/util.h"
#include "sip.h"
#include "packet_udp.h"

packet_t *
parse_packet_udp(packet_t *packet, u_char *data, int size_payload)
{
    // UDP header data
    struct udphdr *udp = (struct udphdr *) data;
    // UDP header size
    uint16_t udp_off = sizeof(struct udphdr);

    // Set packet ports
    packet->src.port = htons(udp->uh_sport);
    packet->dst.port = htons(udp->uh_dport);

    // Remove UDP Header from payload
    size_payload -= udp_off;

    if ((int32_t)size_payload < 0)
        size_payload = 0;

    // Remove TCP Header from payload
    u_char *payload = (u_char *) (udp) + udp_off;

    // Complete packet with Transport information
    packet_set_type(packet, PACKET_SIP_UDP);
    packet_set_payload(packet, payload, size_payload);
    return packet;
}

