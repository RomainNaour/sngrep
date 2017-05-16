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
 * @file packet_rtp.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage RTP packets
 *
 */

#ifndef __SNGREP_PACKET_RTP_H
#define __SNGREP_PACKET_RTP_H

#include "util/buffer.h"
#include "packet.h"

// Version is the first 2 bits of the first octet
#define RTP_VERSION(octet) ((octet) >> 6)
// Payload type is the last 7 bits
#define RTP_PAYLOAD_TYPE(octet) ((octet) & 0x7F)
// Handled RTP versions
#define RTP_VERSION_RFC1889 2
// RTP header length
#define RTP_HDR_LENGTH 12

//! Shorter declaration of rtp_encoding structure
typedef struct rtp_encoding rtp_encoding_t;

//! Struct to store well-known RTP formats
struct rtp_encoding {
    const u_char id;
    const char *name;
    const char *format;
};

//! Packet RTP information
struct rtp_pvt {
    //! Packet payload type
    u_char ptype;
};

void
packet_parse_rtp(packet_t *packet, sng_buff_t data);


#endif /* __SNGREP_PACKET_RTP_H */
