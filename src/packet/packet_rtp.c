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
 * @file packet_rtp.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in packet_rtp.h
 */

#include "config.h"
#include <stddef.h>
#include <stdlib.h>
#include "util/util.h"
#include "packet_rtp.h"

//! Well-known RTP encodings
//rtp_encoding_t encodings[] = {
//    { 0,    "PCMU/8000",    "g711u" },
//    { 3,    "GSM/8000",     "gsm"   },
//    { 4,    "G723/8000",    "g723"  },
//    { 5,    "DVI4/8000",    "dvi"   },
//    { 6,    "DVI4/16000",   "dvi"   },
//    { 7,    "LPC/8000",     "lpc"   },
//    { 8,    "PCMA/8000",    "g711a" },
//    { 9,    "G722/8000",    "g722"  },
//    { 10,   "L16/44100",    "l16"   },
//    { 11,   "L16/44100",    "l16"   },
//    { 12,   "QCELP/8000",   "qcelp" },
//    { 13,   "CN/8000",      "cn"    },
//    { 14,   "MPA/90000",    "mpa"   },
//    { 15,   "G728/8000",    "g728"  },
//    { 16,   "DVI4/11025",   "dvi"   },
//    { 17,   "DVI4/22050",   "dvi"   },
//    { 18,   "G729/8000",    "g729"  },
//    { 25,   "CelB/90000",   "celb"  },
//    { 26,   "JPEG/90000",   "jpeg"  },
//    { 28,   "nv/90000",     "nv"    },
//    { 31,   "H261/90000",   "h261"  },
//    { 32,   "MPV/90000",    "mpv"   },
//    { 33,   "MP2T/90000",   "mp2t"  },
//    { 34,   "H263/90000",   "h263"  },
//    { 0,    NULL,           NULL    }
//};


void
packet_parse_rtp(packet_t *packet, sng_buff_t data)
{
    // Extract the first payload byte
    u_char pt = RTP_PAYLOAD_TYPE(*(data.ptr + 1));

    if ((data.len >= RTP_HDR_LENGTH) &&
        (RTP_VERSION(*data.ptr) == RTP_VERSION_RFC1889) &&
        (data.ptr[0] > 127 && data.ptr[0] < 192) &&
        (pt <= 64 || pt >= 96)) {

        // Interesting packet :-m! Clone it!
        packet_t *rtp_packet = packet_clone(packet);
        packet_add_type(rtp_packet, PACKET_TYPE_RTP);

        // Allocate memory for RTP data
        rtp_packet->rtp = sng_malloc(sizeof(struct rtp_pvt));
        rtp_packet->rtp->ptype = pt;


        packet_dump(rtp_packet, "RTP");
    }
}
