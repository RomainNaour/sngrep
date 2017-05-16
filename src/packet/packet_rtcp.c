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
 * @brief Source of functions defined in packet_rtcp.h
 */

#include "config.h"
#include <stddef.h>
#include <stdlib.h>
#include "util/util.h"
#include "packet_rtcp.h"

void
packet_parse_rtcp(packet_t *packet, sng_buff_t data)
{
    // Extract the first payload byte
    struct rtcp_hdr_generic *hdr = (struct rtcp_hdr_generic*) data.ptr;

    if ((data.len >= RTCP_HDR_LENGTH) &&
        (RTP_VERSION(*data.ptr) == RTP_VERSION_RFC1889) &&
        (data.ptr[0] > 127 && data.ptr[0] < 192) &&
        (hdr->type >= 192 && hdr->type <= 223)) {

        // Interesting packet :-m! Clone it!
        packet_t *rtcp_packet = packet_clone(packet);
        packet_add_type(rtcp_packet, PACKET_TYPE_RTP);

        // Add this type to the packet
        rtcp_packet->rtcp = sng_malloc(sizeof(struct rtcp_pvt));

        // Parse all packet payload headers
        while (data.len) {

            // Check we have at least rtcp generic info
            if (data.len < sizeof(struct rtcp_hdr_generic))
                break;

            // Get data from the initial header bytes
            struct rtcp_hdr_generic *hdr = (struct rtcp_hdr_generic *) data.ptr;

            // Check RTP version
            if (RTP_VERSION(hdr->version) != RTP_VERSION_RFC1889)
                break;

            // Check RTCP packet header typ
            if (hdr->type == RTCP_HDR_SR) {
                // Get Sender Report header
                struct rtcp_hdr_sr *hdr_sr = (struct rtcp_hdr_sr *) data.ptr;
                rtcp_packet->rtcp->spc = ntohl(hdr_sr->spc);
            } else if (hdr->type == RTCP_XR) {
                // Get Sender Report Extended header
                struct rtcp_hdr_xr *hdr_xr = (struct rtcp_hdr_xr *) data.ptr;
				sng_buff_t xrdata = data;
				xrdata.len = ntohs(hdr_xr->len) * 4 + 4;

                // Read all report blocks
                while (xrdata.len) {
                    // Read block header
                    struct rtcp_blk_xr * blk_xr = (struct rtcp_blk_xr *) xrdata.ptr;

                    // Check block type
                    if (blk_xr->type == RTCP_XR_VOIP_METRCS) {
                        // Fill RTCP information
                        struct rtcp_blk_xr_voip *blk_xr_voip = (struct rtcp_blk_xr_voip *) xrdata.ptr;
                        rtcp_packet->rtcp->fdiscard = blk_xr_voip->drate;
                        rtcp_packet->rtcp->flost = blk_xr_voip->lrate;
                        rtcp_packet->rtcp->mosl = blk_xr_voip->moslq;
                        rtcp_packet->rtcp->mosc = blk_xr_voip->moscq;
                    }
					xrdata = sng_buff_shift(xrdata, ntohs(blk_xr->len) * 4 + 4);
                }
            } else {
                // Not handled headers. Skip the rest of this packet
                break;
            }

            // Go to the next header (if any)
			data = sng_buff_shift(data, ntohs(hdr->len) * 4 + 4);
        }

        packet_dump(rtcp_packet, "RTCP");

    }
}
