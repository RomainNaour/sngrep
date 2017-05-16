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
 * @file packet_rtcp.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions and definitions to manage RTCP packets
 *
 */

#ifndef __SNGREP_PACKET_RTCP_H
#define __SNGREP_PACKET_RTCP_H

#include "util/buffer.h"
#include "packet_rtp.h"
#include "packet.h"

// RTCP common header length
#define RTCP_HDR_LENGTH 4

// RTCP header types
//! http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
enum rtcp_header_types
{
    RTCP_HDR_SR = 200,
    RTCP_HDR_RR,
    RTCP_HDR_SDES,
    RTCP_HDR_BYE,
    RTCP_HDR_APP,
    RTCP_RTPFB,
    RTCP_PSFB,
    RTCP_XR,
    RTCP_AVB,
    RTCP_RSI,
    RTCP_TOKEN,
};

//! http://www.iana.org/assignments/rtcp-xr-block-types/rtcp-xr-block-types.xhtml
enum rtcp_xr_block_types
{
    RTCP_XR_LOSS_RLE = 1,
    RTCP_XR_DUP_RLE,
    RTCP_XR_PKT_RXTIMES,
    RTCP_XR_REF_TIME,
    RTCP_XR_DLRR,
    RTCP_XR_STATS_SUMRY,
    RTCP_XR_VOIP_METRCS,
    RTCP_XR_BT_XNQ,
    RTCP_XR_TI_VOIP,
    RTCP_XR_PR_LOSS_RLE,
    RTCP_XR_MC_ACQ,
    RTCP_XR_IDMS
};

//! Packet RTCP information
struct rtcp_pvt {
    //! Sender packet count
    uint32_t spc;
    //! Fraction lost x/256
    uint8_t flost;
    //! uint8_t discarded x/256
    uint8_t fdiscard;
    //! MOS - listening Quality
    uint8_t mosl;
    //! MOS - Conversational Quality
    uint8_t mosc;
};

struct rtcp_hdr_generic
{
    //! version (V): 2 bits
    uint8_t version;
    //! packet type (PT): 8 bits
    uint8_t type;
    //! length: 16 bits
    uint16_t len;
};

struct rtcp_hdr_sr
{
    //! version (V): 2 bits
    uint8_t version:2;
    //! padding (P): 1 bit
    uint8_t padding:1;
    //! reception report count (RC): 5 bits
    uint8_t rcount:5;
    //! packet type (PT): 8 bits
    uint8_t type;
    //! length: 16 bits
    uint16_t len;
    //! SSRC: 32 bits
    uint32_t ssrc;
    //! NTP timestamp: 64 bits
    uint64_t ntpts;
    //! RTP timestamp: 32 bits
    uint32_t rtpts;
    //! sender's packet count: 32 bits
    uint32_t spc;
    //! sender's octet count: 32 bits
    uint32_t soc;
};

struct rtcp_blk_sr
{
    //! SSRC_n (source identifier): 32 bits
    uint32_t ssrc;
    //! fraction lost: 8 bits
    uint8_t flost;
    //! cumulative number of packets lost: 24 bits
    struct {
        uint8_t pl1;
        uint8_t pl2;
        uint8_t pl3;
    } plost;
    //! extended highest sequence number received: 32 bits
    uint32_t hseq;
    //! interarrival jitter: 32 bits
    uint32_t ijitter;
};

struct rtcp_hdr_xr
{
    //! version (V): 2 bits
    uint8_t version:2;
    //! padding (P): 1 bit
    uint8_t padding:1;
    //! reserved: 5 bits
    uint8_t reserved:5;
    //! packet type (PT): 8 bits
    uint8_t type;
    //! length: 16 bits
    uint16_t len;
    //! SSRC: 32 bits
    uint32_t ssrc;
};

struct rtcp_blk_xr
{
    //! block type (BT): 8 bits
    uint8_t type;
    //! type-specific: 8 bits
    uint8_t specific;
    //! length: 16 bits
    uint16_t len;
};

struct rtcp_blk_xr_voip
{
    //! block type (BT): 8 bits
    uint8_t type;
    //! type-specific: 8 bits
    uint8_t reserved;
    //! length: 16 bits
    uint16_t len;
    //! SSRC: 32 bits
    uint32_t ssrc;
    //! loss rate: 8 bits
    uint8_t lrate;
    //! discard rate: 8 bits
    uint8_t drate;
    //! burst density: 8 bits
    uint8_t bdens;
    //! gap density: 8 bits
    uint8_t gdens;
    //! burst duration: 16 bits
    uint16_t bdur;
    //! gap duration: 16 bits
    uint16_t gdur;
    //! round trip delay: 16 bits
    uint16_t rtd;
    //! end system delay: 16 bits
    uint16_t esd;
    //! signal level: 8 bits
    uint8_t slevel;
    //! noise level: 8 bits
    uint8_t nlevel;
    //! residual echo return loss (RERL): 8 bits
    uint8_t rerl;
    //! Gmin: 8 bits
    uint8_t gmin;
    //! R factor: 8 bits
    uint8_t rfactor;
    //! ext. R factor: 8 bits
    uint8_t xrfactor;
    //! MOS-LQ: 8 bits
    uint8_t moslq;
    //! MOS-CQ: 8 bits
    uint8_t moscq;
    //! receiver configuration byte (RX config): 8 bits
    uint8_t rxc;
    //! packet loss concealment (PLC): 2 bits
    uint8_t plc:2;
    //! jitter buffer adaptive (JBA): 2 bits
    uint8_t jba:2;
    //! jitter buffer rate (JB rate): 4 bits
    uint8_t jbrate:4;
    //! reserved: 8 bits
    uint8_t reserved2;
    //! jitter buffer nominal delay (JB nominal): 16 bits
    uint16_t jbndelay;
    //! jitter buffer maximum delay (JB maximum): 16 bits
    uint16_t jbmdelay;
    //! jitter buffer absolute maximum delay (JB abs max): 16 bits
    uint16_t jbadelay;
};

void
packet_parse_rtcp(packet_t *packet, sng_buff_t data);

#endif /* __SNGREP_PACKET_RTCP_H */
