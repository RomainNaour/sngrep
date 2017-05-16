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
 * @file packet_sip.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage SIP packets
 *
 */
#ifndef __SNGREP_PACKET_SIP_H
#define __SNGREP_PACKET_SIP_H

#include <stdbool.h>

#include "util/buffer.h"
#include "packet.h"
#include "packet_sdp.h"

#define SIP_CRLF            "\r\n"
#define SIP_VERSION         "SIP/2.0"
#define SIP_VERSION_LEN     7
#define SIP_MAX_PAYLOAD     10240

//! SIP Method ids
enum sip_method_ids {
    SIP_METHOD_REGISTER     = 1,
    SIP_METHOD_INVITE,
    SIP_METHOD_SUBSCRIBE,
    SIP_METHOD_NOTIFY,
    SIP_METHOD_OPTIONS,
    SIP_METHOD_PUBLISH,
    SIP_METHOD_MESSAGE,
    SIP_METHOD_CANCEL,
    SIP_METHOD_BYE,
    SIP_METHOD_ACK,
    SIP_METHOD_PRACK,
    SIP_METHOD_INFO,
    SIP_METHOD_REFER,
    SIP_METHOD_UPDATE,
    SIP_METHOD_DO,
    SIP_METHOD_QAUTH,
    SIP_METHOD_SPRACK
};

//! SIP Wanted Header ids
enum sip_header_ids {
	SIP_HEADER_CALLID	    = 1,
	SIP_HEADER_FROM,
	SIP_HEADER_TO,
	SIP_HEADER_CSEQ,
	SIP_HEADER_XCALLID,
	SIP_HEADER_CONTENTLEN,	
	SIP_HEADER_CONTENTTYPE
};

//! Return values for sip_validate_packet
enum sip_payload_status {
    SIP_PAYLOAD_INVALID     = -1,
    SIP_PAYLOAD_INCOMPLETE  = 0,
    SIP_PAYLOAD_VALID       = 1
};


//! SIP Method struct
struct sip_method {
    int id;
    const char *text;
};

//! SIP Headers struct
struct sip_header {
	int id;
	const char *name;
	const char *compact;
};

//! Forward declaration structures
struct packet;

//! SIP specific packet data
struct sip_pvt
{
	//! SIP Request or Response
	bool isrequest;

	//! SIP CSeq
	int cseq;

	union {
		//! Request data
		struct {
			int method;
			sng_str_t text;
		} request;
		//! Response data
		struct{
			int code;
			sng_str_t text;
		} response;
	};
	
	//! SIP content payload
	sng_str_t payload;

	//! SIP Headers value
	sng_str_t callid;
	sng_str_t from;
	sng_str_t fromuser;
	sng_str_t to;
	sng_str_t touser;
	sng_str_t xcallid;
	sng_str_t contentlen;
	sng_str_t contenttype;

	//! SDP packet specific data
	struct sdp_pvt *sdp;
};

int
packet_sip_req_method(sng_str_t data);

void
packet_parse_sip(struct packet *packet, sng_buff_t data);

#endif /* __SNGREP_PACKET_SIP_H */
