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
 * @file packet_sip.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in packet_sip.h
 */

#include "config.h"
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include "util/hash.h"
#include "util/util.h"
#include "packet_sip.h"

//! List of SIP methods
struct sip_method sip_methods[] = {
    { SIP_METHOD_REGISTER,      "REGISTER"      },
    { SIP_METHOD_INVITE,        "INVITE"        },
    { SIP_METHOD_SUBSCRIBE,     "SUBSCRIBE"     },
    { SIP_METHOD_NOTIFY,        "NOTIFY"        },
    { SIP_METHOD_OPTIONS,       "OPTIONS"       },
    { SIP_METHOD_PUBLISH,       "PUBLISH"       },
    { SIP_METHOD_MESSAGE,       "MESSAGE"       },
    { SIP_METHOD_CANCEL,        "CANCEL"        },
    { SIP_METHOD_BYE,           "BYE"           },
    { SIP_METHOD_ACK,           "ACK"           },
    { SIP_METHOD_PRACK,         "PRACK"         },
    { SIP_METHOD_INFO,          "INFO"          },
    { SIP_METHOD_REFER,         "REFER"         },
    { SIP_METHOD_UPDATE,        "UPDATE"        },
    { SIP_METHOD_DO,            "DO"            },
    { SIP_METHOD_QAUTH,         "QAUTH"         },
    { SIP_METHOD_SPRACK,        "SPRACK"        },
    { 0, 0 },
};

//! List of interesting SIP Headers
struct sip_header sip_headers[] = {
    { SIP_HEADER_CALLID,        "Call-Id",          "i"     },
    { SIP_HEADER_FROM,          "From",             "f"     },
    { SIP_HEADER_TO,            "To",               "t"     },
    { SIP_HEADER_CSEQ,          "CSeq",             NULL    },
    { SIP_HEADER_XCALLID,       "X-Call-Id",        NULL    },
    { SIP_HEADER_XCALLID,       "X-CID",            NULL    },
    { SIP_HEADER_CONTENTLEN,    "Content-Length",   "l"     },
    { SIP_HEADER_CONTENTTYPE,   "Content-Type",     "l"     },
    { 0, 0, 0 }
};

static sng_str_t
packet_sip_req_text(int id)
{
    int i;
    sng_str_t reqtext;
    for (i = 0; sip_methods[i].id; i++) {
        if (sip_methods[i].id == id) {
            reqtext.ptr = sip_methods[i].text;
            reqtext.len = strlen(reqtext.ptr);
        }
    }
    return reqtext;
}

int
packet_sip_req_method(sng_str_t data)
{
    int i;

    // Nope
    if (data.len < 124)
        return 0;

    // Check if SIP message starts with a method
    for (i = 0; sip_methods[i].id; i++) {
        size_t mlen = strlen(sip_methods[i].text);
        if (!strncmp(data.ptr, sip_methods[i].text, mlen)) {
            return sip_methods[i].id;
        }
    }

    // No method found
    return 0;
}

static int
packet_sip_resp_code(sng_str_t data)
{
    char code[4] = {};

    // Check if SIP message starts with SIP/2.0 followed by response code
    if (!strncmp(data.ptr, SIP_VERSION, SIP_VERSION_LEN)) {
        strncpy(code, data.ptr + 8, 3);
        if (isdigit(code[0]) && isdigit(code[1]) && isdigit(code[1])) {
            return atoi(code);
        }
    }

    // No numeric response code found
    return 0;
}

static sng_str_t
packet_sip_resp_text(sng_str_t data)
{
    // Skip SIP-Version Response-Code
    sng_str_t resptext = sng_str_shift(data, 12);
    // Limit to where Status-Line ends
    return sng_str_cut(resptext, SIP_CRLF);
}

static int
packet_parse_sip_hdr_name(sng_str_t line)
{
    // Strip header name
    sng_str_t header = sng_str_chomp(sng_str_cut(line, ":"));

    // If we got one header
    if (header.len == 0)
        return 0;

    // Compare with the known headers
    int i;
    for (i = 0; sip_headers[i].name; i++) {
        // Header standard name
        if (!strncasecmp(header.ptr, sip_headers[i].name, header.len))
            return sip_headers[i].id;

        // Header compact name
        if (sip_headers[i].compact
                && !strncasecmp(header.ptr, sip_headers[i].compact, header.len))
            return sip_headers[i].id;
    }

    // Not an interesting SIP header
    return 0;
}

static sng_str_t
packet_parse_sip_hdr_value(sng_str_t line)
{
    sng_str_t header = sng_str_chomp(sng_str_cut(line, ":"));
    return sng_str_chomp(sng_str_shift(line, header.len + 1));
}

static sng_str_t
packet_parse_sip_hdr_fromto(sng_str_t line)
{
    sng_str_t leading, value;
    leading = sng_str_cut(line, "sip:");
    value = sng_str_shift(line, leading.len + 4);
    value = sng_str_cut(value, ";");
    value = sng_str_cut(value, ">");
    return sng_str_chomp(value);
}

static sng_str_t
packet_parse_sip_hdr_fromtouser(sng_str_t line)
{
    return sng_str_cut(packet_parse_sip_hdr_fromto(line), "@");
}

static void
packet_dump_sip(packet_t *packet)
{
    packet_dump(packet, "SIP");

    if (packet->sip->isrequest) {
        printf("%s\n", sngstr(packet->sip->request.text));
    } else {
        printf("%d %s\n", packet->sip->response.code,
               sngstr(packet->sip->response.text));
    }

    if (packet->sip->callid.len)
        printf("\tCall-Id: %s\n", sngstr(packet->sip->callid));
    if (packet->sip->from.len)
        printf("\tFrom: %s\n", sngstr(packet->sip->from));
    if (packet->sip->fromuser.len)
        printf("\tFromUser: %s\n", sngstr(packet->sip->fromuser));
    if (packet->sip->to.len)
        printf("\tTo: %s\n", sngstr(packet->sip->to));
    if (packet->sip->touser.len)
        printf("\tToUser: %s\n", sngstr(packet->sip->touser));
    if (packet->sip->contentlen.len)
        printf("\tContent-Len: %s\n", sngstr(packet->sip->contentlen));
    if (packet->sip->contenttype.len)
        printf("\tContent-Type: %s\n", sngstr(packet->sip->contenttype));
    printf("--------------------------\n");
}

enum sip_payload_status
packet_sip_validate(sng_buff_t data)
{
    // Check we have payload
    if (!data.len)
        return SIP_PAYLOAD_INVALID;

    // We will handle this data as characters more than bytes
    sng_str_t payload = sng_buff_str(data);

    // Try to get SIP REQUEST or SIP RESPONSE data
    int method = packet_sip_req_method(payload);
    int code = packet_sip_resp_code(payload);

    // This seems a SIP payload
    if (method || code)
        return SIP_PAYLOAD_VALID;

    // TODO
    return SIP_PAYLOAD_INVALID;

}

void
packet_parse_sip(struct packet *packet, sng_buff_t data)
{

    // Validate if data is in fact SIP
    switch (packet_sip_validate(data)) {
        case SIP_PAYLOAD_INVALID:
        case SIP_PAYLOAD_INCOMPLETE:
            return;
        case SIP_PAYLOAD_VALID:
            /* fun */
            break;
    }

    // Interesting packet :-m! Clone it!
    packet_t *sip_packet = packet_clone(packet);
    packet_add_type(sip_packet, PACKET_TYPE_SIP);
    sip_packet->sip = sng_malloc(sizeof(struct sip_pvt));
    sip_packet->sip->payload = sng_buff_str(data);

    // Store SIP information
    struct sip_pvt *sip = sip_packet->sip;
    sng_str_t payload = sip->payload;

    // Check if SIP message starts with SIP/2.0 followed by response code
    if ((sip->response.code = packet_sip_resp_code(sip->payload)) > 0) {
        sip->response.text = packet_sip_resp_text(sip->payload);
        sip->isrequest = false;
        // Check if SIP message starts with a method
    } else if ((sip->request.method = packet_sip_req_method(sip->payload)) > 0) {
        sip->request.text = packet_sip_req_text(sip->request.method);
        sip->isrequest = true;
    } else {
        // You're not SIP fool!
        return;
    }

    // Skip Status-Line
    sng_str_t status = sng_str_cut(sip->payload, SIP_CRLF);
    payload = sng_str_shift(payload, status.len + strlen(SIP_CRLF));

    while (payload.len) {
        // Strip one line from payload
        sng_str_t line = sng_str_cut(payload, SIP_CRLF);

        // Move payload pointer to the next header
        payload = sng_str_shift(payload, line.len + strlen(SIP_CRLF));

        // End of SIP headers, remove any pending CRLF
        if (line.len == 0) {
            while (payload.len >= 2
                    && !strncmp(payload.ptr, SIP_CRLF, strlen(SIP_CRLF))) {
                payload = sng_str_shift(payload, strlen(SIP_CRLF));
            }
            break;
        }

        // Parse SIP payload headers
        switch (packet_parse_sip_hdr_name(line)) {
            case SIP_HEADER_CALLID:
                sip->callid = packet_parse_sip_hdr_value(line);
                break;
            case SIP_HEADER_FROM:
                sip->from = packet_parse_sip_hdr_fromto(line);
                sip->fromuser = packet_parse_sip_hdr_fromtouser(line);
                break;
            case SIP_HEADER_TO:
                sip->to = packet_parse_sip_hdr_fromto(line);
                sip->touser = packet_parse_sip_hdr_fromtouser(line);
                break;
            case SIP_HEADER_XCALLID:
                sip->xcallid = packet_parse_sip_hdr_value(line);
                break;
            case SIP_HEADER_CONTENTLEN:
                sip->contentlen = packet_parse_sip_hdr_value(line);
                break;
            case SIP_HEADER_CONTENTTYPE:
                sip->contenttype = packet_parse_sip_hdr_value(line);
                break;
            case SIP_HEADER_CSEQ:
                break;
            default:
                break;
        }
    }
    packet_set_payload(sip_packet, sip->payload.ptr, sip->payload.len);

    // dump the jam
    //packet_dump_sip(sip_packet);
    sip_check_packet(sip_packet);

    // Check if pending payload is a SIP message
    if (payload.len) {
        // Remove pending payload from current packet
        sip->payload.len -= payload.len;
        packet_parse_sip(packet, sng_str_buff(payload));
    }
}
