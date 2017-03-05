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
 * @file packet_ws.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in packet_ws.h
 *
 * Support for SIP over WS
 *
 */

#include "config.h"
#include <string.h>
#include "capture/capture.h"
#include "util/util.h"
#include "packet_ws.h"

int
capture_ws_check_packet(packet_t *packet)
{
    int ws_off = 0;
    u_char ws_fin;
    u_char ws_opcode;
    u_char ws_mask;
    uint8_t ws_len;
    u_char ws_mask_key[4];
    u_char *payload, *newpayload;
    uint32_t size_payload;
    int i;

    /**
     * WSocket header definition according to RFC 6455
     *     0                   1                   2                   3
     *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *    +-+-+-+-+-------+-+-------------+-------------------------------+
     *    |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     *    |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     *    |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     *    | |1|2|3|       |K|             |                               |
     *    +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     *    |     Extended payload length continued, if payload len == 127  |
     *    + - - - - - - - - - - - - - - - +-------------------------------+
     *    |                               |Masking-key, if MASK set to 1  |
     *    +-------------------------------+-------------------------------+
     *    | Masking-key (continued)       |          Payload Data         |
     *    +-------------------------------- - - - - - - - - - - - - - - - +
     *    :                     Payload Data continued ...                :
     *    + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     *    |                     Payload Data continued ...                |
     *    +---------------------------------------------------------------+
     */

    // Get payload from packet(s)
    size_payload = packet_payloadlen(packet);
    payload = packet_payload(packet);

    // Check we have payload
    if (size_payload == 0)
        return 0;

    // Flags && Opcode
    ws_fin = (*payload & WH_FIN) >> 4;
    ws_opcode = *payload & WH_OPCODE;
    ws_off++;

    // Only interested in Ws text packets
    if (ws_opcode != WS_OPCODE_TEXT)
        return 0;

    // Masked flag && Payload len
    ws_mask = (*(payload + ws_off) & WH_MASK) >> 4;
    ws_len = (*(payload + ws_off) & WH_LEN);
    ws_off++;

    // Skip Payload len
    switch (ws_len) {
            // Extended
        case 126:
            ws_off += 2;
            break;
        case 127:
            ws_off += 8;
            break;
        default:
            return 0;
    }

    // Get Masking key if mask is enabled
    if (ws_mask) {
        memcpy(ws_mask_key, (payload + ws_off), 4);
        ws_off += 4;
    }

    // Skip Websocket headers
    size_payload -= ws_off;
    if ((int32_t) size_payload <= 0)
        return 0;

    newpayload = sng_malloc(size_payload);
    memcpy(newpayload, payload + ws_off, size_payload);
    // If mask is enabled, unmask the payload
    if (ws_mask) {
        for (i = 0; i < size_payload; i++)
            newpayload[i] = newpayload[i] ^ ws_mask_key[i % 4];
    }
    // Set new packet payload into the packet
    packet_set_payload(packet, newpayload, size_payload);
    // Free the new payload
    sng_free(newpayload);

    if (packet->type == PACKET_SIP_TLS) {
        packet_set_type(packet, PACKET_SIP_WSS);
    } else {
        packet_set_type(packet, PACKET_SIP_WS);
    }
    return 1;
}

