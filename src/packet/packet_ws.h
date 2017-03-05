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
 * @file capture_ws.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to WebSockets protocol
 *
 */

#ifndef __SNGREP_PACKET_WS_H
#define __SNGREP_PACKET_WS_H

#include "config.h"
#include "packet/packet.h"
#include "capture/capture.h"

//! Define Websocket Transport codes
#define WH_FIN      0x80
#define WH_RSV      0x70
#define WH_OPCODE   0x0F
#define WH_MASK     0x80
#define WH_LEN      0x7F
#define WS_OPCODE_TEXT 0x1

/**
 * @brief Check if given payload belongs to a Websocket connection
 *
 * Parse the given payload and determine if given payload could belong
 * to a Websocket packet. This function will change the payload pointer
 * apnd size content to point to the SIP payload data.
 *
 * @return 0 if packet is websocket, 1 otherwise
 */
int
capture_ws_check_packet(packet_t *packet);

#endif
