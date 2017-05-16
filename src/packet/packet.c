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
 * @file packet.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in packet.h
 *
 */
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "packet_sip.h"

packet_t *
packet_create(uint8_t ip_ver, uint8_t proto, address_t src, address_t dst, uint32_t id)
{
    // Create a new packet
    packet_t *packet;
    packet = malloc(sizeof(packet_t));
    memset(packet, 0, sizeof(packet_t));
    packet->ip_version = ip_ver;
    packet->proto = proto;
    packet->frames = vector_create(1, 1);
    packet->ip_id = id;
    packet->src = src;
    packet->dst = dst;
    return packet;
}

packet_t*
packet_clone(packet_t *packet)
{
    packet_t *clone;
    frame_t *frame;

    // Create a new packet with the original information
    clone =    packet_create(packet->ip_version, packet->proto, packet->src, packet->dst, packet->ip_id);
    clone->tcp_seq = packet->tcp_seq;

    // Append this frames to the original packet
    vector_iter_t frames = vector_iterator(packet->frames);
    while ((frame = vector_iterator_next(&frames)))
        packet_add_frame(clone, frame->header, frame->data);

    return clone;
}

void
packet_destroy(packet_t *packet)
{
    frame_t *frame;

    // Check we have a valid packet pointer
    if (!packet) return;

    // Destroy frames
    vector_iter_t it = vector_iterator(packet->frames);
    while ((frame = vector_iterator_next(&it))) {
        free(frame->header);
        free(frame->data);
    }

    // TODO Free remaining packet data
    vector_set_destroyer(packet->frames, vector_generic_destroyer);
    vector_destroy(packet->frames);
    free(packet);
}

void
packet_destroyer(void *packet)
{
    packet_destroy((packet_t*) packet);
}

void
packet_free_frames(packet_t *pkt)
{
    frame_t *frame;
    vector_iter_t it = vector_iterator(pkt->frames);

    while ((frame = vector_iterator_next(&it))) {
        free(frame->data);
        frame->data = NULL;
    }
}

packet_t *
packet_set_transport_data(packet_t *pkt, uint16_t sport, uint16_t dport)
{
    pkt->src.port = sport;
    pkt->dst.port = dport;
    return pkt;
}

frame_t *
packet_add_frame(packet_t *pkt, const struct pcap_pkthdr *header, const u_char *packet)
{
    frame_t *frame = malloc(sizeof(frame_t));
    frame->header = malloc(sizeof(struct pcap_pkthdr));
    memcpy(frame->header, header, sizeof(struct pcap_pkthdr));
    frame->data = malloc(header->caplen);
    memcpy(frame->data, packet, header->caplen);
    vector_append(pkt->frames, frame);
    return frame;
}

void
packet_set_type(packet_t *packet, enum packet_type type)
{
    packet->type = type;
}

void
packet_set_payload(packet_t *packet, u_char *payload, uint32_t payload_len)
{
    // Free previous payload
    packet->content.ptr = payload;
    packet->content.len = payload_len;
}

uint32_t
packet_payloadlen(packet_t *packet)
{
    //return packet->payload_len;
    return packet->content.len;
}

u_char *
packet_payload(packet_t *packet)
{
    //return packet->payload;
    return packet->content.ptr;
}

struct timeval
packet_time(packet_t *packet)
{
    frame_t *first;
    struct timeval ts = { 0 };

    // Return first frame timestamp
    if (packet && (first = vector_first(packet->frames))) {
        ts.tv_sec = first->header->ts.tv_sec;
        ts.tv_usec = first->header->ts.tv_usec;
    }

    // Return packe timestamp
    return ts;
}

void
packet_add_type(packet_t *packet, enum packet_types type)
{
    packet->types |= type;
}

bool
packet_has_type(packet_t *packet, enum packet_types type)
{
    return (packet->types & ( 1 << type))  != 0;
}

void
packet_dump(packet_t *packet, char *title)
{
    return;
    address_t src = packet->src;
    address_t dst = packet->dst;

    printf("[%s] %s:%u -> %s:%u\n", title,
           src.ip, src.port, dst.ip, dst.port);
}

void
packet_dump_hex(char *desc, const void *ptr, int len)
{
    return;
    int i;
    uint8_t buff[17];
    uint8_t *data = (uint8_t*)ptr;

    printf ("%s [%d]:\n", desc, len);
    if (len == 0) return;
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf (" |%s|\n", buff);
            printf ("|");
        }
        printf (" %02x", data[i]);
        if ((data[i] < 0x20) || (data[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = data[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    printf (" |%-16s|\n\n", buff);
}
