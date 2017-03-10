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
 * @file capture_manager.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage capture engines
 *
 * Capture manager is in charge of managing capture inputs and output.
 *
 * A capture input is a source of new packet data:
 *  - a existing file
 *  - a device live capture
 *  - a homer receiver socket
 *  - ...
 *
 * A capture output is a destination for stored packet in memory:
 *  - a new file
 *  - a homer server
 *  - ...
 *
 * There can be multiple capture inputs, so you can combine them, for example
 * opening more than one file, or capturing from multiples devices while you
 * receive packets from another sngrep through the homer socket.
 *
 * The interface for capture inputs and outputs are designed to be as simple as
 * possible, to make it simpler to add new ones in case we require it.
 *
 * Each capture input is run in its own thread, so there is no specific order
 * of how the packets in multiple capture inputs are processed.
 *
 */

#ifndef __SNGREP_CAPTURE_MANAGER_H
#define __SNGREP_CAPTURE_MANAGER_H

#include <pthread.h>
#include "packet.h"
#include "mem.h"

enum capture_mode
{
	CAPTURE_ONLINE = 1,
	CAPTURE_OFFLINE,
};

//! Shorter declaration of capture_input structure
typedef struct capture_input capture_input_t;
//! Shorter declaration of capture_output structure
typedef struct capture_output capture_output_t;
//! Shorter declaration of capture_config structure
typedef struct capture_config capture_config_t;
//; Shorter declaration of capture_info structure
typedef struct capture_info capture_info_t;

/**
 * @brief Capture common configuration
 *
 * Store capture configuration and global data
 */
struct capture_config {
    //! Calls capture limit. 0 for disabling
    size_t limit;
    //! Also capture RTP packets
    bool rtp_capture;
    //! Rotate capturad dialogs when limit have reached
    bool rotate;
    //! Key file for TLS decrypt
    const char *keyfile;
    //! capture filter expression text
    const char *filter;
    //! The compiled filter expression
    struct bpf_program fp;
    //! libpcap dump file handler
    pcap_dumper_t *pd;
    //! Capture sources
    vector_t *sources;
    //! Packets pending IP reassembly
    vector_t *ip_reasm;
    //! Packets pending TCP reassembly
    vector_t *tcp_reasm;
    //! Capture Lock. Avoid parsing and handling data at the same time
    pthread_mutex_t lock;
};

/**
 * @brief store all information related with packet capture
 *
 * Store capture required data from one packet source
 */
struct capture_info
{
    //! libpcap link type
    int link;
    //! libpcap capture handler
    pcap_t *handle;
    //! Netmask of our sniffing device
    bpf_u_int32 mask;
    //! The IP of our sniffing device
    bpf_u_int32 net;
    //! Input file in Offline capture
    const char *infile;
    //! Capture device in Online mode
    const char *device;
    //! Capture thread for online capturing
    pthread_t capture_t;
};

struct capture_input
{
	//! Are captured packets life
	enum capture_mode mode;
	//! Thread that runs capture callback
	pthread_t thread;
	//! Private capture input data
	void *priv;
	//! Memory pool for this input
	mem_pool_t *pool;
	//! Flag to check if capture is running
	bool running;
	//! Flag to skip captured packets
	bool paused;
	//! Start capturing packets function
	void (*start)(capture_input_t *input);
	//! Stop capturing packets function
	void (*stop)(capture_input_t *input);
	//! Capture filtering expression
	int (*filter)(capture_input_t *input, const char *filter);
};

struct capture_output
{
	//! Private capture output data
	void *priv;
    //! Memory pool for this output
    mem_pool_t *pool;
	//! Dump packet function
	void (*write)(capture_output_t *output, packet_t *packet);
	//! Close dump packet function
	void (*close)(capture_output_t *output);
};

/**
 * @brief Initialize capture data
 *
 * @param limit Numbers of calls >0
 * @param rtp_catpure Enable rtp capture
 * @param rotate Enable capture rotation
 */
void
capture_init(size_t limit, bool rtp_capture, bool rotate);

/**
 * @brief Deinitialize capture data
 */
void
capture_deinit();


int
capture_inputs_start(vector_t *inputs);

void
capture_inputs_stop(vector_t *inputs);

int
capture_inputs_filter(vector_t *inputs, const char *filter);

void
capture_lock();

void
capture_unlock();

#endif
