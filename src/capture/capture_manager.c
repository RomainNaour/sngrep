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
 * @file capture.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in capture.h
 *
 */

#include "capture_manager.h"

#include "config.h"
#include <stdio.h>
#include <unistd.h>

// Capture information
capture_config_t capture_cfg =
{ 0 };

void
capture_init(size_t limit, bool rtp_capture, bool rotate)
{
    capture_cfg.limit = limit;
    capture_cfg.rtp_capture = rtp_capture;
    capture_cfg.rotate = rotate;
    capture_cfg.sources = vector_create(1, 1);
    capture_cfg.tcp_reasm = vector_create(0, 10);
    capture_cfg.ip_reasm = vector_create(0, 10);

    // Initialize calls lock
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#if defined(PTHREAD_MUTEX_RECURSIVE) || defined(__FreeBSD__) || defined(BSD) || defined (__OpenBSD__) || defined(__DragonFly__)
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#else
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
    pthread_mutex_init(&capture_cfg.lock, &attr);
}

void
capture_deinit()
{
    // Close pcap handler
    //capture_close();

    // Deallocate vectors
    vector_set_destroyer(capture_cfg.sources, vector_generic_destroyer);
    vector_destroy(capture_cfg.sources);
//    vector_set_destroyer(capture_cfg.tcp_reasm, packet_destroyer);
    vector_destroy(capture_cfg.tcp_reasm);
//    vector_set_destroyer(capture_cfg.ip_reasm, packet_destroyer);
    vector_destroy(capture_cfg.ip_reasm);

    // Remove capture mutex
    pthread_mutex_destroy(&capture_cfg.lock);
}


int
capture_inputs_start(vector_t *inputs)
{
	capture_input_t *input;

    //! capture thread attributes
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    // Start all captures threads
    vector_iter_t it = vector_iterator(inputs);
    while ((input = vector_iterator_next(&it))) {
        if (pthread_create(&input->thread, &attr, (void *) input->start, input)) {
            return 1;
        }
    }
    pthread_attr_destroy(&attr);
    return 0;
}

void
capture_inputs_stop(vector_t *inputs)
{
	capture_input_t *input;
    vector_iter_t it = vector_iterator(inputs);
    while ((input = vector_iterator_next(&it))) {
//		if (input->running) {
//			it = vector_iterator(inputs);
//			usleep(500);
//			continue;
//		}
//		if (input->stop) {
//        	input->stop(input);
//		}
		pthread_join(input->thread, NULL);
    }
}

int 
capture_inputs_filter(vector_t *inputs, const char *filter)
{
	capture_input_t *input;
    vector_iter_t it = vector_iterator(inputs);
    while ((input = vector_iterator_next(&it))) {
		if (input->filter) {
			if (input->filter(input, filter) != 0) {
				return 1;
			}
		}
    }
	return 0;
}

void
capture_lock()
{
    // Avoid parsing more packet
    pthread_mutex_lock(&capture_cfg.lock);
}

void
capture_unlock()
{
    // Allow parsing more packets
    pthread_mutex_unlock(&capture_cfg.lock);
}
