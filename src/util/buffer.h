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
 * @file buffer.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage generic byte buffers
 * 
 */

#ifndef __SNGREP_BUFFER_H
#define __SNGREP_BUFFER_H

#include <stddef.h>

typedef struct
{
	unsigned char *ptr;
	size_t len;
} sng_buff_t;

typedef struct
{
	const char *ptr;
	size_t len;
} sng_str_t;

sng_str_t
sng_buff_str(sng_buff_t buff);

sng_buff_t
sng_buff_shift(sng_buff_t buff, size_t offset);

sng_buff_t
sng_str_buff(sng_str_t str);

sng_str_t
sng_str_shift(sng_str_t str, size_t offset);

sng_str_t
sng_str_cut(sng_str_t str, const char *where);

sng_str_t
sng_str_chomp(sng_str_t str);

#endif /* __SNGREP_BUFFER_H */
