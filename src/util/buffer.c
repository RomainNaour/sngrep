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
 * @file buffer.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Source of functions defined in buffer.h
 *
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "buffer.h"

sng_str_t
sng_buff_str(sng_buff_t buff)
{
	sng_str_t ret;
	ret.ptr = (char *) buff.ptr;
	ret.len = buff.len;
	return ret;
}

sng_buff_t
sng_buff_shift(sng_buff_t buff, size_t offset)
{
	if (buff.len > offset) {
		buff.ptr += offset;
		buff.len -= offset;
	} else {
		buff.len = 0;
		buff.ptr = 0;
	}
	return buff;
}

sng_buff_t
sng_str_buff(sng_str_t str)
{
	sng_buff_t ret;
	ret.ptr = (u_char *) str.ptr;
	ret.len = str.len;
	return ret;
}

sng_str_t
sng_str_shift(sng_str_t str, size_t offset)
{
	sng_str_t ret = {};
	if (str.len > offset) {
		ret = str;
		ret.ptr += offset;
		ret.len -= offset;
	}
	return ret;
}

sng_str_t
sng_str_cut(sng_str_t str, const char *needle)
{
    //	sng_str_t ret = str;
    //	const char *found = strstr(ret.ptr, needle);
    //	if (found) ret.len = found - ret.ptr ;
    //	return ret;

		char haystack[str.len + 1];
		memset(haystack, 0, str.len + 1);
		strncpy(haystack, str.ptr, str.len);

		sng_str_t ret = str;
		const char *found = strstr(haystack, needle);
		if (found) ret.len = found - haystack ;
		return ret;
	//}
}

sng_str_t
sng_str_chomp(sng_str_t str)
{
	sng_str_t ret = str;

	// Remove leading spaces
	int i;
	for (i = 0; i < str.len; i++) {
		if (*ret.ptr == ' ') {
			ret.ptr++;
			ret.len--;
		}
	}

	// Remove trailing spaces
	for (i = ret.len - 1; i >= 0; i--) {
		if (*(ret.ptr + i) == ' ') {
			ret.len--;
		}
	}

	return ret;
}
