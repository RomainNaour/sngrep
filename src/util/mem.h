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
 * @file mem.h
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions to manage memory pools
 */

#ifndef __SNGREP_MEM_H_
#define __SNGREP_MEM_H_

#include <stdlib.h>

#define MALLOC_MAX_SIZE 102400

typedef struct mem_pool mem_pool_t;

struct mem_pool
{
    size_t count;
    void*
    (*malloc)(size_t size);
    void
    (*free)(void *ptr);
    void*
    (*realloc)(void *ptr, size_t size);
    // void* (*calloc)(size_t nmemb, size_t size);
};

mem_pool_t *
sng_gmem_pool();

void*
sng_malloc(mem_pool_t *pool, size_t size);

void
sng_free(mem_pool_t *pool, void *ptr);

void*
sng_generic_malloc(size_t size);

void
sng_generic_free(void *ptr);

void*
sng_generic_realloc(void *ptr, size_t size);

#endif /* __SNGREP_MEM_H_ */
