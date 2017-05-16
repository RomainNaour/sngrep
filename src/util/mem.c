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
 * @file mem.c
 * @author Ivan Alonso [aka Kaian] <kaian@irontec.com>
 *
 * @brief Functions for manage memory pools
 *
 */
#include "mem.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static mem_pool_t globalpool =
{ 0, sng_generic_malloc, sng_generic_free, sng_generic_realloc };

mem_pool_t *
sng_gmem_pool()
{
    return &globalpool;
}

void*
sng_malloc(mem_pool_t *pool, size_t size)
{
    void *ret = pool->malloc(size);
    pool->count += size;
    //printf("malloc'd %d bytes [Total %d bytes]\n", (int)size, (int)pool->count);
    return ret;
}

void
sng_free(mem_pool_t *pool, void *ptr)
{
    pool->free(ptr);
    // pool->count;
}

void*
sng_generic_malloc(size_t size)
{
    void *data;

    // Check memory allocation size
    if (size <= 0 || size > MALLOC_MAX_SIZE)
        return NULL;

    // Allocate memory
    if (!(data = malloc(size)))
        return NULL;

    // Initialize allocated memory
    memset(data, 0, size);
    return data;
}

void
sng_generic_free(void *ptr)
{
    if (ptr)
        free(ptr);
}

void*
sng_generic_realloc(void *ptr, size_t size)
{
    if (ptr)
        return NULL;
    return realloc(ptr, size);
}
