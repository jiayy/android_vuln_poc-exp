/**
 * @file
 * Defines the public API for qpol_iterator; this structure
 * is used when requesting lists of components from the policy
 * database.
 * 
 * @author Kevin Carr kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef QPOL_ITERATOR_H
#define QPOL_ITERATOR_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>

	struct qpol_iterator;
	typedef struct qpol_iterator qpol_iterator_t;

/**
 *  Free memory used by the iterator.
 *  @param iter Pointer to the iterator to be freed; frees all
 *  memory used by the iterator and the iterator itself. On returning
 *  *iter will be NULL.
 */
	extern void qpol_iterator_destroy(qpol_iterator_t ** iter);

/**
 *  Get the item at the current position of the iterator.
 *  @param iter The iterator from which to get the item.
 *  @param item Pointer in which to store the current item; the caller is 
 *  responsible for safely casting this pointer. Unless specifically
 *  noted by the function creating the iterator, the item set 
 *  by this function should not be freed. If the iterator is at 
 *  the end (i.e. all items have been traversed) *item will be NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *item will be NULL.
 */
	extern int qpol_iterator_get_item(const qpol_iterator_t * iter, void **item);

/**
 *  Advance the iterator to the next item.
 *  @param iter The iterator to advance; internal state data will change.
 *  @return Returns 0 on success and < 0 on failure; advancing an
 *  iterator that is at the end fails (and returns < 0). If the call fails,
 *  errno will be set.
 */
	extern int qpol_iterator_next(qpol_iterator_t * iter);

/**
 *  Determine if an iterator is at the end.
 *  @param iter The iterator to check.
 *  @return Returns non-zero if the current position of the iterator
 *  is at the end of the list (i.e. past the last valid item) and
 *  zero in any other case. If there is an error determining if
 *  the iterator is at the end then non-zero will be returned.
 */
	extern int qpol_iterator_end(const qpol_iterator_t * iter);

/**
 *  Get the total number of items in the list traversed by the iterator.
 *  @param iter The iterator from which to get the number of items.
 *  @param size Pointer in which to store the number of items. 
 *  Must be non-NULL.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *size will be 0.
 */
	extern int qpol_iterator_get_size(const qpol_iterator_t * iter, size_t * size);

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_ITERATOR */
