/**
 *  @file
 *  Contains the API for a binary search tree.  The tree guarantees
 *  uniqueness of all entries within.  Note that BST functions are not
 *  thread-safe.  Use this if you need uniqueness in items; use
 *  vectors otherwise because they are faster.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifndef APOL_BST_H
#define APOL_BST_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stdlib.h>

	typedef struct apol_bst apol_bst_t;

	typedef int (apol_bst_comp_func) (const void *a, const void *b, void *data);
	typedef void (apol_bst_free_func) (void *elem);

#include "vector.h"

/**
 *  Allocate and initialize an empty binary search tree.  The tree
 *  must have a comparison function, used when comparing nodes so as
 *  to determine how to sort them.
 *
 *  @param cmp A comparison call back for the type of element stored
 *  in the BST.  The expected return value from this function is less
 *  than, equal to, or greater than 0 if the first argument is less
 *  than, equal to, or greater than the second respectively.  If this
 *  is NULL then do pointer address comparison.
 *  @param fr Function to call when destroying the tree.  Each
 *  element of the tree will be passed into this function; it should
 *  free the memory used by that element.  If this parameter is NULL,
 *  the elements will not be freed.
 *
 *  @return A pointer to a newly created BST on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_bst_destroy() to free memory used.
 */
	extern apol_bst_t *apol_bst_create(apol_bst_comp_func * cmp, apol_bst_free_func * fr);

/**
 *  Free a BST and any memory used by it.  This will recursively
 *  invoke the free function that was stored within the tree when it
 *  was created.
 *
 *  @param b Pointer to the BST to free.  The pointer will be set to
 *  NULL afterwards.  If already NULL then this function does nothing.
 */
	extern void apol_bst_destroy(apol_bst_t ** b);

/**
 *  Allocate and return a vector that has been initialized with the
 *  contents of a binary search tree.  If change_owner is zero then
 *  this function will make a <b>shallow copy of the BST's
 *  contents</b>; the BST will still <em>own</em> the objects.
 *  Otherwise the victor will gain ownership of the items; the BST can
 *  then be destroyed safely without affecting the vector.  (The
 *  resulting vector will be sorted as per the BST's comparison
 *  function.)
 *
 *  @param b Binary search tree from which to copy.
 *  @param change_owner If zero then do a shallow copy, else change
 *  item ownership.
 *
 *  @return A pointer to a newly created vector on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_vector_destroy() to free memory used
 *  by the vector.
 */
	extern apol_vector_t *apol_bst_get_vector(apol_bst_t * b, int change_owner);

/**
 *  Get the number of elements stored in the BST.
 *
 *  @param b The BST from which to get the number of elements.  Must
 *  be non-NULL.
 *
 *  @return The number of elements in the BST; if b is NULL, return
 *  0 and set errno.
 */
	extern size_t apol_bst_get_size(const apol_bst_t * v);

/**
 *  Find an element within a BST and return it.
 *
 *  @param b The BST from which to get the element.
 *  @param elem The element to find.  (This will be the second
 *  parameter to the comparison function given in apol_bst_create().)
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater (the function given in apol_bst_create()).
 *  @param elem Location to write the found element.  This value is
 *  undefined if the key did not match any elements.
 *
 *  @return 0 if element was found, or < 0 if not found.
 */
	extern int apol_bst_get_element(const apol_bst_t * b, const void *elem, void *data, void **result);

/**
 *  Insert an element to the BST.  If the element already exists then
 *  do not insert it again.
 *
 *  @param b The BST to which to add the element.
 *  @param elem The element to add.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater (the function given in apol_bst_create()).
 *
 *  @return 0 if the item was inserted, 1 if the item already exists
 *  (and thus not inserted).  On failure return < 0, set errno, and b
 *  will be unchanged.
 */
	extern int apol_bst_insert(apol_bst_t * b, void *elem, void *data);

/**
 *  Insert an element into the BST, and then get the element back out.
 *  If the element did not already exist, then this function behaves
 *  the same as apol_bst_insert().  If however the element did exist,
 *  then the passed in element is freed (as per the BST's free
 *  function) and then the existing element is returned.
 *
 *  @param b The BST to which to add the element.
 *  @param elem Reference to an element to add.  If the element is
 *  new, then the pointer remains unchanged.  Otherwise set the
 *  reference to the element already within the tree.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater (the function given in apol_bst_create()).
 *
 *  @return 0 if the item was inserted, 1 if the item already exists
 *  (and thus not inserted).  On failure return < 0, set errno, and b
 *  will be unchanged.
 */
	extern int apol_bst_insert_and_get(apol_bst_t * b, void **elem, void *data);

/**
 * Map a function across all the elements of the BST.  Mapping occurs in
 * the sorted order as defined by the original comparison function.
 *
 * @param node BST upon which to map against.
 * @param fn Function pointer that takes 2 arguments, first is a
 * pointer to the data in a node of the BST, second is an arbitrary
 * data element.  The function may change the BST node, but it must
 * not affect the node's sorting order within the tree.  This function
 * should return >= 0 on success; a return of < 0 signals error and
 * ends the mapping over the tree.

 * @return Result of the last call to fn() (i.e., >= 0 on success < 0 on
 * failure).  If the tree is empty then return 0.
 */
	extern int apol_bst_inorder_map(const apol_bst_t * b, int (*fn) (void *, void *), void *data);
#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_BST_H */
