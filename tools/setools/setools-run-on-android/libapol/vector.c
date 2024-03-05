/**
 *  @file
 *  Contains the implementation of a generic vector.
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

#include <apol/vector.h>
#include "vector-internal.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/** The default initial capacity of a vector; must be a positive integer */
#define APOL_VECTOR_DFLT_INIT_CAP 10

/**
 *  Generic vector structure. Stores elements as void*.
 */
struct apol_vector
{
	/** The array of element pointers, which will be resized as needed. */
	void **array;
	/** The number of elements currently stored in array. */
	size_t size;
	/** The actual amount of space in array. This amount will always
	 *  be >= size and will grow exponentially as needed. */
	size_t capacity;
	apol_vector_free_func *fr;
};

apol_vector_t *apol_vector_create(apol_vector_free_func * fr)
{
	return apol_vector_create_with_capacity(APOL_VECTOR_DFLT_INIT_CAP, fr);
}

apol_vector_t *apol_vector_create_with_capacity(size_t cap, apol_vector_free_func * fr)
{
	apol_vector_t *v = NULL;
	int error;

	if (cap < 1) {
		cap = 1;
	}
	v = calloc(1, sizeof(apol_vector_t));
	if (!v)
		return NULL;
	v->array = calloc((v->capacity = cap), sizeof(void *));
	if (!(v->array)) {
		error = errno;
		free(v);
		errno = error;
		return NULL;
	}
	v->fr = fr;
	return v;
}

apol_vector_t *apol_vector_create_from_iter(qpol_iterator_t * iter, apol_vector_free_func * fr)
{
	size_t iter_size;
	apol_vector_t *v;
	void *item;
	int error;
	if (qpol_iterator_get_size(iter, &iter_size) < 0 || (v = apol_vector_create_with_capacity(iter_size, fr)) == NULL) {
		return NULL;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, &item)) {
			error = errno;
			free(v);
			errno = error;
			return NULL;
		}
		apol_vector_append(v, item);
	}
	return v;
}

apol_vector_t *apol_vector_create_from_vector(const apol_vector_t * v, apol_vector_dup_func * dup, void *data,
					      apol_vector_free_func * fr)
{
	apol_vector_t *new_v;
	size_t i;
	if (v == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((new_v = apol_vector_create_with_capacity(v->capacity, fr)) == NULL) {
		return NULL;
	}
	if (dup == NULL) {
		memcpy(new_v->array, v->array, v->size * sizeof(void *));
	} else {
		for (i = 0; i < v->size; i++) {
			new_v->array[i] = dup(v->array[i], data);
		}
	}
	new_v->size = v->size;
	return new_v;
}

apol_vector_t *apol_vector_create_from_intersection(const apol_vector_t * v1,
						    const apol_vector_t * v2, apol_vector_comp_func * cmp, void *data)
{
	apol_vector_t *new_v;
	size_t i, j;
	if (v1 == NULL || v2 == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((new_v = apol_vector_create(NULL)) == NULL) {
		return NULL;
	}
	for (i = 0; i < v1->size; i++) {
		for (j = 0; j < v2->size; j++) {
			if ((cmp != NULL && cmp(v1->array[i], v2->array[j], data) == 0) ||
			    (cmp == NULL && v1->array[i] == v2->array[j])) {
				if (apol_vector_append(new_v, v1->array[i]) < 0) {
					apol_vector_destroy(&new_v);
					return NULL;
				}
				break;
			}
		}
	}
	return new_v;
}

void apol_vector_destroy(apol_vector_t ** v)
{
	size_t i = 0;

	if (!v || !(*v))
		return;

	if ((*v)->fr) {
		for (i = 0; i < (*v)->size; i++) {
			(*v)->fr((*v)->array[i]);
		}
	}
	free((*v)->array);
	(*v)->array = NULL;
	free(*v);
	*v = NULL;
}

size_t apol_vector_get_size(const apol_vector_t * v)
{
	if (!v) {
		errno = EINVAL;
		return 0;
	} else {
		return v->size;
	}
}

size_t apol_vector_get_capacity(const apol_vector_t * v)
{
	if (!v) {
		errno = EINVAL;
		return 0;
	} else {
		return v->capacity;
	}
}

void *apol_vector_get_element(const apol_vector_t * v, size_t idx)
{
	if (!v || !(v->array)) {
		errno = EINVAL;
		return NULL;
	}

	if (idx >= v->size) {
		errno = ERANGE;
		return NULL;
	}

	return v->array[idx];
}

/**
 * Grows a vector, by reallocating additional space for it.
 *
 * @param v Vector to which increase its size.
 *
 * @return 0 on success, -1 on error.
 */
static int apol_vector_grow(apol_vector_t * v)
{
	void **tmp;
	size_t new_capacity = v->capacity;
	if (new_capacity >= 128) {
		new_capacity += 128;
	} else {
		new_capacity *= 2;
	}
	tmp = realloc(v->array, new_capacity * sizeof(void *));
	if (!tmp) {
		return -1;
	}
	v->capacity = new_capacity;
	v->array = tmp;
	return 0;
}

int apol_vector_get_index(const apol_vector_t * v, const void *elem, apol_vector_comp_func * cmp, void *data, size_t * i)
{
	if (!v || !i) {
		errno = EINVAL;
		return -1;
	}

	for (*i = 0; *i < v->size; (*i)++) {
		if ((cmp != NULL && cmp(v->array[*i], elem, data) == 0) || (cmp == NULL && elem == v->array[*i])) {
			return 0;
		}
	}
	return -1;
}

int apol_vector_append(apol_vector_t * v, void *elem)
{
	if (!v) {
		errno = EINVAL;
		return -1;
	}

	if (v->size >= v->capacity && apol_vector_grow(v)) {
		return -1;
	}

	v->array[v->size] = elem;
	v->size++;

	return 0;
}

int apol_vector_append_unique(apol_vector_t * v, void *elem, apol_vector_comp_func * cmp, void *data)
{
	size_t i;
	if (apol_vector_get_index(v, elem, cmp, data, &i) < 0) {
		return apol_vector_append(v, elem);
	}
	errno = EEXIST;
	return 1;
}

int apol_vector_compare(const apol_vector_t * a, const apol_vector_t * b, apol_vector_comp_func * cmp, void *data, size_t * i)
{
	int compval;
	if (a == NULL || b == NULL || i == NULL) {
		errno = EINVAL;
		return 0;
	}
	size_t a_len = apol_vector_get_size(a);
	size_t b_len = apol_vector_get_size(b);
	for (*i = 0; *i < a_len && *i < b_len; (*i)++) {
		if (cmp != NULL) {
			compval = cmp(a->array[*i], b->array[*i], data);
		} else {
			compval = (int)((char *)a->array[*i] - (char *)b->array[*i]);
		}
		if (compval != 0) {
			return compval;
		}
	}
	if (a_len == b_len) {
		return 0;
	} else if (a_len < b_len) {
		return -1;
	} else {
		return 1;
	}
}

static size_t vector_qsort_partition(void **data, size_t first, size_t last, apol_vector_comp_func * cmp, void *arg)
{
	void *pivot = data[last];
	size_t i = first, j = last;
	while (i < j) {
		if (cmp(data[i], pivot, arg) <= 0) {
			i++;
		} else {
			data[j] = data[i];
			data[i] = data[j - 1];
			j--;
		}
	}
	data[j] = pivot;
	return j;
}

static void vector_qsort(void **data, size_t first, size_t last, apol_vector_comp_func * cmp, void *arg)
{
	if (first < last) {
		size_t i = vector_qsort_partition(data, first, last, cmp, arg);
		/* need this explicit check here, because i is an
		 * unsigned integer, and subtracting 1 from 0 is
		 * bad */
		if (i > 0) {
			vector_qsort(data, first, i - 1, cmp, arg);
		}
		vector_qsort(data, i + 1, last, cmp, arg);
	}
}

/**
 * Generic comparison function, which treats elements of the vector as
 * unsigned integers.
 */
static int vector_int_comp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	char *i = (char *)a;
	char *j = (char *)b;
	if (i < j) {
		return -1;
	} else if (i > j) {
		return 1;
	}
	return 0;
}

/* implemented as an in-place quicksort */
void apol_vector_sort(apol_vector_t * v, apol_vector_comp_func * cmp, void *data)
{
	if (!v) {
		errno = EINVAL;
		return;
	}
	if (cmp == NULL) {
		cmp = vector_int_comp;
	}
	if (v->size > 1) {
		vector_qsort(v->array, 0, v->size - 1, cmp, data);
	}
}

void apol_vector_sort_uniquify(apol_vector_t * v, apol_vector_comp_func * cmp, void *data)
{
	if (!v) {
		errno = EINVAL;
		return;
	}
	if (cmp == NULL) {
		cmp = vector_int_comp;
	}
	if (v->size > 1) {
		size_t i, j = 0;
		void **new_array;
		/* sweep through the array, do a quick compaction,
		 * then sort */
		for (i = 1; i < v->size; i++) {
			if (cmp(v->array[i], v->array[j], data) != 0) {
				/* found a unique element */
				j++;
				v->array[j] = v->array[i];
			} else {
				/* found a non-unique element */
				if (v->fr != NULL) {
					v->fr(v->array[i]);
				}
			}
		}
		v->size = j + 1;

		apol_vector_sort(v, cmp, data);
		j = 0;
		for (i = 1; i < v->size; i++) {
			if (cmp(v->array[i], v->array[j], data) != 0) {
				/* found a unique element */
				j++;
				v->array[j] = v->array[i];
			} else {
				/* found a non-unique element */
				if (v->fr != NULL) {
					v->fr(v->array[i]);
				}
			}
		}
		/* try to realloc vector to save space */
		v->size = j + 1;
		if ((new_array = realloc(v->array, v->size * sizeof(void *))) != NULL) {
			v->array = new_array;
			v->capacity = v->size;
		}
	}
}

int apol_vector_cat(apol_vector_t * dest, const apol_vector_t * src)
{
	size_t i, orig_size, cap;
	void **a;
	if (!src || !apol_vector_get_size(src)) {
		return 0;	       /* nothing to append */
	}

	if (!dest) {
		errno = EINVAL;
		return -1;
	}
	orig_size = apol_vector_get_size(dest);
	for (i = 0; i < apol_vector_get_size(src); i++)
		if (apol_vector_append(dest, apol_vector_get_element(src, i))) {
			/* revert if possible */
			if (orig_size == 0) {
				cap = 1;
			} else {
				cap = orig_size;
			}
			a = realloc(dest->array, cap * sizeof(*a));
			if (a != NULL) {
				dest->array = a;
			}
			dest->size = orig_size;
			dest->capacity = cap;
			return -1;
		}

	return 0;
}

int apol_vector_remove(apol_vector_t * v, const size_t idx)
{
	if (v == NULL || idx >= v->size) {
		errno = EINVAL;
		return -1;
	}
	memmove(v->array + idx, v->array + idx + 1, sizeof(v->array[0]) * (v->size - idx - 1));
	v->size--;
	return 0;
}

/******************** friend function below ********************/

void vector_set_free_func(apol_vector_t * v, apol_vector_free_func * fr)
{
	v->fr = fr;
}
