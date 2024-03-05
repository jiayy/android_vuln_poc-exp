/**
 * @file
 *
 * Protected routines for information flow analysis.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2003-2007 Tresys Technology, LLC
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

#ifndef APOL_INFOFLOW_ANALYSIS_INTERNAL_H
#define APOL_INFOFLOW_ANALYSIS_INTERNAL_H

/**
 * Do a deep copy (i.e., a clone) of an apol_infoflow_result_t object.
 * The caller is responsible for calling apol_infoflow_result_free()
 * upon the returned value.
 *
 * @param result Pointer to an infoflow result structure to destroy.
 *
 * @return A clone of the passed in result node, or NULL upon error.
 */
extern apol_infoflow_result_t *infoflow_result_create_from_infoflow_result(const apol_infoflow_result_t * result);

/**
 * Free all memory associated with an information flow analysis
 * result, including the pointer itself.  This function does nothing
 * if the result is already NULL.
 *
 * @param result Pointer to an infoflow result structure to destroy.
 */
extern void infoflow_result_free(void *result);

#endif
