/**
 * @file
 *
 * Protected routines for domain transition analysis.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2007 Tresys Technology, LLC
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

#ifndef APOL_DOMAIN_TRANS_ANALYSIS_INTERNAL_H
#define APOL_DOMAIN_TRANS_ANALYSIS_INTERNAL_H

/**
 *  Free all memory associated with a domain transition result, including
 *  the pointer itself. This function does nothing if the result is NULL.
 *  @param dtr Pointer to a domain transition result structure to free.
 */
void domain_trans_result_free(void *dtr);

#endif
