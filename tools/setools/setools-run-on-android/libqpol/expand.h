/**
 * @file
 * 
 * Public interface for expanding a modular policy.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
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

#ifndef QPOL_EXPAND_H
#define QPOL_EXPAND_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <qpol/policy.h>

/**
 * Expand a policy. Linking should always be done prior to calling
 * this function.  
 *
 * @param base the module to expand.
 * @param neverallows if non-zero expand neverallows.
 * @return 0 on success, -1 on error.
 */
	int qpol_expand_module(qpol_policy_t * base, int neverallows);

#ifdef	__cplusplus
}
#endif

#endif
