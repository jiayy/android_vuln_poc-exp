/**
 * @file
 *
 * Routines to query parts of a policy.  For each component and rule
 * there is a query structure to specify the details of the query.
 * Analyses are also included by this header file.
 *
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

#ifndef APOL_POLICY_QUERY_H
#define APOL_POLICY_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

/* Many libapol queries act upon MLS contexts.  Use these defines to
 * specify set operations upon contexts.
 */
#define APOL_QUERY_SUB	 0x02	       /**< The range specified by the query is a subset of the target range */
#define APOL_QUERY_SUPER 0x04	       /**< The range specified by the query is a superset of the target range */
#define APOL_QUERY_EXACT (APOL_QUERY_SUB|APOL_QUERY_SUPER) /**< The range specified by the query matches the target range exactly. */
#define APOL_QUERY_INTERSECT 0x08      /* query overlaps any part of rule range */
#define APOL_QUERY_FLAGS \
	(APOL_QUERY_SUB | APOL_QUERY_SUPER | APOL_QUERY_EXACT | \
	 APOL_QUERY_INTERSECT)

/* The AV rule search and TE rule search use these flags when
 * specifying what kind of symbol is being searched.  Strings are
 * normally interpreted either as a type or as an attribute; the behavior
 * can be changed to use only types or only attributes.
 */
#define APOL_QUERY_SYMBOL_IS_TYPE 0x01
#define APOL_QUERY_SYMBOL_IS_ATTRIBUTE 0x02

#include <qpol/policy.h>

#include "type-query.h"
#include "class-perm-query.h"
#include "role-query.h"
#include "user-query.h"
#include "bool-query.h"
#include "isid-query.h"
#include "mls-query.h"
#include "netcon-query.h"
#include "fscon-query.h"
#include "context-query.h"
#include "permissive-query.h"
#include "polcap-query.h"

#include "avrule-query.h"
#include "terule-query.h"
#include "condrule-query.h"
#include "rbacrule-query.h"
#include "ftrule-query.h"
#include "range_trans-query.h"
#include "constraint-query.h"

#include "domain-trans-analysis.h"
#include "infoflow-analysis.h"
#include "relabel-analysis.h"
#include "types-relation-analysis.h"

#ifdef	__cplusplus
}
#endif

#endif
