/**
 *  @file
 *  Protected definition for syntactic rules from the extended
 *  policy image.
 *
 *  @author Kevin Carr kcarr@tresys.com
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
#ifndef QPOL_SYN_RULE_INTERNAL_H
#define QPOL_SYN_RULE_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

	struct qpol_syn_rule
	{
		avrule_t *rule;
		cond_node_t *cond;
	/** 0 if this rule is unconditional or in a conditional's true branch, 1 if in else */
		int cond_branch;
/*	char *mod_name; for later use */
	};

#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_SYN_RULE_INTERNAL_H */
