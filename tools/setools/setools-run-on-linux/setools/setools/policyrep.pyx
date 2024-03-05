# Copyright 2017-2018, Chris PeBenito <pebenito@ieee.org>
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of
# the License, or (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with SETools.  If not, see
# <http://www.gnu.org/licenses/>.
#

from cpython.exc cimport PyErr_SetFromErrnoWithFilename
from cpython.mem cimport PyMem_Malloc, PyMem_Free
from libc.errno cimport errno, EPERM, ENOENT, ENOMEM, EINVAL
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, uintptr_t
from libc.stdio cimport FILE, fopen, fclose, snprintf
from libc.stdlib cimport calloc, free
from libc.string cimport memcpy, memset, strerror
from posix.stat cimport S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFREG, S_IFLNK, S_IFSOCK

import logging
import warnings
import itertools
import ipaddress
import collections
import enum
import weakref

cimport sepol
cimport selinux

from .exception import InvalidPolicy, MLSDisabled, InvalidBoolean, InvalidCategory, InvalidClass, \
    InvalidCommon, InvalidInitialSid, InvalidLevel, InvalidLevelDecl, InvalidRange, InvalidRole, \
    InvalidSensitivity, InvalidType, InvalidUser, InvalidRuleType, InvalidBoundsType, \
    InvalidConstraintType, InvalidDefaultType, InvalidFSUseType, InvalidMLSRuleType, \
    InvalidRBACRuleType, InvalidTERuleType, SymbolUseError, RuleUseError, ConstraintUseError, \
    NoStatement, InvalidDefaultValue, InvalidDefaultRange, NoCommon, NoDefaults, \
    RuleNotConditional, TERuleNoFilename, LowLevelPolicyError

cdef extern from "<stdio.h>":
    int vasprintf(char **strp, const char *fmt, va_list ap)

cdef extern from "<stdarg.h>":
    ctypedef struct va_list:
        pass
    void va_start(va_list, void* arg)
    void va_end(va_list)

cdef extern from "<sys/socket.h>":
    ctypedef unsigned int socklen_t
    cdef int AF_INET
    cdef int AF_INET6

cdef extern from "<netinet/in.h>":
    cdef int INET6_ADDRSTRLEN
    cdef int IPPROTO_DCCP
    cdef int IPPROTO_SCTP
    cdef int IPPROTO_TCP
    cdef int IPPROTO_UDP

cdef extern from "<arpa/inet.h>":
    cdef const char *inet_ntop(int af, const void *src, char *dst, socklen_t size)

# this must be here so that the PolicyEnum subclasses are created correctly.
# otherwise you get an error during runtime
include "util.pxi"

include "boolcond.pxi"
include "bounds.pxi"
include "constraint.pxi"
include "context.pxi"
include "default.pxi"
include "fscontext.pxi"
include "initsid.pxi"
include "mls.pxi"
include "mlsrule.pxi"
include "netcontext.pxi"
include "objclass.pxi"
include "object.pxi"
include "polcap.pxi"
include "rbacrule.pxi"
include "role.pxi"
include "rule.pxi"
include "selinuxpolicy.pxi"
include "terule.pxi"
include "typeattr.pxi"
include "user.pxi"
include "xencontext.pxi"
