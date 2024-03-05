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

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t
from libc.stdio cimport FILE


cdef extern from "<sepol/handle.h>":
    cdef struct sepol_handle:
        pass
    ctypedef sepol_handle sepol_handle_t

    sepol_handle_t* sepol_handle_create()
    void sepol_handle_destroy(sepol_handle_t *sh)


cdef extern from "<sepol/debug.h>":
    ctypedef void (*msg_callback)(void *varg, sepol_handle_t *handle, const char *fmt, ...)
    void sepol_msg_set_callback(sepol_handle * handle, msg_callback cb, void *cb_arg)


cdef extern from "<sepol/policydb/services.h>":
    cdef int SECURITY_FS_USE_XATTR
    cdef int SECURITY_FS_USE_TRANS
    cdef int SECURITY_FS_USE_TASK
    cdef int SECURITY_FS_USE_GENFS
    cdef int SECURITY_FS_USE_NONE


cdef extern from "<sepol/policydb/flask.h>":
    cdef int SECCLASS_DIR
    cdef int SECCLASS_FILE
    cdef int SECCLASS_LNK_FILE
    cdef int SECCLASS_FIFO_FILE
    cdef int SECCLASS_SOCK_FILE
    cdef int SECCLASS_CHR_FILE
    cdef int SECCLASS_BLK_FILE


cdef extern from "<sepol/policydb/flask_types.h>":
    cdef int SELINUX_MAGIC

    ctypedef char* sepol_security_context_t
    ctypedef uint32_t sepol_access_vector_t
    ctypedef uint16_t sepol_security_class_t
    ctypedef uint32_t sepol_security_id_t


cdef extern from "<sepol/policydb/ebitmap.h>":
    #
    # ebitmap_node_t
    #
    cdef struct ebitmap_node:
        uint32_t startbit
        uint64_t map
        ebitmap_node *next

    ctypedef ebitmap_node ebitmap_node_t

    #
    # ebitmap_t
    #
    cdef int MAPBIT
    cdef int MAPSIZE

    cdef struct ebitmap:
        ebitmap_node_t *node
        uint32_t highbit

    ctypedef ebitmap ebitmap_t

    #
    # ebitmap functions
    #
    void ebitmap_init(ebitmap_t * e)
    size_t ebitmap_length(ebitmap_t * e)
    unsigned int ebitmap_start(const ebitmap_t * e, ebitmap_node_t ** n)
    unsigned int ebitmap_next(ebitmap_node_t ** n, unsigned int bit)
    int ebitmap_node_get_bit(ebitmap_node_t * n, unsigned int bit)


cdef extern from "<sepol/policydb/hashtab.h>":
    ctypedef char* hashtab_key_t
    ctypedef const char* const_hashtab_key_t
    ctypedef void* hashtab_datum_t

    #
    # hashtab_node_t/hashtab_ptr_t
    #
    cdef struct hashtab_node:
        hashtab_key_t key
        hashtab_datum_t datum
        hashtab_node * next

    ctypedef hashtab_node* hashtab_ptr_t
    ctypedef hashtab_node hashtab_node_t

    #
    # hashtab_t
    #
    ctypedef unsigned int (*hash_value_cb) (hashtab_val *, const_hashtab_key_t)
    ctypedef int (*keycmp_cb) (hashtab_val *, const_hashtab_key_t, const_hashtab_key_t)

    cdef struct hashtab_val:
        hashtab_ptr_t *htable
        unsigned int size
        uint32_t nel
        hash_value_cb hash_value
        keycmp_cb keycmp

    ctypedef hashtab_val hashtab_val_t
    ctypedef hashtab_val_t* hashtab_t


cdef extern from "<sepol/policydb/symtab.h>":
    #
    # symtab_datum_t
    #
    cdef struct symtab_datum:
        uint32_t value

    ctypedef symtab_datum symtab_datum_t

    #
    # symtab_t
    #
    ctypedef struct symtab_t:
        hashtab_t table
        uint32_t nprim


cdef extern from "<sepol/policydb/avtab.h>":
    #
    # avtab_key_t
    #
    cdef int AVTAB_ALLOWED
    cdef int AVTAB_AUDITALLOW
    cdef int AVTAB_AUDITDENY
    cdef int AVTAB_NEVERALLOW
    cdef int AVTAB_AV
    cdef int AVTAB_TRANSITION
    cdef int AVTAB_MEMBER
    cdef int AVTAB_CHANGE
    cdef int AVTAB_TYPE
    cdef int AVTAB_XPERMS_ALLOWED
    cdef int AVTAB_XPERMS_AUDITALLOW
    cdef int AVTAB_XPERMS_DONTAUDIT
    cdef int AVTAB_XPERMS_NEVERALLOW
    cdef int AVTAB_XPERMS
    cdef int AVTAB_ENABLED_OLD
    cdef int AVTAB_ENABLED

    cdef struct avtab_key:
        uint16_t source_type
        uint16_t target_type
        uint16_t target_class
        uint16_t specified

    ctypedef avtab_key avtab_key_t

    #
    # avtab_extended_perms_t
    #
    cdef int AVTAB_XPERMS_IOCTLFUNCTION
    cdef int AVTAB_XPERMS_IOCTLDRIVER

    cdef struct avtab_extended_perms:
        uint8_t specified
        uint8_t driver
        uint32_t perms[8]  # 8 is hardcoded in the header

    ctypedef avtab_extended_perms avtab_extended_perms_t

    #
    # avtab_datum_t
    #
    cdef struct avtab_datum:
        uint32_t data
        avtab_extended_perms_t *xperms

    ctypedef avtab_datum avtab_datum_t

    #
    # avtab_ptr_t
    #
    cdef struct avtab_node:
        avtab_key_t key
        avtab_datum_t datum
        avtab_node *next
        void *parse_context
        unsigned merged

    ctypedef avtab_node* avtab_ptr_t

    #
    # avtab_t
    #
    cdef struct avtab:
        avtab_ptr_t *htable
        uint32_t nel
        uint32_t nslot
        uint32_t mask

    ctypedef avtab avtab_t


cdef extern from "<sepol/policydb/mls_types.h>":
    #
    # mls_level_t
    #
    cdef struct mls_level:
        uint32_t sens
        ebitmap_t cat
    ctypedef mls_level mls_level_t

    #
    # mls_range_t
    #
    cdef struct mls_range:
        mls_level_t level[2]  # 2 is hardcoded in the header (low == level[0], high == level[1])
    ctypedef mls_range  mls_range_t

    #
    # mls_semantic_cat_t
    #
    cdef struct mls_semantic_cat:
        uint32_t low
        uint32_t high
        mls_semantic_cat *next

    ctypedef mls_semantic_cat mls_semantic_cat_t

    #
    # mls_semantic_level
    #
    cdef struct mls_semantic_level:
        uint32_t sens
        mls_semantic_cat_t *cat

    ctypedef mls_semantic_level mls_semantic_level_t

    #
    # mls_semantic_range
    #
    cdef struct mls_semantic_range:
        mls_semantic_level_t level[2]

    ctypedef mls_semantic_range mls_semantic_range_t


cdef extern from "<sepol/policydb/context.h>":
    #
    # context_struct_t
    #
    cdef struct context_struct:
        uint32_t user
        uint32_t role
        uint32_t type
        mls_range_t range

    ctypedef context_struct context_struct_t


cdef extern from "<sepol/policydb/sidtab.h>":
    #
    # sidtab_node_t/sidtab_ptr_t
    #
    cdef struct sidtab_node:
        sepol_security_id_t sid
        context_struct_t context
        sidtab_node *next

    ctypedef sidtab_node sidtab_node_t
    ctypedef sidtab_node* sidtab_ptr_t

    #
    # sidtab_t
    #
    cdef int SIDTAB_HASH_BITS
    cdef int SIDTAB_HASH_BUCKETS
    cdef int SIDTAB_HASH_MASK
    cdef int SIDTAB_SIZE

    ctypedef struct sidtab_t:
        sidtab_ptr_t *htable
        unsigned int nel
        unsigned int next_sid
        unsigned char shutdown


cdef extern from "<sepol/policydb/conditional.h>":
    cdef int COND_EXPR_MAXDEPTH
    cdef int COND_MAX_BOOLS

    #
    # cond_av_list_t
    #
    cdef struct cond_av_list:
        avtab_ptr_t node
        cond_av_list *next

    ctypedef cond_av_list cond_av_list_t

    #
    # cond_expr_t
    #
    cdef int COND_BOOL
    cdef int COND_NOT
    cdef int COND_OR
    cdef int COND_AND
    cdef int COND_XOR
    cdef int COND_EQ
    cdef int COND_NEQ
    cdef int COND_LAST

    cdef struct cond_expr:
        uint32_t expr_type
        uint32_t bool
        cond_expr *next

    ctypedef cond_expr cond_expr_t

    #
    # cond_node_t
    #
    cdef int COND_NODE_FLAGS_TUNABLE

    cdef struct cond_node:
        int cur_state
        cond_expr_t *expr
        cond_av_list_t *true_list
        cond_av_list_t *false_list
        avrule *avtrue_list
        avrule *avfalse_list
        unsigned int nbools
        uint32_t bool_ids[5] # TODO: COND_MAX_BOOLS=5
        uint32_t expr_pre_comp
        cond_node *next
        uint32_t flags

    ctypedef cond_node cond_node_t
    ctypedef cond_node cond_list_t


cdef extern from "<sepol/policydb/constraint.h>":
    cdef int CEXPR_NOT
    cdef int CEXPR_AND
    cdef int CEXPR_OR
    cdef int CEXPR_ATTR
    cdef int CEXPR_NAMES
    cdef int CEXPR_USER
    cdef int CEXPR_ROLE
    cdef int CEXPR_TYPE
    cdef int CEXPR_TARGET
    cdef int CEXPR_XTARGET
    cdef int CEXPR_L1L2
    cdef int CEXPR_L1H2
    cdef int CEXPR_H1L2
    cdef int CEXPR_H1H2
    cdef int CEXPR_L1H1
    cdef int CEXPR_L2H2

    #
    # constraint_expr_t
    #
    cdef int CEXPR_EQ
    cdef int CEXPR_NEQ
    cdef int CEXPR_DOM
    cdef int CEXPR_DOMBY
    cdef int CEXPR_INCOMP

    cdef struct constraint_expr:
        uint32_t expr_type
        uint32_t attr
        uint32_t op
        ebitmap_t names
        type_set *type_names
        constraint_expr *next

    ctypedef constraint_expr constraint_expr_t

    #
    # constraint_node_t
    #
    cdef struct constraint_node:
        sepol_access_vector_t permissions
        constraint_expr_t *expr
        constraint_node *next

    ctypedef constraint_node constraint_node_t


cdef extern from "<sepol/policydb/polcaps.h>":
    const char *sepol_polcap_getname(unsigned int capnum)


cdef extern from "<sepol/policydb/policydb.h>":
    #
    # class_perm_node_t
    #
    cdef struct class_perm_node:
        uint32_t tclass
        uint32_t data
        class_perm_node *next

    ctypedef class_perm_node class_perm_node_t

    #
    # role_set_t
    #
    cdef int ROLE_STAR
    cdef int ROLE_COMP

    cdef struct role_set:
        ebitmap_t roles
        uint32_t flags

    ctypedef role_set role_set_t

    #
    # type_set_t
    #
    cdef int TYPE_STAR
    cdef int TYPE_COMP

    cdef struct type_set:
        ebitmap_t types
        ebitmap_t negset
        uint32_t flags

    ctypedef type_set type_set_t

    #
    # av_extended_perms_t
    #
    cdef int AVRULE_XPERMS_IOCTLFUNCTION
    cdef int AVRULE_XPERMS_IOCTLDRIVER
    cdef int EXTENDED_PERMS_LEN

    cdef struct av_extended_perms:
        uint8_t specified
        uint8_t driver
        uint32_t perms[8]  # TODO: EXTENDED_PERMS_LEN=8

    ctypedef av_extended_perms av_extended_perms_t

    cdef bint xperm_test(size_t x, uint32_t *perms)

    #
    # avrule_t
    #
    cdef int AVRULE_ALLOWED
    cdef int AVRULE_AUDITALLOW
    cdef int AVRULE_AUDITDENY
    cdef int AVRULE_DONTAUDIT
    cdef int AVRULE_NEVERALLOW
    cdef int AVRULE_AV
    cdef int AVRULE_TRANSITION
    cdef int AVRULE_MEMBER
    cdef int AVRULE_CHANGE
    cdef int AVRULE_TYPE
    cdef int AVRULE_XPERMS_ALLOWED
    cdef int AVRULE_XPERMS_AUDITALLOW
    cdef int AVRULE_XPERMS_DONTAUDIT
    cdef int AVRULE_XPERMS_NEVERALLOW
    cdef int AVRULE_XPERMS
    cdef int RULE_SELF

    cdef struct avrule:
        uint32_t specified
        uint32_t flags
        type_set_t stypes
        type_set_t ttypes
        class_perm_node_t *perms
        av_extended_perms_t *xperms
        unsigned long line
        char *source_filename
        unsigned long source_line
        avrule *next

    ctypedef avrule avrule_t

    #
    # cat_datum_t
    #
    cdef struct cat_datum:
        symtab_datum_t s
        unsigned char isalias

    ctypedef cat_datum cat_datum_t

    #
    # common_datum_t
    #
    cdef struct common_datum:
        symtab_datum_t s
        symtab_t permissions

    ctypedef common_datum common_datum_t

    #
    # class_datum_t
    #
    cdef int DEFAULT_SOURCE
    cdef int DEFAULT_TARGET
    cdef int DEFAULT_SOURCE_LOW
    cdef int DEFAULT_SOURCE_HIGH
    cdef int DEFAULT_SOURCE_LOW_HIGH
    cdef int DEFAULT_TARGET_LOW
    cdef int DEFAULT_TARGET_HIGH
    cdef int DEFAULT_TARGET_LOW_HIGH

    cdef struct class_datum:
        symtab_datum_t s
        char *comkey
        common_datum_t *comdatum
        symtab_t permissions
        constraint_node *constraints
        constraint_node *validatetrans
        char default_user
        char default_role
        char default_type
        char default_range

    ctypedef class_datum class_datum_t

    #
    # cond_bool_datum_t
    #
    cdef int COND_BOOL_FLAGS_TUNABLE

    cdef struct cond_bool_datum:  # Boolean data type
        symtab_datum_t s
        int state
        uint32_t flags

    ctypedef cond_bool_datum cond_bool_datum_t

    #
    # filename_trans_t
    #
    cdef struct filename_trans:
        uint32_t stype
        uint32_t ttype
        uint32_t tclass
        char *name

    ctypedef filename_trans filename_trans_t

    #
    # filename_trans_datum_t
    #
    cdef struct filename_trans_datum:
        uint32_t otype

    ctypedef filename_trans_datum filename_trans_datum_t

    #
    # genfs_t
    #
    cdef struct genfs:
        char* fstype
        ocontext* head
        genfs* next

    ctypedef genfs genfs_t

    #
    # level_datum_t
    #
    cdef struct level_datum:
        mls_level_t *level
        unsigned char isalias
        unsigned char defined

    ctypedef level_datum level_datum_t

    #
    # ocontext_t union u member structs
    #
    cdef struct ocontext_port:
        uint8_t protocol
        uint16_t low_port
        uint16_t high_port

    cdef struct ocontext_node:
        uint32_t addr # network order
        uint32_t mask # network order

    cdef struct ocontext_node6:
        uint32_t addr[4] # network order
        uint32_t mask[4] # network order

    cdef struct ocontext_iomem:
        uint64_t low_iomem
        uint64_t high_iomem

    cdef struct ocontext_ioport:
        uint32_t low_ioport
        uint32_t high_ioport

    cdef struct ocontext_ibpkey:
        uint64_t subnet_prefix
        uint16_t low_pkey
        uint16_t high_pkey

    cdef struct ocontext_ibendport:
        char *dev_name
        uint8_t port

    cdef union ocontext_u_union:
        char *name
        ocontext_port port
        ocontext_node node
        ocontext_node6 node6
        uint32_t device
        uint16_t pirq
        ocontext_iomem iomem
        ocontext_ioport ioport
        ocontext_ibpkey ibpkey
        ocontext_ibendport ibendport

    #
    # ocontext_t v union
    #
    cdef union ocontext_v_union:
        uint32_t sclass
        uint32_t behavior

    #
    # ocontext_t
    #
    cdef int OCON_ISID
    cdef int OCON_FS
    cdef int OCON_PORT
    cdef int OCON_NETIF
    cdef int OCON_NODE
    cdef int OCON_FSUSE
    cdef int OCON_NODE6
    cdef int OCON_IBPKEY
    cdef int OCON_IBENDPORT

    cdef int OCON_XEN_ISID
    cdef int OCON_XEN_PIRQ
    cdef int OCON_XEN_IOPORT
    cdef int OCON_XEN_IOMEM
    cdef int OCON_XEN_PCIDEVICE
    cdef int OCON_XEN_DEVICETREE

    cdef int OCON_NUM

    cdef struct ocontext:
        ocontext_u_union u
        ocontext_v_union v
        context_struct_t context[2]  # 2 is hardcoded in the header
        sepol_security_id_t sid[2]  # 2 is hardcoded in the header
        ocontext *next

    ctypedef ocontext ocontext_t

    #
    # perm_datum_t
    #
    cdef struct perm_datum:
        symtab_datum_t s

    ctypedef perm_datum perm_datum_t

    #
    # range_trans_t
    #
    cdef struct range_trans:
        uint32_t source_type
        uint32_t target_type
        uint32_t target_class

    ctypedef range_trans range_trans_t

    #
    # role_allow_t
    #
    cdef struct role_allow:
        uint32_t role
        uint32_t new_role
        role_allow *next

    ctypedef role_allow role_allow_t

    #
    # role_allow_rule_t
    #
    cdef struct role_allow_rule:
        role_set_t roles
        role_set_t new_roles
        role_allow_rule *next

    ctypedef role_allow_rule role_allow_rule_t

    #
    # role_datum_t
    #
    cdef int ROLE_ROLE
    cdef int ROLE_ATTRIB

    cdef struct role_datum:
        symtab_datum_t s
        ebitmap_t dominates
        type_set_t types
        ebitmap_t cache
        uint32_t bounds
        uint32_t flavor
        ebitmap_t roles

    ctypedef role_datum role_datum_t

    #
    # role_trans_t
    #
    cdef struct role_trans:
        uint32_t role
        uint32_t type
        uint32_t tclass
        uint32_t new_role
        role_trans *next

    ctypedef role_trans role_trans_t

    #
    # role_trans_rule_t
    #
    cdef struct role_trans_rule:
        role_set_t roles
        type_set_t types
        ebitmap_t classes
        uint32_t new_role
        role_trans_rule *next

    ctypedef role_trans_rule role_trans_rule_t

    #
    # type_datum_t
    #
    cdef int TYPE_TYPE
    cdef int TYPE_ATTRIB
    cdef int TYPE_ALIAS
    cdef int TYPE_FLAGS_PERMISSIVE
    cdef int TYPE_FLAGS_EXPAND_ATTR_TRUE
    cdef int TYPE_FLAGS_EXPAND_ATTR_FALSE
    cdef int TYPE_FLAGS_EXPAND_ATTR

    cdef struct type_datum:
        symtab_datum_t s
        uint32_t primary
        uint32_t flavor
        ebitmap_t types
        uint32_t flags
        uint32_t bounds

    ctypedef type_datum type_datum_t

    #
    # user_datum_t
    #
    cdef struct user_datum:
        symtab_datum_t s
        role_set_t roles
        mls_semantic_range_t range
        mls_semantic_level_t dfltlevel
        ebitmap_t cache
        mls_range_t exp_range
        mls_level_t exp_dfltlevel
        uint32_t bounds

    ctypedef user_datum user_datum_t

    #
    # Policy DB
    #
    cdef int POLICYDB_VERSION_MAX
    cdef int POLICYDB_VERSION_MIN

    cdef int SYM_COMMONS
    cdef int SYM_CLASSES
    cdef int SYM_ROLES
    cdef int SYM_TYPES
    cdef int SYM_USERS
    cdef int SYM_BOOLS
    cdef int SYM_LEVELS
    cdef int SYM_CATS
    cdef int SYM_NUM

    cdef struct policydb:
        uint32_t policy_type
        char *name
        char *version
        int  target_platform

        # Set when the policydb is modified such that writing is unsupported
        int unsupported_format

        int mls

        symtab_t symtab[8]  # TODO: SYM_NUM=8
        char **sym_val_to_name[8]  # TODO: SYM_NUM=8
        class_datum_t **class_val_to_struct
        role_datum_t **role_val_to_struct
        user_datum_t **user_val_to_struct
        type_datum_t **type_val_to_struct
        avtab_t te_avtab
        cond_bool_datum_t **bool_val_to_struct  # bools indexed by (value - 1)
        avtab_t te_cond_avtab
        cond_node *cond_list
        role_trans_t *role_tr
        role_allow_t *role_allow
        ocontext_t *ocontexts[9]  # TODO: OCON_NUM=9
        genfs_t *genfs
        hashtab_t range_tr
        hashtab_t filename_trans
        ebitmap_t *type_attr_map
        ebitmap_t *attr_type_map	# not saved in the binary policy
        ebitmap_t policycaps

        # this bitmap is referenced by type NOT the typical type-1 used in other
        # bitmaps.  Someday the 0 bit may be used for global permissive
        ebitmap_t permissive_map

        unsigned policyvers
        unsigned handle_unknown

    ctypedef policydb policydb_t


cdef extern from "<sepol/policydb.h>":
    cdef struct sepol_policy_file:
        pass
    ctypedef sepol_policy_file sepol_policy_file_t

    cdef struct sepol_policydb:
        policydb p

    ctypedef sepol_policydb sepol_policydb_t

    cdef int SEPOL_DENY_UNKNOWN
    cdef int SEPOL_REJECT_UNKNOWN
    cdef int SEPOL_ALLOW_UNKNOWN
    cdef int SEPOL_TARGET_SELINUX
    cdef int SEPOL_TARGET_XEN
    cdef int sepol_policy_kern_vers_min()
    cdef int sepol_policy_kern_vers_max()

    int sepol_policydb_create(sepol_policydb_t ** p)
    int sepol_policy_file_create(sepol_policy_file_t ** pf)
    void sepol_policy_file_set_handle(sepol_policy_file_t * pf, sepol_handle_t * handle)
    void sepol_policy_file_set_fp(sepol_policy_file_t * pf, FILE * fp)
    int sepol_policydb_read(sepol_policydb_t * p, sepol_policy_file_t * pf)
    void sepol_policydb_free(sepol_policydb_t * p)
    void sepol_policy_file_free(sepol_policy_file_t * pf)
