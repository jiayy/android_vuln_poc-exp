# Copyright 2014-2016, Tresys Technology, LLC
# Copyright 2016-2018, Chris PeBenito <pebenito@ieee.org>
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


#
# Classes
#
class TERuletype(PolicyEnum):

    """Enumeration of types of TE rules."""

    allow = sepol.AVTAB_ALLOWED
    neverallow = sepol.AVTAB_NEVERALLOW
    auditallow = sepol.AVTAB_AUDITALLOW
    dontaudit = sepol.AVTAB_AUDITDENY
    allowxperm = sepol.AVTAB_XPERMS_ALLOWED
    neverallowxperm = sepol.AVTAB_XPERMS_NEVERALLOW
    auditallowxperm = sepol.AVTAB_XPERMS_AUDITALLOW
    dontauditxperm = sepol.AVTAB_XPERMS_DONTAUDIT
    type_transition = sepol.AVTAB_TRANSITION
    type_change = sepol.AVTAB_CHANGE
    type_member = sepol.AVTAB_MEMBER


cdef class BaseTERule(PolicyRule):

    """Base class for TE rules."""

    cdef:
        readonly ObjClass tclass
        str rule_string
        Conditional _conditional
        bint _conditional_block

    @property
    def filename(self):
        """The type_transition rule's file name."""
        # Since name type_transitions have a different
        # class, this is always an error.
        if self.ruletype == TERuletype.type_transition:
            raise TERuleNoFilename
        else:
            raise RuleUseError("{0} rules do not have file names".format(self.ruletype))

    @property
    def conditional(self):
        """The rule's conditional expression."""
        if self._conditional is None:
            raise RuleNotConditional
        else:
            return self._conditional

    @property
    def conditional_block(self):
        """
        The conditional block of the rule (T/F)

        For example, if the policy looks like this:

        if ( the_conditional_expression ) {
            If the rule is here, this property is True
        } else {
            If the rule is here, this property is False
        }
        """
        if self._conditional is None:
            raise RuleNotConditional
        else:
            return self._conditional_block

    def enabled(self, **kwargs):
        """
        Determine if the rule is enabled, given the stated boolean values.

        Keyword Parameters: bool_name=True|False
        Each keyword parameter name corresponds to a Boolean name
        in the expression and the state to use in the evaluation.
        If a Boolean value is not set, its default value is used.
        Extra values are ignored.

        Return:     bool
        """
        if self._conditional is None:
            return True

        if self._conditional.evaluate(**kwargs):
            return self._conditional_block
        else:
            return not self._conditional_block


cdef class AVRule(BaseTERule):

    """An access vector type enforcement rule."""

    cdef readonly frozenset perms

    @staticmethod
    cdef inline AVRule factory(SELinuxPolicy policy, sepol.avtab_key_t *key, sepol.avtab_datum_t *datum,
                               conditional, conditional_block):
        """Factory function for creating AVRule objects."""
        cdef AVRule r = AVRule.__new__(AVRule)
        r.policy = policy
        r.key = <uintptr_t>key
        r.ruletype = TERuletype(key.specified & ~sepol.AVTAB_ENABLED)
        r.source = type_or_attr_factory(policy, policy.type_value_to_datum(key.source_type - 1))
        r.target = type_or_attr_factory(policy, policy.type_value_to_datum(key.target_type - 1))
        r.tclass = ObjClass.factory(policy, policy.class_value_to_datum(key.target_class - 1))
        r.perms = frozenset(p for p in PermissionVectorIterator.factory(policy, r.tclass,
                      ~datum.data if key.specified & sepol.AVTAB_AUDITDENY else datum.data))
        r._conditional = conditional
        r._conditional_block = conditional_block
        r.origin = None
        return r

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}".
            format(self, self._conditional, self._conditional_block))

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def default(self):
        """The rule's default type."""
        raise RuleUseError("{0} rules do not have a default type.".format(self.ruletype))

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef AVRule r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                r = AVRule.__new__(AVRule)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.tclass = self.tclass
                r.perms = self.perms
                r._conditional = self._conditional
                r._conditional_block = self._conditional_block
                r.origin = self
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        if not self.rule_string:
            self.rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} ".format(self)

            # allow/dontaudit/auditallow/neverallow rules
            perms = self.perms
            if len(perms) > 1:
                self.rule_string += "{{ {0} }};".format(' '.join(sorted(perms)))
            else:
                # convert to list since sets cannot be indexed
                self.rule_string += "{0};".format(list(perms)[0])

            try:
                self.rule_string += " [ {0.conditional} ]:{0.conditional_block}".format(self)
            except RuleNotConditional:
                pass

        return self.rule_string


cdef class IoctlSet(frozenset):

    """
    A set with overridden string functions which compresses
    the output into ioctl ranges instead of individual elements.
    """

    def __format__(self, spec):
        """
        String formating.

        The standard formatting (no specification) will render the
        ranges of ioctls, space separated.

        The , option by itself will render the ranges of ioctls,
        comma separated

        Any other combination of formatting options will fall back
        to set's formatting behavior.
        """

        # generate short permission notation
        perms = sorted(self)
        shortlist = []
        for _, i in itertools.groupby(perms, key=lambda k, c=itertools.count(): k - next(c)):
            group = list(i)
            if len(group) > 1:
                shortlist.append("{0:#06x}-{1:#06x}".format(group[0], group[-1]))
            else:
                shortlist.append("{0:#06x}".format(group[0]))

        if not spec:
            return " ".join(shortlist)
        elif spec == ",":
            return ", ".join(shortlist)
        else:
            return super(IoctlSet, self).__format__(spec)

    def __str__(self):
        return "{0}".format(self)

    def __repr__(self):
        return "{{ {0:,} }}".format(self)

    def ranges(self):
        """
        Return the number of ranges in the set.  Main use
        is to determine if brackets need to be used in
        string output.
        """
        return sum(1 for (_a, _b) in itertools.groupby(
            sorted(self), key=lambda k, c=itertools.count(): k - next(c)))


cdef class AVRuleXperm(BaseTERule):

    """An extended permission access vector type enforcement rule."""

    cdef:
        readonly IoctlSet perms
        readonly str xperm_type

    @staticmethod
    cdef inline AVRuleXperm factory(SELinuxPolicy policy, sepol.avtab_key_t *key,
                                    sepol.avtab_datum_t *datum, conditional, conditional_block):
        """Factory function for creating AVRuleXperm objects."""
        cdef:
            str xperm_type
            sepol.avtab_extended_perms_t *xperms = datum.xperms
            set perms = set()
            size_t curr = 0
            size_t len = sizeof(xperms.perms) * sepol.EXTENDED_PERMS_LEN

        #
        # Build permission set
        #
        while curr < len:
            if sepol.xperm_test(curr, xperms.perms):
                if xperms.specified & sepol.AVTAB_XPERMS_IOCTLFUNCTION:
                    perms.add(xperms.driver << 8 | curr)
                elif xperms.specified & sepol.AVTAB_XPERMS_IOCTLDRIVER:
                    perms.add(curr << 8)
                else:
                    raise LowLevelPolicyError("Unknown extended permission: {}".format(
                                              xperms.specified))

            curr += 1

        #
        # Determine xperm type
        #
        if datum.xperms == NULL:
            raise LowLevelPolicyError("Extended permission information is NULL")

        if datum.xperms.specified == sepol.AVTAB_XPERMS_IOCTLFUNCTION \
            or datum.xperms.specified == sepol.AVTAB_XPERMS_IOCTLDRIVER:
            xperm_type = intern("ioctl")
        else:
            raise LowLevelPolicyError("Unknown extended permission: {}".format(
                                      datum.xperms.specified))

        #
        # Construct rule object
        #
        cdef AVRuleXperm r = AVRuleXperm.__new__(AVRuleXperm)
        r.policy = policy
        r.key = <uintptr_t>key
        r.ruletype = TERuletype(key.specified & ~sepol.AVTAB_ENABLED)
        r.source = type_or_attr_factory(policy, policy.type_value_to_datum(key.source_type - 1))
        r.target = type_or_attr_factory(policy, policy.type_value_to_datum(key.target_type - 1))
        r.tclass = ObjClass.factory(policy, policy.class_value_to_datum(key.target_class - 1))
        r.perms = IoctlSet(perms)
        r.extended = True
        r.xperm_type = xperm_type
        r._conditional = conditional
        r._conditional_block = conditional_block
        r.origin = None
        return r

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{0.xperm_type}|{1}|{2}".
            format(self, self._conditional, self._conditional_block))

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def default(self):
        """The rule's default type."""
        raise RuleUseError("{0} rules do not have a default type.".format(self.ruletype))

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef AVRuleXperm r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                r = AVRuleXperm.__new__(AVRuleXperm)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.tclass = self.tclass
                r.perms = self.perms
                r.extended = True
                r.xperm_type = self.xperm_type
                r._conditional = self._conditional
                r._conditional_block = self._conditional_block
                r.origin = self
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        if not self.rule_string:
            self.rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type} ". \
                                format(self)

            # generate short permission notation
            perms = self.perms
            if perms.ranges() > 1:
                self.rule_string += "{{ {0} }};".format(perms)
            else:
                self.rule_string += "{0};".format(perms)

        return self.rule_string


cdef class TERule(BaseTERule):

    """A type_* type enforcement rule."""

    cdef Type dft

    @staticmethod
    cdef inline TERule factory(SELinuxPolicy policy, sepol.avtab_key_t *key,
                               sepol.avtab_datum_t *datum, conditional, conditional_block):
        """Factory function for creating TERule objects."""
        cdef TERule r = TERule.__new__(TERule)
        r.policy = policy
        r.key = <uintptr_t>key
        r.ruletype = TERuletype(key.specified & ~sepol.AVTAB_ENABLED)
        r.source = type_or_attr_factory(policy, policy.type_value_to_datum(key.source_type - 1))
        r.target = type_or_attr_factory(policy, policy.type_value_to_datum(key.target_type - 1))
        r.tclass = ObjClass.factory(policy, policy.class_value_to_datum(key.target_class - 1))
        r.dft = Type.factory(policy, policy.type_value_to_datum(datum.data - 1))
        r.origin = None
        r._conditional = conditional
        r._conditional_block = conditional_block
        return r

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{1}|{2}|{3}".format(
            self, None, self._conditional, self._conditional_block))

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def perms(self):
        """The rule's permission set."""
        raise RuleUseError("{0} rules do not have a permission set.".format(self.ruletype))

    @property
    def default(self):
        """The rule's default type."""
        return self.dft

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef TERule r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                r = TERule.__new__(TERule)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.tclass = self.tclass
                r.dft = self.dft
                r.origin = self
                r._conditional = self._conditional
                r._conditional_block = self._conditional_block
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        if not self.rule_string:
            self.rule_string = "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};". \
                               format(self)

            try:
                self.rule_string += " [ {0.conditional} ]:{0.conditional_block}".format(self)
            except RuleNotConditional:
                pass

        return self.rule_string


cdef class FileNameTERule(BaseTERule):

    """A type_transition type enforcement rule with filename."""

    cdef:
        Type dft
        readonly str filename

    @staticmethod
    cdef inline FileNameTERule factory(SELinuxPolicy policy, sepol.filename_trans_t *key,
                                       sepol.filename_trans_datum_t *datum):
        """Factory function for creating FileNameTERule objects."""
        cdef FileNameTERule r = FileNameTERule.__new__(FileNameTERule)
        r.policy = policy
        r.key = <uintptr_t>key
        r.ruletype = TERuletype.type_transition
        r.source = type_or_attr_factory(policy, policy.type_value_to_datum(key.stype - 1))
        r.target = type_or_attr_factory(policy, policy.type_value_to_datum(key.ttype - 1))
        r.tclass = ObjClass.factory(policy, policy.class_value_to_datum(key.tclass - 1))
        r.dft = Type.factory(policy, policy.type_value_to_datum(datum.otype - 1))
        r.filename = intern(key.name)
        r.origin = None
        return r

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|{0.filename}|{1}|{2}".format(
            self, None, None))

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def perms(self):
        """The rule's permission set."""
        raise RuleUseError("{0} rules do not have a permission set.".format(self.ruletype))

    @property
    def default(self):
        """The rule's default type."""
        return self.dft

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef FileNameTERule r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                r = FileNameTERule.__new__(FileNameTERule)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.tclass = self.tclass
                r.dft = self.dft
                r.filename = self.filename
                r.origin = None
                r._conditional = self._conditional
                r._conditional_block = self._conditional_block
                r.origin = self
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default} {0.filename};". \
            format(self)


#
# Iterators
#
cdef class TERuleIterator(PolicyIterator):

    """Iterator for access vector tables."""

    cdef:
        sepol.avtab_t *table
        sepol.avtab_ptr_t node
        unsigned int bucket
        object conditional
        object cond_block

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.avtab *table):
        """Factory function for creating TERule iterators."""
        i = TERuleIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    cdef void _next_bucket(self):
        """Internal method for advancing to the next bucket."""
        self.bucket += 1
        if self.bucket < self.table.nslot:
            self.node = self.table.htable[self.bucket]
        else:
            self.node = NULL

    cdef void _next_node(self):
        """Internal method for advancing to the next node."""
        if self.node != NULL and self.node.next != NULL:
            self.node = self.node.next
        else:
            self._next_bucket()
            while self.bucket < self.table.nslot and self.node == NULL:
                self._next_bucket()

    def __next__(self):
        cdef:
            sepol.avtab_key_t *key
            sepol.avtab_datum_t *datum

        if self.table == NULL or self.table.nel == 0 or self.bucket >= self.table.nslot:
            raise StopIteration

        key = &self.node.key
        datum = &self.node.datum

        self._next_node()

        if key.specified & sepol.AVRULE_AV:
            return AVRule.factory(self.policy, key, datum, None, None)
        elif key.specified & sepol.AVRULE_TYPE:
            return TERule.factory(self.policy, key, datum, None, None)
        elif key.specified & sepol.AVRULE_XPERMS:
            return AVRuleXperm.factory(self.policy, key, datum, None, None)
        else:
            raise LowLevelPolicyError("Unknown AV rule type 0x{}".format(key.specified, '04x'))

    def __len__(self):
        return self.table.nel

    def ruletype_count(self):
        """
        Determine the number of rules.

        Return: collections.Counter object keyed by TERuletype.value
        """
        cdef:
            sepol.avtab_key_t *key
            sepol.avtab_ptr_t node
            uint32_t bucket = 0

        count = collections.Counter()

        while bucket < self.table[0].nslot:
            node = self.table[0].htable[bucket]
            while node != NULL:
                key = &node.key if node else NULL
                if key != NULL:
                    count[key.specified & ~sepol.AVTAB_ENABLED] += 1

                node = node.next

            bucket += 1

        return count

    def reset(self):
        """Reset the iterator to the start."""
        self.node = self.table.htable[0]

        # advance to first item
        if self.node == NULL:
            self._next_node()


cdef class ConditionalTERuleIterator(PolicyIterator):

    """Conditional TE rule iterator."""

    cdef:
        sepol.cond_av_list_t *head
        sepol.cond_av_list_t *curr
        object conditional
        object conditional_block

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.cond_av_list_t *head, conditional, cond_block):
        """ConditionalTERuleIterator iterator factory."""
        c = ConditionalTERuleIterator()
        c.policy = policy
        c.head = head
        c.conditional = conditional
        c.conditional_block = cond_block
        c.reset()
        return c

    def __next__(self):
        if self.curr == NULL:
            raise StopIteration

        key = &self.curr.node.key
        datum = &self.curr.node.datum

        self.curr = self.curr.next

        if key.specified & sepol.AVRULE_AV:
            return AVRule.factory(self.policy, key, datum, self.conditional, self.conditional_block)
        elif key.specified & sepol.AVRULE_TYPE:
            return TERule.factory(self.policy, key, datum, self.conditional, self.conditional_block)
        elif key.specified & sepol.AVRULE_XPERMS:
            return AVRuleXperm.factory(self.policy, key, datum, self.conditional, self.conditional_block)
        else:
            raise LowLevelPolicyError("Unknown AV rule type 0x{}".format(key.specified, '04x'))

    def __len__(self):
        cdef:
            sepol.cond_av_list_t *curr
            size_t count = 0

        curr = self.head
        while curr != NULL:
            count += 1
            curr = curr.next

        return count

    def ruletype_count(self):
        """
        Determine the number of rules.

        Return: collections.Counter object keyed by TERuletype.value
        """
        cdef sepol.cond_av_list_t *curr

        count = collections.Counter()

        curr = self.head
        while curr != NULL:
            count[curr.node.key.specified & ~sepol.AVTAB_ENABLED] += 1
            curr = curr.next

        return count

    def reset(self):
        """Reset the iterator back to the start."""
        self.curr = self.head


cdef class FileNameTERuleIterator(HashtabIterator):

    """Iterate over FileNameTERules in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating FileNameTERule iterators."""
        i = FileNameTERuleIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return FileNameTERule.factory(self.policy, <sepol.filename_trans_t *>self.curr.key,
                                      <sepol.filename_trans_datum_t *>self.curr.datum)
