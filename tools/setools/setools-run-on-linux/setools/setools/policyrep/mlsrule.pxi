# Copyright 2014, 2016, Tresys Technology, LLC
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


class MLSRuletype(PolicyEnum):

    """An enumeration of MLS rule types."""

    range_transition = 1


cdef class MLSRule(PolicyRule):

    """An MLS rule."""

    cdef:
        readonly ObjClass tclass
        object rng

    @staticmethod
    cdef inline MLSRule factory(SELinuxPolicy policy, sepol.range_trans_t *symbol,
                                sepol.mls_range_t *rng):
        """Factory function for creating MLSRule objects."""
        cdef MLSRule r = MLSRule.__new__(MLSRule)
        r.policy = policy
        r.key = <uintptr_t>symbol
        r.ruletype = MLSRuletype.range_transition
        r.source = type_or_attr_factory(policy, policy.type_value_to_datum(symbol.source_type - 1))
        r.target = type_or_attr_factory(policy, policy.type_value_to_datum(symbol.target_type - 1))
        r.tclass = ObjClass.factory(policy, policy.class_value_to_datum(symbol.target_class - 1))
        r.rng = Range.factory(policy, rng)
        r.origin = None
        return r

    def __hash__(self):
        return hash("{0.ruletype}|{0.source}|{0.target}|{0.tclass}|None|None".format(self))

    def __lt__(self, other):
        return str(self) < str(other)

    @property
    def default(self):
        """The rule's default range."""
        return self.rng

    def expand(self):
        """Expand the rule into an equivalent set of rules without attributes."""
        cdef MLSRule r
        if self.origin is None:
            for s, t in itertools.product(self.source.expand(), self.target.expand()):
                r = MLSRule.__new__(MLSRule)
                r.policy = self.policy
                r.key = self.key
                r.ruletype = self.ruletype
                r.source = s
                r.target = t
                r.tclass = self.tclass
                r.rng = self.rng
                r.origin = self
                yield r

        else:
            # this rule is already expanded.
            yield self

    def statement(self):
        return "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default};".format(self)


#
# Iterators
#
cdef class MLSRuleIterator(HashtabIterator):

    """Iterate over MLS rules in the policy."""

    @staticmethod
    cdef factory(SELinuxPolicy policy, sepol.hashtab_t *table):
        """Factory function for creating MLS rule iterators."""
        i = MLSRuleIterator()
        i.policy = policy
        i.table = table
        i.reset()
        return i

    def __next__(self):
        super().__next__()
        return MLSRule.factory(self.policy, <sepol.range_trans_t *>self.curr.key,
                               <sepol.mls_range_t *>self.curr.datum)
