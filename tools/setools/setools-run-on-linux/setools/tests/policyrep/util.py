# Copyright 2015, Tresys Technology, LLC
# Copyright 2018, Chris PeBenito <pebenito@ieee.org>
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.
#
import os
import subprocess
import tempfile

from setools import SELinuxPolicy


def compile_policy(source_file, mls=True, xen=False):
    """
    Compile the specified source policy.  Checkpolicy is
    assumed to be /usr/bin/checkpolicy.  Otherwise the path
    must be specified in the CHECKPOLICY environment variable.

    Return:
    A SELinuxPolicy object.
    """
    # create a temp file for the binary policy
    # and then have checkpolicy overwrite it.
    fd, policy_path = tempfile.mkstemp()
    os.close(fd)

    if "USERSPACE_SRC" in os.environ:
        command = [os.environ['USERSPACE_SRC'] + "/checkpolicy/checkpolicy"]
    elif "CHECKPOLICY" in os.environ:
        command = [os.environ['CHECKPOLICY']]
    else:
        command = ["/usr/bin/checkpolicy"]

    if mls:
        command.append("-M")

    if xen:
        command.extend(["-t", "xen", "-c", "30"])

    command.extend(["-o", policy_path, "-U", "reject", source_file])

    with open(os.devnull, "w") as null:
        subprocess.check_call(command, stdout=null, shell=False, close_fds=True)

    try:
        policy = SELinuxPolicy(policy_path)
    except Exception:
        # This should never be hit, since this policy
        # successfully compiled with checkpolicy above.
        # If we do, clean up the binary policy since
        # tearDownClass() does not run.
        os.unlink(policy_path)
        raise

    return policy
